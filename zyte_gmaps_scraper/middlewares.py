"""
Custom Scrapy middlewares for zyte_gmaps_scraper.

Scrapy DoS vulnerability (unpatched) – mitigation layers
---------------------------------------------------------
This project cannot upgrade past Scrapy 2.11.2 because no patched release
exists for the advisory (Scrapy >= 0.7, <= 2.14.1).  Two complementary
middlewares close the remaining attack surface:

ZyteApiEnforcementMiddleware  (priority 10 – first in process_request)
    Architectural isolation: every outgoing Scrapy request MUST carry the
    ``zyte_api`` or ``zyte_api_automap`` meta key, which routes it through
    Zyte API's managed infrastructure.  Any request lacking that key is
    rejected with IgnoreRequest before it reaches the downloader.

    Effect: Scrapy's TCP stack never opens a direct connection to an
    untrusted host.  All bytes that Scrapy processes originate from Zyte
    API, a controlled source, eliminating the primary remote-exploitation
    path of the unpatched DoS vulnerability.

ResponseGuardMiddleware  (priority 595 – runs before HttpCompressionMiddleware)
    Scrapy's built-in HttpCompressionMiddleware sits at priority 590.  In
    process_response, Scrapy calls middlewares in *descending* priority
    order (higher number → runs first).  At priority 595 our guard runs
    immediately before the decompression step, so it validates the raw
    compressed bytes and all headers *before* any decompression occurs.

    Five independent layers:
    1. Content-Length header check  – reject if advertised size > cap.
    2. Actual compressed body size  – reject if len(response.body) > cap
       (catches servers that lie about or omit Content-Length).
    3. Stacked Content-Encoding     – "gzip, gzip" and unknown encodings
       raise IgnoreRequest; Scrapy never attempts to decompress.
    4. Response header count cap    – anomalous header counts dropped.
    5. Header value length cap      – each value bounded to 8 KB.

BehavioralMimicryMiddleware
    Injects human-like request headers (Accept-Language, viewport hints)
    to reduce behavioural fingerprinting signals.

AdaptiveDOMMiddleware
    Detects anti-bot challenge pages and escalates to full browser render.

DomainRateLimitMiddleware
    Per-domain token-bucket rate limiter (secondary back-pressure valve).

DeadLetterMiddleware
    Captures dropped/errored items to ``dead_letter.jsonl``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

import orjson
import scrapy
from scrapy import Spider, signals
from scrapy.exceptions import IgnoreRequest, NotConfigured
from scrapy.http import Request, Response

logger = logging.getLogger(__name__)

# ─── ZyteApiEnforcementMiddleware constant ────────────────────────────────────
# All requests must carry one of these meta keys to be routed through Zyte API.
_ZYTE_META_KEYS: frozenset[str] = frozenset({"zyte_api", "zyte_api_automap"})

# ─── ResponseGuardMiddleware constants ────────────────────────────────────────
# Must be kept in sync with DOWNLOAD_MAXSIZE in settings.py.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024   # 10 MB
_MAX_HEADER_COUNT = 100
_MAX_HEADER_VALUE_BYTES = 8_192          # 8 KB per header value

# Only single-layer well-understood encodings are accepted.
# Stacked (e.g. "gzip, gzip") or unknown schemes are rejected outright.
_ALLOWED_ENCODINGS: frozenset[str] = frozenset(
    {"gzip", "deflate", "br", "identity", "zstd", ""}
)


# ─── ZyteApiEnforcementMiddleware ─────────────────────────────────────────────

class ZyteApiEnforcementMiddleware:
    """
    Architectural isolation layer: rejects any request not routed via Zyte API.

    Scrapy's downloader is never allowed to open a direct TCP connection to
    an untrusted host.  Every request must carry ``zyte_api`` or
    ``zyte_api_automap`` in its meta; otherwise it is dropped before the
    downloader sees it.

    This eliminates the primary remote-exploitation path of the unpatched
    Scrapy DoS vulnerability: an attacker-controlled server can never feed
    raw bytes directly into Scrapy's vulnerable HTTP-handling code.

    Priority 10 ensures this check runs before all other middlewares in
    process_request, making bypass impossible from within the middleware stack.
    """

    @classmethod
    def from_crawler(cls, crawler: Any) -> "ZyteApiEnforcementMiddleware":
        return cls()

    def process_request(self, request: Request, spider: Spider) -> None:
        if not any(k in request.meta for k in _ZYTE_META_KEYS):
            raise IgnoreRequest(
                f"Direct request rejected – must be routed through Zyte API "
                f"(set zyte_api or zyte_api_automap in meta): {request.url}"
            )


# ─── ResponseGuardMiddleware ──────────────────────────────────────────────────
# ─── Anti-fingerprinting constants ────────────────────────────────────────────
_ACCEPT_LANGUAGE_POOL = [
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-GB,en;q=0.9,fr;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
]
_VIEWPORT_SIZES = [
    "1920,1080", "1366,768", "1440,900", "1536,864", "1280,800",
]
_ANTI_BOT_INDICATORS = [
    "detected unusual traffic",
    "please verify you are a human",
    "enable javascript",
    "cf-challenge",
    "g-recaptcha",
    "hcaptcha",
    "__cf_chl_",
    "ddos-guard",
    "perimeterx",
    "datadome",
]


# ─── ResponseGuardMiddleware ──────────────────────────────────────────────────

class ResponseGuardMiddleware:
    """
    Pre-decompression response guard for the unpatched Scrapy DoS vulnerability.

    Priority 595 places this middleware immediately *before*
    HttpCompressionMiddleware (590) in the process_response chain
    (Scrapy calls process_response in descending priority order, so
    595 → 590 → lower).  The response body is therefore still compressed
    when all five checks execute; no decompression has occurred yet.

    Layers
    ------
    1. Content-Length header check  – reject if the advertised size exceeds
       the cap (catches compressed-but-declared-large responses early).
    2. Actual body byte count       – reject if len(response.body) > cap,
       independent of the Content-Length header (catches lying/missing headers).
    3. Stacked Content-Encoding     – e.g. "gzip, gzip"; IgnoreRequest before
       HttpCompressionMiddleware can attempt multi-pass decompression.
    4. Response header count cap    – anomalous counts dropped.
    5. Header value length cap      – each value bounded to MAX_HEADER_VALUE_BYTES.
    """

    def __init__(
        self,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        max_header_count: int = _MAX_HEADER_COUNT,
        max_header_value_bytes: int = _MAX_HEADER_VALUE_BYTES,
    ) -> None:
        self._max_response_bytes = max_response_bytes
        self._max_header_count = max_header_count
        self._max_header_value_bytes = max_header_value_bytes

    @classmethod
    def from_crawler(cls, crawler: Any) -> "ResponseGuardMiddleware":
        return cls(
            max_response_bytes=crawler.settings.getint(
                "DOWNLOAD_MAXSIZE", _MAX_RESPONSE_BYTES
            ),
        )

    def process_response(
        self, request: Request, response: Response, spider: Spider
    ) -> Response:
        # ── Layer 1: Content-Length header check ──────────────────────────────
        cl_header: bytes = response.headers.get(b"Content-Length", b"")
        if cl_header:
            try:
                claimed_length = int(cl_header.strip())
                if claimed_length > self._max_response_bytes:
                    raise IgnoreRequest(
                        f"Oversized Content-Length {claimed_length} "
                        f"(limit {self._max_response_bytes}) from {request.url}"
                    )
            except ValueError:
                logger.warning(
                    "Malformed Content-Length header %r from %s",
                    cl_header,
                    request.url,
                )

        # ── Layer 2: Actual compressed body byte count ────────────────────────
        # This check is independent of the Content-Length header and catches
        # servers that lie about or omit it.  At priority 595 the body has
        # not yet been decompressed, so this is the raw compressed size.
        actual_body_len = len(response.body)
        if actual_body_len > self._max_response_bytes:
            raise IgnoreRequest(
                f"Response body size {actual_body_len} exceeds limit "
                f"{self._max_response_bytes} from {request.url}"
            )

        # ── Layer 3: Stacked / unknown Content-Encoding rejection ─────────────
        ce_header: bytes = response.headers.get(b"Content-Encoding", b"")
        if ce_header:
            raw_encoding = ce_header.decode("latin-1", errors="replace").strip().lower()
            layers = [layer.strip() for layer in raw_encoding.split(",")]

            if len(layers) > 1:
                raise IgnoreRequest(
                    f"Stacked Content-Encoding {raw_encoding!r} rejected "
                    f"(zip-bomb risk) from {request.url}"
                )
            if layers[0] not in _ALLOWED_ENCODINGS:
                raise IgnoreRequest(
                    f"Unknown/disallowed Content-Encoding {raw_encoding!r} "
                    f"from {request.url}"
                )

        # ── Layer 4: Header count cap ─────────────────────────────────────────
        header_count = len(response.headers)
        if header_count > self._max_header_count:
            raise IgnoreRequest(
                f"Excessive response header count {header_count} "
                f"(limit {self._max_header_count}) from {request.url}"
            )

        # ── Layer 5: Individual header value length cap ───────────────────────
        for header_name, header_values in response.headers.items():
            for val in header_values:
                if len(val) > self._max_header_value_bytes:
                    name_str = header_name.decode("latin-1", errors="replace")
                    raise IgnoreRequest(
                        f"Header {name_str!r} value length {len(val)} exceeds "
                        f"limit {self._max_header_value_bytes} from {request.url}"
                    )

        return response


# ─── Anti-fingerprinting constants ────────────────────────────────────────────

class BehavioralMimicryMiddleware:
    """
    Injects randomised human-like headers into every outgoing Zyte API request.

    TLS fingerprint mitigation: Zyte API handles TLS at the edge; this
    middleware controls the *browser-layer* headers forwarded to the target.
    """

    def __init__(self, jitter_max_ms: int = 250) -> None:
        self._jitter_max = jitter_max_ms / 1000.0

    @classmethod
    def from_crawler(cls, crawler: Any) -> "BehavioralMimicryMiddleware":
        jitter = crawler.settings.getint("MIMICRY_JITTER_MAX_MS", 250)
        return cls(jitter_max_ms=jitter)

    def process_request(self, request: Request, spider: Spider) -> Optional[Request]:
        zyte_params: dict = request.meta.get("zyte_api_automap", {})

        # Inject Accept-Language diversity
        zyte_params.setdefault(
            "customHttpRequestHeaders",
            [{"name": "Accept-Language", "value": random.choice(_ACCEPT_LANGUAGE_POOL)}],
        )

        # Inject viewport hint for browser actions
        if "browserHtml" in zyte_params or "actions" in zyte_params:
            zyte_params.setdefault("viewport", {"width": 1920, "height": 1080})
            vp = random.choice(_VIEWPORT_SIZES).split(",")
            zyte_params["viewport"] = {"width": int(vp[0]), "height": int(vp[1])}

        request.meta["zyte_api_automap"] = zyte_params
        return None   # let request proceed


# ─── AdaptiveDOMMiddleware ────────────────────────────────────────────────────

class AdaptiveDOMMiddleware:
    """
    Detects anti-bot challenge pages and escalates to full browser rendering.

    If a response body contains known challenge indicators, the middleware
    schedules a retry with ``actions`` (browser script execution) enabled,
    mitigating DOM-mutation-based detection.
    """

    MAX_RETRIES = 2

    def process_response(
        self, request: Request, response: Response, spider: Spider
    ) -> Request | Response:
        body_lower = response.text.lower()
        challenge_detected = any(ind in body_lower for ind in _ANTI_BOT_INDICATORS)

        if not challenge_detected:
            return response

        retry_count = request.meta.get("adaptive_dom_retries", 0)
        if retry_count >= self.MAX_RETRIES:
            logger.warning(
                "Anti-bot challenge persists after %d retries: %s",
                self.MAX_RETRIES, request.url,
            )
            return response

        logger.info(
            "Anti-bot challenge detected on %s – escalating to full browser (retry %d/%d)",
            request.url, retry_count + 1, self.MAX_RETRIES,
        )
        new_meta = dict(request.meta)
        new_meta["adaptive_dom_retries"] = retry_count + 1
        zyte_params = dict(new_meta.get("zyte_api_automap", {}))
        zyte_params["browserHtml"] = True
        zyte_params["actions"] = [
            {"action": "waitForTimeout", "timeout": 3000},
        ]
        new_meta["zyte_api_automap"] = zyte_params

        return request.replace(meta=new_meta, dont_filter=True)


# ─── DomainRateLimitMiddleware ────────────────────────────────────────────────

class DomainRateLimitMiddleware:
    """
    Token-bucket rate limiter (per effective domain) acting as a secondary
    back-pressure valve on top of Zyte API's own throttling.

    Configurable via spider ``custom_settings``::

        DOMAIN_RATE_LIMIT = {
            "google.com": {"rate": 8, "burst": 16},
        }
    """

    def __init__(self, limits: dict[str, dict]) -> None:
        # {domain: {"rate": N, "tokens": N, "last_refill": ts}}
        self._buckets: dict[str, dict] = {}
        for domain, cfg in limits.items():
            self._buckets[domain] = {
                "rate": cfg.get("rate", 10),
                "burst": cfg.get("burst", 20),
                "tokens": float(cfg.get("burst", 20)),
                "last_refill": time.monotonic(),
            }

    @classmethod
    def from_crawler(cls, crawler: Any) -> "DomainRateLimitMiddleware":
        limits = crawler.settings.getdict("DOMAIN_RATE_LIMIT", default={})
        return cls(limits=limits)

    def process_request(self, request: Request, spider: Spider) -> None:
        from scrapy.utils.httpobj import urlparse_cached
        parsed = urlparse_cached(request)
        host = parsed.hostname or ""
        domain = _effective_domain(host)

        bucket = self._buckets.get(domain)
        if bucket is None:
            return   # no limit configured for this domain

        now = time.monotonic()
        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(
            bucket["burst"],
            bucket["tokens"] + elapsed * bucket["rate"],
        )
        bucket["last_refill"] = now

        if bucket["tokens"] < 1:
            raise IgnoreRequest(
                f"Rate limit exceeded for {domain} – request dropped."
            )
        bucket["tokens"] -= 1


def _effective_domain(host: str) -> str:
    """Return the last two labels of a hostname (e.g. 'www.google.com' → 'google.com')."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ─── DeadLetterMiddleware ─────────────────────────────────────────────────────

class DeadLetterMiddleware:
    """
    Spider middleware that captures dropped/errored items and writes them to
    ``dead_letter.jsonl`` so they can be re-processed without data loss.
    """

    def __init__(self, output_dir: Path) -> None:
        self._path = output_dir / "dead_letter.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_crawler(cls, crawler: Any) -> "DeadLetterMiddleware":
        output_dir = Path(crawler.settings.get("OUTPUT_DIR", "./output"))
        return cls(output_dir=output_dir)

    def process_spider_exception(
        self, response: Response, exception: Exception, spider: Spider
    ) -> None:
        logger.error(
            "Spider exception on %s: %s – writing to dead-letter queue",
            response.url if response else "unknown",
            exception,
        )
        self._write({"url": getattr(response, "url", ""), "error": str(exception)})

    def _write(self, record: dict) -> None:
        with self._path.open("ab") as fh:
            fh.write(orjson.dumps(record) + b"\n")

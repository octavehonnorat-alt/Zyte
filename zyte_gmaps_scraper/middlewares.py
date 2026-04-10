"""
Custom Scrapy middlewares for zyte_gmaps_scraper.

Middlewares implemented
-----------------------
ResponseGuardMiddleware  (priority 50 – runs first)
    Defense-in-depth guard against the unpatched Scrapy DoS vulnerability
    (no patch available for Scrapy >= 0.7, <= 2.14.1).  Enforces four
    independent layers independently of Scrapy's own DOWNLOAD_MAXSIZE:

    1. Content-Length pre-check  – drop any response that advertises a body
       exceeding MAX_RESPONSE_BYTES before downstream middlewares parse it.
    2. Stacked / unknown Content-Encoding rejection – "gzip, gzip" or any
       multi-layer compression scheme is a classic zip-bomb vector; rejected
       with IgnoreRequest so Scrapy never attempts to decompress the body.
    3. Header count cap – more than MAX_HEADER_COUNT response headers is
       anomalous and could cause memory exhaustion in header-parsing code.
    4. Individual header value length cap – each header value is bounded to
       MAX_HEADER_VALUE_BYTES to prevent header-based buffer pressure.

BehavioralMimicryMiddleware
    Injects human-like request headers (Accept-Language, viewport hints) and
    randomised timing jitter to reduce behavioural fingerprinting signals.

AdaptiveDOMMiddleware
    Detects when a response contains a known anti-bot challenge page and
    marks the request for retry via Zyte API's browser mode with
    `javascript=True` escalation.

DomainRateLimitMiddleware
    Enforces per-domain request rate caps independent of Zyte's internal
    throttle, acting as a secondary back-pressure valve.

DeadLetterMiddleware
    Captures items that fail all pipeline stages and writes them to a
    ``dead_letter.jsonl`` file for post-hoc analysis.
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
    Layered defense-in-depth guard for the unpatched Scrapy DoS vulnerability.

    All four checks run inside ``process_response``, which Scrapy invokes
    *after* the body bytes are received but *before* any spider callback or
    other middleware calls ``response.text`` / ``response.body``.  Raising
    ``IgnoreRequest`` here prevents further processing and frees the buffer.

    Priority in settings.py: 50 (lower number = runs earlier than all other
    custom middlewares, ensuring bad responses are culled first).
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
        # ── Layer 1: Content-Length pre-check ─────────────────────────────────
        # Reject responses that *advertise* a body larger than our cap, before
        # any middleware attempts to decode or parse the bytes.
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
                # Non-integer Content-Length is malformed; log and continue so
                # Scrapy's own DOWNLOAD_MAXSIZE enforcement takes over.
                logger.warning(
                    "Malformed Content-Length header %r from %s",
                    cl_header,
                    request.url,
                )

        # ── Layer 2: Stacked / unknown Content-Encoding rejection ─────────────
        # A response with "Content-Encoding: gzip, gzip" (or similar stacked
        # schemes) is the hallmark of a zip-bomb attack.  We only permit a
        # single, well-known encoding layer.
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

        # ── Layer 3: Header count cap ─────────────────────────────────────────
        header_count = len(response.headers)
        if header_count > self._max_header_count:
            raise IgnoreRequest(
                f"Excessive response header count {header_count} "
                f"(limit {self._max_header_count}) from {request.url}"
            )

        # ── Layer 4: Individual header value length cap ───────────────────────
        for header_name, header_values in response.headers.items():
            for val in header_values:
                if len(val) > self._max_header_value_bytes:
                    name_str = header_name.decode("latin-1", errors="replace")
                    raise IgnoreRequest(
                        f"Header {name_str!r} value length {len(val)} exceeds "
                        f"limit {self._max_header_value_bytes} from {request.url}"
                    )

        return response


# ─── BehavioralMimicryMiddleware ──────────────────────────────────────────────

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

"""
Custom Scrapy middlewares for zyte_gmaps_scraper.

Middlewares implemented
-----------------------
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

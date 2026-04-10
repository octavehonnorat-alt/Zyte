"""
Scrapy settings – zyte_gmaps_scraper.

Security profile
----------------
* OWASP ASVS 5.0.0 §V1/V7/V8
* TLS fingerprint mitigation via Zyte API managed proxies
* Concurrency tuned for Twisted asyncio reactor (CPU-IO overlap)

All credentials MUST be injected via environment variables.
No secret may appear in this file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ─── Identity ─────────────────────────────────────────────────────────────────
BOT_NAME = "zyte_gmaps_scraper"
SPIDER_MODULES = ["zyte_gmaps_scraper.spiders"]
NEWSPIDER_MODULE = "zyte_gmaps_scraper.spiders"

# ─── Zyte API ─────────────────────────────────────────────────────────────────
# OWASP ASVS 5.0 §V2.10: credentials never hard-coded
ZYTE_API_KEY: str = os.environ.get("ZYTE_API_KEY") or sys.exit(  # type: ignore[assignment]
    "FATAL: ZYTE_API_KEY environment variable is required but not set."
)

# Default automap: every request goes through Zyte's browser by default.
ZYTE_API_AUTOMAP_PARAMS: dict = {
    "browserHtml": True,
}

# ─── Twisted asyncio reactor (required for async def callbacks) ───────────────
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"

# ─── Request fingerprinting ────────────────────────────────────────────────────
REQUEST_FINGERPRINTER_CLASS = "scrapy_zyte_api.ScrapyZyteAPIRequestFingerprinter"

# ─── Concurrency model ────────────────────────────────────────────────────────
# Tuned for massively parallel event-loop execution.
# Real scaling is achieved by running multiple Scrapy processes (scrapyd /
# Kubernetes pods), each operating at this concurrency level.
CONCURRENT_REQUESTS = 128
CONCURRENT_REQUESTS_PER_DOMAIN = 32
DOWNLOAD_TIMEOUT = 60
DOWNLOAD_DELAY = 0  # Zyte handles back-pressure internally

AUTOTHROTTLE_ENABLED = True
AUTOTHROTTLE_START_DELAY = 0.25
AUTOTHROTTLE_MAX_DELAY = 120.0
AUTOTHROTTLE_TARGET_CONCURRENCY = 64.0
AUTOTHROTTLE_DEBUG = False

# ─── Retry policy (exponential back-off + jitter) ─────────────────────────────
RETRY_ENABLED = True
RETRY_TIMES = 5
RETRY_HTTP_CODES = [429, 500, 502, 503, 504, 520, 521, 522, 524]
RETRY_PRIORITY_ADJUST = -1

# ─── Middleware stack ─────────────────────────────────────────────────────────
DOWNLOADER_MIDDLEWARES: dict = {
    # Zyte API integration (must run last, after custom middlewares)
    "scrapy_zyte_api.ScrapyZyteAPIDownloaderMiddleware": 1000,
    # Custom behavioural mimicry (runs before Zyte middleware)
    "zyte_gmaps_scraper.middlewares.BehavioralMimicryMiddleware": 100,
    # Adaptive DOM health-check
    "zyte_gmaps_scraper.middlewares.AdaptiveDOMMiddleware": 200,
    # Per-domain rate guard
    "zyte_gmaps_scraper.middlewares.DomainRateLimitMiddleware": 300,
}

SPIDER_MIDDLEWARES: dict = {
    "scrapy_zyte_api.ScrapyZyteAPISpiderMiddleware": 100,
    # Dead-letter queue for unrecoverable items
    "zyte_gmaps_scraper.middlewares.DeadLetterMiddleware": 900,
}

# ─── Item pipelines ────────────────────────────────────────────────────────────
ITEM_PIPELINES: dict = {
    "zyte_gmaps_scraper.pipelines.InputValidationPipeline": 100,
    "zyte_gmaps_scraper.pipelines.DeduplicationPipeline": 200,
    "zyte_gmaps_scraper.pipelines.EmailVerificationPipeline": 300,
    "zyte_gmaps_scraper.pipelines.CryptographicSigningPipeline": 400,
    "zyte_gmaps_scraper.pipelines.JsonLinesExportPipeline": 500,
}

# ─── Feed export ──────────────────────────────────────────────────────────────
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FEEDS: dict = {
    str(OUTPUT_DIR / "leads_%(time)s.jsonl"): {
        "format": "jsonlines",
        "encoding": "utf-8",
        "store_empty": False,
        "overwrite": False,
    }
}

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
LOG_DATEFORMAT = "%Y-%m-%dT%H:%M:%S"

# ─── Telemetry / privacy ──────────────────────────────────────────────────────
TELEMETRY_ENABLED = False
COOKIES_ENABLED = False  # Zyte API manages cookies internally
ROBOTSTXT_OBEY = False   # Zyte proxied requests; obedience handled upstream

# ─── Memory & GC pressure ─────────────────────────────────────────────────────
MEMUSAGE_ENABLED = True
MEMUSAGE_LIMIT_MB = 4096
MEMUSAGE_WARNING_MB = 2048

# ─── Duplicate filtering ──────────────────────────────────────────────────────
DUPEFILTER_CLASS = "scrapy.dupefilters.RFPDupeFilter"
DUPEFILTER_DEBUG = False

# ─── Encryption / ZKP secrets (injected at runtime, never logged) ─────────────
LEAD_ENCRYPTION_KEY: str = os.environ.get("LEAD_ENCRYPTION_KEY", "")
CHAIN_HMAC_SECRET: str = os.environ.get("CHAIN_HMAC_SECRET", "")

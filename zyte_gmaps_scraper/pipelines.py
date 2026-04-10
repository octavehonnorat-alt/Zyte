"""
Scrapy item pipelines for zyte_gmaps_scraper.

Pipeline order
--------------
100  InputValidationPipeline     – Pydantic schema validation (OWASP ASVS §V5)
200  DeduplicationPipeline       – Drop leads already seen in this run
300  EmailVerificationPipeline   – Async 3-stage email verification
400  CryptographicSigningPipeline – ZKP commitment + chain of custody
500  JsonLinesExportPipeline     – Append to output/<ts>.jsonl
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

import orjson
import scrapy
from itemadapter import ItemAdapter
from pydantic import ValidationError
from scrapy.exceptions import DropItem

from .crypto_chain import DataChainOfCustody
from .email_verifier import AsyncEmailVerifier
from .items import (
    BusinessProfile,
    DeliverabilityTier,
    EmailLead,
    ExtractionMethod,
    VerificationResult,
)

logger = logging.getLogger(__name__)


# ─── 100 – Input Validation ───────────────────────────────────────────────────

class InputValidationPipeline:
    """
    Validates that each item produced by the spider matches the
    ``BusinessProfile`` Pydantic schema (OWASP ASVS 5.0 §V5.1).

    Malformed items are dropped with a structured log entry; they are also
    forwarded to the dead-letter file by ``DeadLetterMiddleware``.
    """

    def process_item(self, item: Any, spider: scrapy.Spider) -> Any:
        adapter = ItemAdapter(item)
        raw = dict(adapter)

        try:
            # If the item is already a Pydantic model, re-validate it.
            if isinstance(item, (BusinessProfile, EmailLead)):
                item.model_validate(item.model_dump())
                return item

            # Otherwise attempt to coerce from dict.
            BusinessProfile(**raw)
            return item

        except (ValidationError, TypeError) as exc:
            raise DropItem(f"Schema validation failed: {exc}") from exc


# ─── 200 – Deduplication ──────────────────────────────────────────────────────

class DeduplicationPipeline:
    """
    In-process deduplication using a SHA-256 fingerprint of
    ``(business_id, normalised_email)``.

    For cross-process / distributed deduplication, replace ``_seen`` with a
    Redis SSET or Bloom filter backed by shared memory.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def process_item(self, item: Any, spider: scrapy.Spider) -> Any:
        adapter = ItemAdapter(item)
        business_id = adapter.get("business_id") or adapter.get("business", {}).get("business_id", "")
        email = str(adapter.get("email", "")).lower().strip()

        if not email:
            return item  # no email yet; let downstream pipelines handle it

        fp = hashlib.sha256(f"{business_id}:{email}".encode()).hexdigest()
        if fp in self._seen:
            raise DropItem(f"Duplicate lead: {email} for business {business_id}")
        self._seen.add(fp)
        return item


# ─── 300 – Email Verification ─────────────────────────────────────────────────

class EmailVerificationPipeline:
    """
    Async 3-stage email verification (syntax → DNS/MX → SMTP ping).

    Items whose email resolves to ``DeliverabilityTier.INVALID`` are dropped.
    Items with ``DeliverabilityTier.LOW`` are kept but flagged.
    """

    def __init__(self) -> None:
        self._verifier = AsyncEmailVerifier()

    def open_spider(self, spider: scrapy.Spider) -> None:
        logger.info("EmailVerificationPipeline active.")

    async def process_item(self, item: Any, spider: scrapy.Spider) -> Any:
        adapter = ItemAdapter(item)
        email: str = str(adapter.get("email", ""))

        if not email:
            return item

        result: VerificationResult = await self._verifier.verify(email)

        if result.deliverability_tier == DeliverabilityTier.INVALID:
            raise DropItem(
                f"Email {email!r} failed verification (INVALID): "
                f"syntax={result.is_valid_syntax}"
            )

        # Attach verification result to item
        if hasattr(item, "verification"):
            object.__setattr__(item, "verification", result)
        else:
            adapter["verification"] = result

        return item


# ─── 400 – Cryptographic Signing ─────────────────────────────────────────────

class CryptographicSigningPipeline:
    """
    Attaches a ZKP commitment and a chain-of-custody entry to every lead.

    This pipeline MUST run after email verification so that the verification
    result is included in the commitment payload.
    """

    def __init__(self, hmac_secret: str, encryption_key: str) -> None:
        self._chain = DataChainOfCustody(
            hmac_secret=hmac_secret,
            encryption_key=encryption_key,
        )

    @classmethod
    def from_crawler(cls, crawler: scrapy.crawler.Crawler) -> "CryptographicSigningPipeline":
        return cls(
            hmac_secret=crawler.settings.get("CHAIN_HMAC_SECRET", ""),
            encryption_key=crawler.settings.get("LEAD_ENCRYPTION_KEY", ""),
        )

    def process_item(self, item: Any, spider: scrapy.Spider) -> Any:
        adapter = ItemAdapter(item)

        business_id = (
            adapter.get("business_id")
            or (adapter.get("business") or {}).get("business_id", "unknown")
        )
        email = str(adapter.get("email", ""))
        source_url = adapter.get("source_url") or adapter.get("extraction_source", "")
        scraped_at = adapter.get("scraped_at") or adapter.get("extracted_at")
        from datetime import datetime, timezone
        if scraped_at is None:
            scraped_at = datetime.now(timezone.utc)

        extraction_method = adapter.get("extraction_method", ExtractionMethod.UNKNOWN)
        if isinstance(extraction_method, str):
            extraction_method = ExtractionMethod(extraction_method)

        # Generate fingerprint and commit
        fp = self._chain.create_lead_fingerprint(business_id, email, source_url, scraped_at)
        commitment = self._chain.create_zkp_commitment({"business_id": business_id, "email": email})
        chain_entry = self._chain.create_chain_entry(fp, source_url, extraction_method, scraped_at)

        if hasattr(item, "zkp_commitment"):
            object.__setattr__(item, "zkp_commitment", commitment)
            object.__setattr__(item, "chain_entry", chain_entry)
        else:
            adapter["zkp_commitment"] = commitment
            adapter["chain_entry"] = chain_entry

        return item


# ─── 500 – JSON Lines Export ──────────────────────────────────────────────────

class JsonLinesExportPipeline:
    """
    Appends serialised leads to the output file.

    Pydantic models are serialised via ``model_dump(mode="json")`` for
    full type fidelity; plain dicts fall back to ``orjson.dumps``.
    """

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir
        self._file = None

    @classmethod
    def from_crawler(cls, crawler: scrapy.crawler.Crawler) -> "JsonLinesExportPipeline":
        return cls(output_dir=Path(crawler.settings.get("OUTPUT_DIR", "./output")))

    def open_spider(self, spider: scrapy.Spider) -> None:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        ts = spider.crawler.stats.get_value("start_time") or "run"
        filename = f"leads_{spider.name}_{ts}.jsonl".replace(" ", "_").replace(":", "-")
        path = self._output_dir / filename
        self._file = path.open("ab")
        logger.info("Export pipeline writing to %s", path)

    def close_spider(self, spider: scrapy.Spider) -> None:
        if self._file:
            self._file.close()

    def process_item(self, item: Any, spider: scrapy.Spider) -> Any:
        if hasattr(item, "model_dump"):
            raw = item.model_dump(mode="json")
        else:
            raw = dict(ItemAdapter(item))

        self._file.write(orjson.dumps(raw) + b"\n")
        return item

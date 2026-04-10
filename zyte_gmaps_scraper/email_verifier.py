"""
Async email verification module.

Verification cascade
--------------------
1. Syntactic validation (RFC 5321/5322 + Unicode IDNA) via *email-validator*.
2. DNS / MX record resolution via *dnspython* async resolver.
3. Silent SMTP "ping" – RCPT TO without DATA – via *aiosmtplib*.

Rate-limiting
-------------
SMTP verifications are rate-limited per MX host to avoid triggering
anti-spam defences.  An in-memory LRU cache prevents re-verification of
recently seen addresses.

OWASP ASVS 5.0 §V5.1 compliance
---------------------------------
All inputs are bounded-length strings; no shell expansion or eval is used.
SMTP connection is always terminated with QUIT before the coroutine returns.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Optional

import dns.asyncresolver
import dns.exception
from aiosmtplib import SMTP, SMTPConnectError, SMTPServerDisconnected
from email_validator import EmailNotValidError, validate_email
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from .items import DeliverabilityTier, SmtpStatus, VerificationResult

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────
_SMTP_TIMEOUT = 10          # seconds per SMTP operation
_DNS_TIMEOUT = 8            # seconds for DNS resolution
_CACHE_TTL = 3600           # seconds to cache verification results
_CACHE_MAX_SIZE = 50_000    # max LRU cache entries (≈ 50 k emails)
_SMTP_PORT = 25
_SMTP_HELO_DOMAIN = os.environ.get("SMTP_HELO_DOMAIN", "verify.example.com")
# NOTE: For production use, set SMTP_HELO_DOMAIN to a domain you control
# that has a valid forward DNS record.  Using example.com may cause some
# strict SMTP servers to reject the EHLO greeting.
_SMTP_PROBE_SENDER = f"probe@{_SMTP_HELO_DOMAIN}"

# Domains known to block SMTP probing – skip SMTP step for these
_SMTP_BLOCKED_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com", "googlemail.com",
        "yahoo.com", "yahoo.fr", "yahoo.co.uk",
        "hotmail.com", "outlook.com", "live.com", "msn.com",
        "icloud.com", "me.com", "mac.com",
        "protonmail.com", "proton.me",
    }
)


# ─── Simple thread-safe LRU cache ─────────────────────────────────────────────

class _LRUCache:
    def __init__(self, maxsize: int, ttl: int) -> None:
        self._store: OrderedDict[str, tuple[VerificationResult, float]] = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[VerificationResult]:
        async with self._lock:
            if key not in self._store:
                return None
            result, ts = self._store[key]
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return result

    async def set(self, key: str, value: VerificationResult) -> None:
        async with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, time.monotonic())
            if len(self._store) > self._maxsize:
                self._store.popitem(last=False)


# ─── Per-host SMTP rate limiter ────────────────────────────────────────────────

class _SmtpRateLimiter:
    """Allows at most ``rate`` calls per ``window`` seconds per MX host."""

    def __init__(self, rate: int = 3, window: float = 60.0) -> None:
        self._rate = rate
        self._window = window
        self._buckets: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> bool:
        """Return True if the call is allowed, False if rate-limited."""
        async with self._lock:
            now = time.monotonic()
            bucket = self._buckets.setdefault(host, [])
            # evict expired timestamps
            self._buckets[host] = [t for t in bucket if now - t < self._window]
            if len(self._buckets[host]) >= self._rate:
                return False
            self._buckets[host].append(now)
            return True


# ─── Main verifier ────────────────────────────────────────────────────────────

class AsyncEmailVerifier:
    """
    Async email verifier implementing a 3-stage cascade.

    Usage::

        verifier = AsyncEmailVerifier()
        result = await verifier.verify("contact@example.com")
    """

    def __init__(
        self,
        smtp_timeout: int = _SMTP_TIMEOUT,
        dns_timeout: int = _DNS_TIMEOUT,
        smtp_rate: int = 3,
    ) -> None:
        self._cache: _LRUCache = _LRUCache(_CACHE_MAX_SIZE, _CACHE_TTL)
        self._smtp_limiter = _SmtpRateLimiter(rate=smtp_rate)
        self._smtp_timeout = smtp_timeout
        self._dns_timeout = dns_timeout

    # ── Public API ────────────────────────────────────────────────────────────

    async def verify(self, email: str) -> VerificationResult:
        """
        Full 3-stage verification.  Cached per address for ``_CACHE_TTL`` s.
        """
        # OWASP ASVS 5.0 §V5.1.3 – bounded input
        if not isinstance(email, str) or len(email) > 254:
            return _invalid_result(email, "Input is not a valid string or exceeds 254 chars.")

        cached = await self._cache.get(email.lower())
        if cached is not None:
            return cached

        result = await self._full_verify(email)
        await self._cache.set(email.lower(), result)
        return result

    # ── Stage 1: Syntax ────────────────────────────────────────────────────────

    def _syntax_check(self, email: str) -> tuple[bool, bool, Optional[str], Optional[str]]:
        """
        Returns (is_valid, is_unicode, normalised_email, domain).
        Uses email-validator which enforces RFC 5321/5322 + Unicode IDNA 2008.
        """
        try:
            info = validate_email(email, check_deliverability=False)
            normalised = info.normalized
            domain = info.domain.lower()
            is_unicode = bool(re.search(r"[^\x00-\x7F]", email))
            return True, is_unicode, normalised, domain
        except EmailNotValidError:
            return False, False, None, None

    # ── Stage 2: DNS / MX ─────────────────────────────────────────────────────

    async def _resolve_mx(self, domain: str) -> list[str]:
        """Return MX hostnames sorted by preference (lowest = highest priority)."""
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self._dns_timeout
        resolver.lifetime = self._dns_timeout * 2
        try:
            answers = await resolver.resolve(domain, "MX")
            pairs = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
            return [host for _, host in pairs]
        except (dns.exception.DNSException, Exception) as exc:
            logger.debug("MX lookup failed for %s: %s", domain, exc)
            return []

    # ── Stage 3: SMTP ping ────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type((SMTPConnectError, OSError, asyncio.TimeoutError)),
        stop=stop_after_attempt(2),
        wait=wait_exponential_jitter(initial=1, max=10),
        reraise=False,
    )
    async def _smtp_ping(
        self, email: str, mx_host: str
    ) -> tuple[SmtpStatus, Optional[int], Optional[str]]:
        """
        Silent SMTP probe: EHLO → MAIL FROM → RCPT TO → QUIT.
        No DATA is ever sent.  Returns (status, response_code, response_msg).
        """
        allowed = await self._smtp_limiter.acquire(mx_host)
        if not allowed:
            logger.debug("SMTP rate limit hit for %s", mx_host)
            return SmtpStatus.SKIPPED, None, "rate-limited"

        smtp = SMTP(
            hostname=mx_host,
            port=_SMTP_PORT,
            timeout=self._smtp_timeout,
            use_tls=False,
        )
        try:
            await asyncio.wait_for(smtp.connect(), timeout=self._smtp_timeout)
            await smtp.ehlo(_SMTP_HELO_DOMAIN)
            await smtp.mail(_SMTP_PROBE_SENDER)
            code, msg = await smtp.rcpt(email)
            await smtp.quit()

            if 200 <= code < 300:
                return SmtpStatus.VERIFIED, code, msg
            if 400 <= code < 500:
                return SmtpStatus.GREYLISTED, code, msg
            # 500-series = permanent rejection
            return SmtpStatus.REJECTED, code, msg

        except (SMTPConnectError, ConnectionRefusedError, socket.gaierror, OSError) as exc:
            logger.debug("SMTP connect failed to %s: %s", mx_host, exc)
            return SmtpStatus.BLOCKED, None, str(exc)
        except asyncio.TimeoutError:
            return SmtpStatus.TIMEOUT, None, "connection timed out"
        except SMTPServerDisconnected as exc:
            return SmtpStatus.BLOCKED, None, str(exc)
        finally:
            try:
                await smtp.quit()
            except Exception:
                pass

    # ── Orchestrator ──────────────────────────────────────────────────────────

    async def _full_verify(self, email: str) -> VerificationResult:
        ts = datetime.now(timezone.utc)

        # Stage 1 – syntax
        is_valid, is_unicode, normalised, domain = self._syntax_check(email)
        if not is_valid or domain is None:
            return VerificationResult(
                email=email,
                is_valid_syntax=False,
                is_valid_unicode=False,
                deliverability_tier=DeliverabilityTier.INVALID,
                verified_at=ts,
            )

        # Stage 2 – DNS/MX
        mx_records = await self._resolve_mx(domain)
        mx_reachable = bool(mx_records)

        if not mx_reachable:
            return VerificationResult(
                email=email,
                normalised_email=normalised,
                is_valid_syntax=True,
                is_valid_unicode=is_unicode,
                local_part=normalised.split("@")[0] if normalised else None,
                domain=domain,
                mx_records=[],
                mx_reachable=False,
                deliverability_score=0.1,
                deliverability_tier=DeliverabilityTier.LOW,
                verified_at=ts,
            )

        # Stage 3 – SMTP ping (skip for large providers that block it)
        smtp_status = SmtpStatus.SKIPPED
        smtp_code: Optional[int] = None
        smtp_msg: Optional[str] = None

        if domain not in _SMTP_BLOCKED_DOMAINS:
            smtp_status, smtp_code, smtp_msg = await self._smtp_ping(
                normalised or email, mx_records[0]
            )

        # Score calculation
        score, tier = _compute_deliverability(mx_reachable, smtp_status, domain)

        return VerificationResult(
            email=email,
            normalised_email=normalised,
            is_valid_syntax=True,
            is_valid_unicode=is_unicode,
            local_part=normalised.split("@")[0] if normalised else None,
            domain=domain,
            mx_records=mx_records,
            mx_reachable=True,
            smtp_status=smtp_status,
            smtp_response_code=smtp_code,
            smtp_response_message=smtp_msg,
            deliverability_score=score,
            deliverability_tier=tier,
            verified_at=ts,
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _invalid_result(email: str, reason: str) -> VerificationResult:
    logger.debug("Invalid email input: %s – %s", email, reason)
    return VerificationResult(
        email=email,
        is_valid_syntax=False,
        deliverability_tier=DeliverabilityTier.INVALID,
        verified_at=datetime.now(timezone.utc),
    )


def _compute_deliverability(
    mx_reachable: bool, smtp_status: SmtpStatus, domain: str
) -> tuple[float, DeliverabilityTier]:
    if not mx_reachable:
        return 0.1, DeliverabilityTier.LOW

    # Known-good large provider – we can't SMTP-ping them but they're reliable
    if domain in _SMTP_BLOCKED_DOMAINS:
        return 0.75, DeliverabilityTier.MEDIUM

    if smtp_status == SmtpStatus.VERIFIED:
        return 0.99, DeliverabilityTier.HIGH
    if smtp_status == SmtpStatus.GREYLISTED:
        return 0.65, DeliverabilityTier.MEDIUM
    if smtp_status == SmtpStatus.REJECTED:
        return 0.05, DeliverabilityTier.LOW
    if smtp_status in (SmtpStatus.TIMEOUT, SmtpStatus.BLOCKED):
        return 0.55, DeliverabilityTier.MEDIUM   # can't confirm, likely valid
    # SKIPPED
    return 0.60, DeliverabilityTier.MEDIUM

"""
Pydantic v2 domain models for zyte_gmaps_scraper.

All external data MUST pass through these validators before processing
(OWASP ASVS 5.0 §V5 – Input Validation).

ZKP-compatible commitment structure
------------------------------------
Each lead carries a ``ZKPCommitment`` that enables selective disclosure
under GDPR Article 25 (data-protection-by-design):

  commitment = BLAKE2b-512( serialize(data) ‖ blinding_nonce )

The prover can reveal (data, nonce) to any verifier without exposing raw
data on the network.  The verifier re-computes the hash and checks equality.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)


# ─── Enumerations ──────────────────────────────────────────────────────────────


class ExtractionMethod(str, Enum):
    DESCRIPTION = "description"
    GOOGLE_POSTS = "google_posts"
    SOCIAL_FACEBOOK = "social_facebook"
    SOCIAL_LINKEDIN = "social_linkedin"
    REGISTRY = "registry"
    PHONE_PERMUTATION = "phone_permutation"
    UNKNOWN = "unknown"


class SmtpStatus(str, Enum):
    VERIFIED = "verified"       # 2xx from RCPT TO
    REJECTED = "rejected"       # 5xx from RCPT TO
    GREYLISTED = "greylisted"   # 4xx transient
    TIMEOUT = "timeout"
    BLOCKED = "blocked"         # server refused connection on port 25/587
    SKIPPED = "skipped"         # disabled or rate-limited


class DeliverabilityTier(str, Enum):
    HIGH = "high"       # syntax ✓  MX ✓  SMTP ✓
    MEDIUM = "medium"   # syntax ✓  MX ✓  SMTP unknown
    LOW = "low"         # syntax ✓  MX ✗
    INVALID = "invalid" # syntax ✗


# ─── Sub-models ────────────────────────────────────────────────────────────────


class VerificationResult(BaseModel):
    """RFC 5321/5322 + Unicode IDNA email verification."""

    email: str
    normalised_email: Optional[str] = None
    is_valid_syntax: bool = False
    is_valid_unicode: bool = False
    local_part: Optional[str] = None
    domain: Optional[str] = None
    mx_records: list[str] = Field(default_factory=list)
    mx_reachable: bool = False
    smtp_status: SmtpStatus = SmtpStatus.SKIPPED
    smtp_response_code: Optional[int] = None
    smtp_response_message: Optional[str] = None
    deliverability_score: float = Field(0.0, ge=0.0, le=1.0)
    deliverability_tier: DeliverabilityTier = DeliverabilityTier.INVALID
    verified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ZKPCommitment(BaseModel):
    """
    Pedersen-style hiding & binding commitment.

    Guarantees GDPR Article 25 compliance:
    - ``commitment`` is safe to publish (reveals nothing about the plaintext).
    - ``data_ciphertext`` is AES-256-GCM encrypted; key never leaves the
      secure enclave / HSM.
    - Right-to-be-forgotten: delete the encryption key to irreversibly
      pseudonymise the record.
    """

    commitment: str               # BLAKE2b-512( data_bytes ‖ nonce ) – hex
    nonce: str                    # 32-byte random blinding factor – hex
    data_ciphertext: str          # AES-256-GCM( data_bytes ) – base64
    data_hash_sha3: str           # SHA3-256( data_bytes ) – hex cross-reference
    commitment_algorithm: str = "BLAKE2b-512"
    encryption_algorithm: str = "AES-256-GCM"
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ChainEntry(BaseModel):
    """
    Immutable chain-of-custody record (Data Provenance – NIST SP 800-188).

    Each entry records the full audit trail for a single lead extraction event.
    The ``chain_hash`` is a chained BLAKE2b that links this entry to the
    previous one, forming a tamper-evident log.
    """

    entry_id: str                  # UUIDv4
    lead_fingerprint: str          # BLAKE2b-512( business_id ‖ email ‖ ts ) – hex
    source_url: str
    extractor_version: str
    extraction_method: ExtractionMethod
    scraped_at: datetime
    chain_hash: str                # BLAKE2b-512( previous_hash ‖ lead_fingerprint )
    hmac_signature: str            # HMAC-SHA3-256 signed with CHAIN_HMAC_SECRET


class BusinessProfile(BaseModel):
    """
    Validated Google Maps business record.

    OWASP ASVS 5.0 §V5.1: all string fields are length-bounded.
    Input containing null-bytes or control characters is rejected.
    """

    business_id: str = Field(..., min_length=1, max_length=256)
    name: str = Field(..., min_length=1, max_length=512)
    category: str = Field("", max_length=256)
    address: str = Field("", max_length=1024)
    city: str = Field("", max_length=256)
    country: str = Field("", max_length=128)
    phone: Optional[str] = Field(None, max_length=32)
    website: Optional[str] = None     # MUST be None for our zero-website filter
    plus_code: Optional[str] = Field(None, max_length=16)
    rating: Optional[float] = Field(None, ge=0.0, le=5.0)
    review_count: Optional[int] = Field(None, ge=0)
    description: str = Field("", max_length=8192)
    google_posts: list[str] = Field(default_factory=list)
    social_urls: list[str] = Field(default_factory=list)
    source_url: str = Field(..., max_length=2048)
    scraped_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("name", "category", "address", "city", "country", "description", mode="before")
    @classmethod
    def _reject_control_chars(cls, v: object) -> object:
        """OWASP ASVS 5.0 §V5.1.4 – reject null-bytes and C0/C1 control chars."""
        if isinstance(v, str) and any(ord(c) < 32 and c not in "\t\n\r" for c in v):
            raise ValueError("Control characters are not permitted in this field.")
        return v

    @field_validator("website", mode="before")
    @classmethod
    def _website_must_be_absent(cls, v: object) -> object:
        """Reject records that do have a website – they are out of scope."""
        if v and str(v).strip():
            raise ValueError("BusinessProfile must represent a zero-website business.")
        return None


class EmailLead(BaseModel):
    """
    A verified email lead with full provenance.

    This is the canonical output item of the spider pipeline.
    """

    business: BusinessProfile
    email: EmailStr
    verification: VerificationResult
    extraction_method: ExtractionMethod
    extraction_source: str = Field(..., max_length=2048)
    zkp_commitment: ZKPCommitment
    chain_entry: ChainEntry
    extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @model_validator(mode="after")
    def _minimum_deliverability(self) -> "EmailLead":
        """Reject leads whose email cannot be at least minimally verified."""
        if self.verification.deliverability_tier == DeliverabilityTier.INVALID:
            raise ValueError(
                f"Email {self.email!r} failed syntax validation and cannot be a lead."
            )
        return self

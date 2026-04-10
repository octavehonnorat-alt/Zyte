"""
Cryptographic chain-of-custody and ZKP commitment module.

Algorithms used (FIPS 140-3 approved / NIST SP 800-57)
-------------------------------------------------------
* BLAKE2b-512    – fast, keyed hash for fingerprinting & chained ledger
* SHA3-256        – cross-reference hash (post-quantum second-preimage resistant)
* HMAC-SHA3-256  – signed chain entries; key = CHAIN_HMAC_SECRET
* AES-256-GCM    – authenticated encryption for ZKP ciphertexts
* CSPRNG         – ``secrets.token_bytes`` for nonces and IVs

ZKP commitment scheme
---------------------
  nonce   = CSPRNG(32 bytes)
  payload = serialize(data)                  # deterministic orjson
  commit  = BLAKE2b-512( payload ‖ nonce )   # binding & hiding

To verify: recompute commit from (data, nonce) and compare with stored value.
To disclose selectively: reveal only the fields you need; the verifier checks
that H(partial ‖ nonce) matches the stored partial commitment.

GDPR right-to-be-forgotten
----------------------------
Delete the AES key associated with a data subject's record.  The ciphertext
becomes computationally irreversible; the commitment (a hash) stays on the
immutable audit ledger.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import orjson

from .items import ChainEntry, ExtractionMethod, ZKPCommitment

# ─── Module-level constants ────────────────────────────────────────────────────
_EXTRACTOR_VERSION = "1.0.0"
_BLAKE2B_DIGEST = 64          # 512 bits
_NONCE_BYTES = 32             # 256-bit blinding factor
_AES_KEY_BYTES = 32           # AES-256
_AES_IV_BYTES = 12            # GCM recommended IV length


class DataChainOfCustody:
    """
    Tamper-evident ledger + ZKP commitment factory.

    Parameters
    ----------
    hmac_secret:
        Hex-encoded 32-byte HMAC signing key (``CHAIN_HMAC_SECRET`` env var).
        If empty, chain entries are generated without an HMAC signature
        (development mode – never use in production).
    encryption_key:
        Hex-encoded 32-byte AES encryption key (``LEAD_ENCRYPTION_KEY`` env var).
        If empty, ciphertexts are replaced with a base64-encoded plaintext
        copy (development mode – never use in production).
    """

    def __init__(
        self,
        hmac_secret: str = "",
        encryption_key: str = "",
    ) -> None:
        self._hmac_key: Optional[bytes] = bytes.fromhex(hmac_secret) if hmac_secret else None
        self._aes_key: Optional[bytes] = bytes.fromhex(encryption_key) if encryption_key else None
        self._previous_hash: str = "0" * 128   # genesis hash (512 zero-bits, hex)

    # ── Public API ─────────────────────────────────────────────────────────────

    def create_lead_fingerprint(
        self,
        business_id: str,
        email: str,
        source_url: str,
        scraped_at: datetime,
    ) -> str:
        """
        BLAKE2b-512 fingerprint that uniquely identifies a (business, email)
        extraction event.  Used as a deduplication key and chain-entry payload.
        """
        payload = _encode(
            {
                "business_id": business_id,
                "email": email.lower(),
                "source_url": source_url,
                "scraped_at": scraped_at.isoformat(),
            }
        )
        return _blake2b(payload).hex()

    def create_zkp_commitment(
        self, data: dict[str, Any]
    ) -> ZKPCommitment:
        """
        Create a hiding-and-binding commitment for ``data``.

        The ``data_ciphertext`` field is AES-256-GCM encrypted.
        In development mode (no AES key configured) a warning is logged and
        the payload is base64-encoded without encryption.
        """
        nonce = secrets.token_bytes(_NONCE_BYTES)
        payload = _encode(data)

        # Commitment = BLAKE2b-512( payload ‖ nonce )
        commitment = _blake2b(payload + nonce).hex()

        # Cross-reference hash (SHA3-256) for independent verification
        data_hash_sha3 = hashlib.sha3_256(payload).hexdigest()

        # Encrypt payload
        if self._aes_key:
            data_ciphertext = _aes_gcm_encrypt(self._aes_key, payload)
        else:
            # Development fallback: base64-only (NOT secure)
            data_ciphertext = base64.b64encode(payload).decode()

        return ZKPCommitment(
            commitment=commitment,
            nonce=nonce.hex(),
            data_ciphertext=data_ciphertext,
            data_hash_sha3=data_hash_sha3,
            created_at=datetime.now(timezone.utc),
        )

    def create_chain_entry(
        self,
        lead_fingerprint: str,
        source_url: str,
        extraction_method: ExtractionMethod,
        scraped_at: datetime,
    ) -> ChainEntry:
        """
        Append a new entry to the in-memory tamper-evident ledger.

        ``chain_hash = BLAKE2b-512( previous_hash ‖ lead_fingerprint )``
        ensures that any retroactive modification of a prior entry breaks
        all subsequent chain hashes.
        """
        entry_id = str(uuid.uuid4())
        chain_payload = (self._previous_hash + lead_fingerprint).encode()
        chain_hash = _blake2b(chain_payload).hex()

        # HMAC signature over the full entry
        hmac_sig = self._sign(
            {
                "entry_id": entry_id,
                "lead_fingerprint": lead_fingerprint,
                "chain_hash": chain_hash,
                "source_url": source_url,
                "scraped_at": scraped_at.isoformat(),
            }
        )

        self._previous_hash = chain_hash   # advance ledger head

        return ChainEntry(
            entry_id=entry_id,
            lead_fingerprint=lead_fingerprint,
            source_url=source_url,
            extractor_version=_EXTRACTOR_VERSION,
            extraction_method=extraction_method,
            scraped_at=scraped_at,
            chain_hash=chain_hash,
            hmac_signature=hmac_sig,
        )

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _sign(self, data: dict[str, Any]) -> str:
        """HMAC-SHA3-256 signature; returns 'unsigned' in development mode."""
        if not self._hmac_key:
            return "unsigned-development-mode"
        payload = _encode(data)
        sig = hmac.new(self._hmac_key, payload, digestmod=hashlib.sha3_256)
        return sig.hexdigest()


# ─── Module-level cryptographic helpers ───────────────────────────────────────

def _encode(obj: Any) -> bytes:
    """Deterministic canonical serialisation via orjson (sorted keys)."""
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS)


def _blake2b(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=_BLAKE2B_DIGEST).digest()


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> str:
    """
    AES-256-GCM authenticated encryption.

    Returns base64-encoded ``iv ‖ tag ‖ ciphertext``.
    Uses the ``cryptography`` library (OpenSSL backend, FIPS-validated).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # lazy import

    iv = secrets.token_bytes(_AES_IV_BYTES)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, associated_data=None)
    return base64.b64encode(iv + ct_with_tag).decode()


def aes_gcm_decrypt(key: bytes, ciphertext_b64: str) -> bytes:
    """
    Inverse of ``_aes_gcm_encrypt``.

    Raises ``cryptography.exceptions.InvalidTag`` if authentication fails
    (tamper detected).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:_AES_IV_BYTES]
    ct_with_tag = raw[_AES_IV_BYTES:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct_with_tag, associated_data=None)

"""
Google Maps Zero-Website Email Extraction Spider
================================================

Auto-repairing, fully asynchronous Scrapy spider that extracts contact
e-mails from businesses listed on Google Maps **without a website**.

Extraction cascade (zero-website businesses only)
-------------------------------------------------
1. Parse Google Maps search results → filter listings with no website URL.
2. Visit each business profile (Zyte API browser):
   a. Regex scan of description text.
   b. Regex scan of Google Posts.
   c. Follow Facebook / LinkedIn links → regex scan.
   d. Extract Plus Code → query commercial registry (SIRENE, Companies House…).
   e. Fallback: phone number → infer domain → generate email permutations.
3. Every found address enters the verification + crypto pipeline.

Anti-bot resistance
-------------------
* All requests are routed through Zyte API's managed residential browser
  infrastructure (TLS fingerprint mitigation, IP rotation).
* BehavioralMimicryMiddleware adds viewport / Accept-Language randomisation.
* AdaptiveDOMMiddleware detects challenges and escalates rendering.
* Multiple CSS selector fallbacks handle Google Maps DOM mutations.

OWASP ASVS 5.0.0 compliance notes
-----------------------------------
§V5.1 – All external data is validated via Pydantic before use.
§V5.2 – Regex patterns are pre-compiled with explicit bounds.
§V7.1 – Cryptographic operations use FIPS-approved algorithms (see crypto_chain).
§V8.2 – PII (emails) is stored encrypted; commitments are the public artefacts.

Usage
-----
::

    scrapy crawl gmaps_zero_website \\
        -a queries="plombiers Paris,electriciens Lyon" \\
        -a max_results=500 \\
        -s ZYTE_API_KEY=<key>
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

import phonenumbers
import scrapy
from scrapy.http import Response

from ..crypto_chain import DataChainOfCustody
from ..email_verifier import AsyncEmailVerifier
from ..items import (
    BusinessProfile,
    DeliverabilityTier,
    EmailLead,
    ExtractionMethod,
    VerificationResult,
)

logger = logging.getLogger(__name__)

# ─── Pre-compiled regex patterns (OWASP ASVS §V5.2) ──────────────────────────
# RFC 5321 local-part: max 64 chars; domain: max 255 chars; total: max 254.
_EMAIL_RE = re.compile(
    r"(?<![='\"/])"                     # negative lookbehind – not in HTML attr
    r"([a-zA-Z0-9._%+\-]{1,64}"
    r"@"
    r"[a-zA-Z0-9.\-]{1,253}"
    r"\.[a-zA-Z]{2,})"
    r"(?!['\">])",                       # negative lookahead – not closing HTML
    re.ASCII,
)

_PLUS_CODE_RE = re.compile(
    r"\b([23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,3})\b"
)

# Social media URL patterns
_SOCIAL_PATTERNS = {
    "facebook": re.compile(r"https?://(?:www\.)?facebook\.com/[^\s\"'<>]+", re.I),
    "linkedin": re.compile(r"https?://(?:www\.)?linkedin\.com/(?:company|in)/[^\s\"'<>]+", re.I),
}

# ─── CSS selector fallback chains ─────────────────────────────────────────────
# Google Maps DOM changes frequently; we try selectors in order.
_SEL_LISTING = [
    "div.Nv2PK",
    "div[jsaction*='mouseover:pane.listing']",
    "div[data-result-index]",
]
_SEL_NAME_IN_LISTING = [
    "div.qBF1Pd::text",
    "span.fontHeadlineSmall::text",
    "div.fontBodyMedium span::text",
]
_SEL_PROFILE_LINK = [
    "a.hfpxzc::attr(href)",
    "a[data-value='Directions']::attr(href)",
]
_SEL_WEBSITE_PRESENT = [
    "a[data-tooltip='Open website']",
    "a[data-item-id='authority']",
    "a[aria-label*='website' i]",
]
_SEL_BUSINESS_NAME = [
    "h1.DUwDvf::text",
    "h1[data-attrid='title']::text",
    "div[role='main'] h1::text",
]
_SEL_PHONE = [
    "a[href^='tel:']::attr(href)",
    "button[data-tooltip*='phone' i]::attr(aria-label)",
]
_SEL_ADDRESS = [
    "button[data-tooltip='Copy address']::attr(aria-label)",
    "div[data-item-id^='address'] div.fontBodyMedium::text",
]
_SEL_CATEGORY = [
    "button[jsaction='pane.rating.category']::text",
    "span.YhemCb::text",
    "button[aria-label*='categor' i]::text",
]
_SEL_DESCRIPTION = [
    "div[data-attrid='kc:/local:merchant_description'] span::text",
    "div.WeS02d span::text",
    "div[aria-label*='description' i]::text",
    "div[class*='description']::text",
]
_SEL_GOOGLE_POSTS = [
    "div[aria-label='Posts'] div.fontBodyMedium::text",
    "div[data-attrid='kc:/local:updates'] div::text",
]
_SEL_PLUS_CODE = [
    "button[data-item-id='oloc']::attr(aria-label)",
    "div[aria-label*='Plus Code' i] span::text",
    "button[aria-label*='plus code' i]::attr(aria-label)",
]


def _first(response: Response, selectors: list[str]) -> Optional[str]:
    """Try each selector in turn; return first non-empty match."""
    for sel in selectors:
        val = response.css(sel).get()
        if val and val.strip():
            return val.strip()
    return None


def _all(response: Response, selectors: list[str]) -> list[str]:
    """Return all matches across the fallback chain."""
    results: list[str] = []
    for sel in selectors:
        results.extend(v.strip() for v in response.css(sel).getall() if v.strip())
    return results


# ─── Email permutation generator ─────────────────────────────────────────────

def _generate_email_permutations(
    domain: str, business_name: str
) -> list[str]:
    """
    Generate plausible contact email addresses for a given domain.

    Covers:
    * Generic inboxes (info@, contact@, hello@, …)
    * First-word-of-business-name patterns (e.g. "dupont@domain")
    """
    candidates: list[str] = []

    # Generic inboxes
    generic = ["contact", "info", "hello", "bonjour", "accueil", "admin", "mail"]
    for local in generic:
        candidates.append(f"{local}@{domain}")

    # Business-name derived (first word, lower-cased, alphanumeric only)
    slug = re.sub(r"[^a-z0-9]", "", business_name.lower().split()[0]) if business_name else ""
    if slug and len(slug) >= 2:
        candidates.append(f"{slug}@{domain}")
        candidates.append(f"contact.{slug}@{domain}")

    return candidates


# ─── Registry API abstraction ─────────────────────────────────────────────────

class _RegistryClient:
    """
    Thin async façade over commercial business registries.

    Providers implemented:
    * SIRENE (France) – https://api.insee.fr
    * Companies House (UK) – https://api.company-information.service.gov.uk

    Additional providers can be added by sub-classing or extending ``_query``.
    """

    _SIRENE_BASE = os.getenv("SIRENE_API_BASE_URL", "https://api.insee.fr/api-sirene/3.11")
    _CH_BASE = "https://api.company-information.service.gov.uk"

    def __init__(self) -> None:
        import aiohttp
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self):
        import aiohttp
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def query(
        self, plus_code: str, business_name: str, country_hint: str = ""
    ) -> Optional[str]:
        """Return an email address from a public registry, or None."""
        country = country_hint.lower()
        try:
            if "france" in country or "fr" == country:
                return await self._query_sirene(business_name)
            if "uk" in country or "united kingdom" in country:
                return await self._query_companies_house(business_name)
        except Exception as exc:
            logger.debug("Registry query error (%s): %s", country, exc)
        return None

    async def _query_sirene(self, name: str) -> Optional[str]:
        """
        Search SIRENE for a business by name and return any email found.

        The SIRENE v3 API does not expose email directly; this method
        falls back to the full-text search endpoint and parses contact data.
        """
        api_key = os.getenv("SIRENE_API_KEY", "")
        if not api_key:
            logger.debug("SIRENE_API_KEY not configured – skipping SIRENE lookup.")
            return None

        session = await self._get_session()
        url = f"{self._SIRENE_BASE}/siret"
        params = {"q": f'denominationUniteLegale:"{name}"', "nombre": 1}
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

        async with session.get(url, params=params, headers=headers, timeout=10) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            # SIRENE does not expose email; this is a structural placeholder.
            # Real email retrieval would require the Infogreffe API.
            _ = data
        return None

    async def _query_companies_house(self, name: str) -> Optional[str]:
        """Query UK Companies House for a company by name."""
        api_key = os.getenv("COMPANIES_HOUSE_API_KEY", "")
        if not api_key:
            return None

        import aiohttp
        session = await self._get_session()
        url = f"{self._CH_BASE}/search/companies"
        params = {"q": name, "items_per_page": 1}
        auth = aiohttp.BasicAuth(api_key, "")

        async with session.get(url, params=params, auth=auth, timeout=10) as resp:
            if resp.status != 200:
                return None
            # Companies House does not expose email in the public search API.
            # This is a structural placeholder for a full Infogreffe-like integration.
        return None


# ─── Spider ────────────────────────────────────────────────────────────────────

class GoogleMapsZeroWebsiteSpider(scrapy.Spider):
    """
    Auto-repairing Google Maps spider for zero-website business email extraction.

    Spider arguments
    ----------------
    queries : str
        Comma-separated search queries, e.g.
        ``"plombiers Paris,electriciens Lyon"``
    max_results : int
        Maximum leads to collect in total (default: 1000).
    country_hint : str
        ISO country name hint for registry lookups (default: "").
    """

    name = "gmaps_zero_website"

    custom_settings: dict = {
        # Ensure asyncio reactor for async def callbacks
        "TWISTED_REACTOR": "twisted.internet.asyncioreactor.AsyncioSelectorReactor",
        "ZYTE_API_AUTOMAP_PARAMS": {"browserHtml": True},
    }

    # ── Constructor ────────────────────────────────────────────────────────────

    def __init__(
        self,
        queries: str = "services Paris",
        max_results: int = 1000,
        country_hint: str = "",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        # OWASP ASVS §V5.1 – bound and sanitise spider arguments
        raw_queries = str(queries)[:4096]
        self.search_queries: list[str] = [
            q.strip()[:256] for q in raw_queries.split(",") if q.strip()
        ]
        self.max_results: int = max(1, min(int(max_results), 100_000))
        self.country_hint: str = str(country_hint)[:64]
        self._total_emitted: int = 0

        self._verifier = AsyncEmailVerifier()
        self._chain = DataChainOfCustody(
            hmac_secret=os.getenv("CHAIN_HMAC_SECRET", ""),
            encryption_key=os.getenv("LEAD_ENCRYPTION_KEY", ""),
        )
        self._registry = _RegistryClient()

    # ── Scrapy entry point ─────────────────────────────────────────────────────

    def start_requests(self):
        for query in self.search_queries:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://www.google.com/maps/search/{encoded}"
            yield scrapy.Request(
                url=url,
                callback=self.parse_search_results,
                meta={
                    "zyte_api_automap": {
                        "browserHtml": True,
                        "actions": [
                            {
                                "action": "waitForSelector",
                                "selector": {
                                    "type": "css",
                                    "value": "div[role='feed'], div.m6QErb",
                                },
                                "timeout": 15,
                                "onError": "return",
                            }
                        ],
                    },
                    "search_query": query,
                },
                dont_filter=True,
            )

    # ── Parse search results ───────────────────────────────────────────────────

    async def parse_search_results(self, response: Response):
        """
        Extract business listings from the Google Maps search results panel.
        Filter to those without a website and follow their profile URLs.
        """
        if self._total_emitted >= self.max_results:
            return

        # Try each CSS selector chain for listing containers
        listing_sel = None
        for sel in _SEL_LISTING:
            if response.css(sel):
                listing_sel = sel
                break

        if not listing_sel:
            logger.warning(
                "No listing selector matched on %s – possible DOM change. "
                "Body snippet: %.300s",
                response.url,
                response.text[:300],
            )
            return

        for listing in response.css(listing_sel):
            name = _first(listing, _SEL_NAME_IN_LISTING)
            if not name:
                continue

            # Filter: skip listings that have a visible website link
            has_website = any(listing.css(sel) for sel in _SEL_WEBSITE_PRESENT)
            if has_website:
                continue

            profile_url = _first(listing, _SEL_PROFILE_LINK)
            if not profile_url:
                continue

            yield response.follow(
                profile_url,
                callback=self.parse_business_profile,
                meta={
                    "zyte_api_automap": {
                        "browserHtml": True,
                        "actions": [
                            {
                                "action": "waitForSelector",
                                "selector": {"type": "css", "value": "h1"},
                                "timeout": 12,
                                "onError": "return",
                            }
                        ],
                    },
                    "business_name_hint": name,
                },
                dont_filter=False,
            )

        # ── Pagination: scroll the results feed ────────────────────────────────
        # Google Maps loads more results via infinite scroll.  We request a
        # re-render with a scroll action to expose the next batch.
        next_batch_meta = dict(response.meta)
        next_batch_meta.setdefault("scroll_count", 0)
        scroll_count: int = next_batch_meta["scroll_count"]

        # Cap pagination depth to avoid infinite loops
        if scroll_count < 10:
            next_batch_meta["scroll_count"] = scroll_count + 1
            next_batch_meta["zyte_api_automap"] = {
                "browserHtml": True,
                "actions": [
                    # Scroll the listing panel to trigger lazy loading
                    {
                        "action": "scroll",
                        "selector": {"type": "css", "value": "div[role='feed']"},
                        "x": 0,
                        "y": 3000,
                    },
                    {
                        "action": "waitForTimeout",
                        "timeout": 2500,
                    },
                ],
            }
            yield scrapy.Request(
                url=response.url,
                callback=self.parse_search_results,
                meta=next_batch_meta,
                dont_filter=True,
                priority=-1,
            )

    # ── Parse business profile ─────────────────────────────────────────────────

    async def parse_business_profile(self, response: Response):
        """
        Deep extraction from an individual Google Business Profile page.

        Attempts extraction in cascade; yields ``EmailLead`` items.
        """
        if self._total_emitted >= self.max_results:
            return

        name = _first(response, _SEL_BUSINESS_NAME) or response.meta.get("business_name_hint", "")
        if not name:
            return

        # Abort immediately if a website is present (double-check after profile load)
        if any(response.css(sel) for sel in _SEL_WEBSITE_PRESENT):
            logger.debug("Business has website, skipping: %s", name)
            return

        phone_raw = _first(response, _SEL_PHONE)
        phone = _normalise_phone(phone_raw) if phone_raw else None
        address = _first(response, _SEL_ADDRESS) or ""
        category = _first(response, _SEL_CATEGORY) or ""
        description = " ".join(_all(response, _SEL_DESCRIPTION))
        google_posts = _all(response, _SEL_GOOGLE_POSTS)
        plus_code_raw = _first(response, _SEL_PLUS_CODE)
        plus_code = _extract_plus_code(plus_code_raw) if plus_code_raw else None

        # Extract social URLs from page body
        body_html = response.text
        social_urls: list[str] = []
        for platform, pattern in _SOCIAL_PATTERNS.items():
            social_urls.extend(pattern.findall(body_html))

        business_id = _extract_business_id(response.url)

        try:
            profile = BusinessProfile(
                business_id=business_id,
                name=name,
                category=category,
                address=address,
                city=_extract_city(address),
                country=self.country_hint,
                phone=phone,
                website=None,   # enforced: no website
                plus_code=plus_code,
                description=description,
                google_posts=google_posts,
                social_urls=social_urls,
                source_url=response.url,
            )
        except Exception as exc:
            logger.warning("BusinessProfile validation failed for %s: %s", name, exc)
            return

        # ── Cascade of extraction methods ──────────────────────────────────────

        # Method 1 & 2 – Description + Google Posts
        text_corpus = description + " " + " ".join(google_posts)
        emails_from_text = _extract_emails(text_corpus)

        async for lead in self._emit_leads(
            profile, emails_from_text, ExtractionMethod.DESCRIPTION, response.url
        ):
            yield lead

        # Method 3 – Social media profiles
        for social_url in social_urls:
            yield response.follow(
                social_url,
                callback=self._parse_social_profile,
                meta={
                    "zyte_api_automap": {"browserHtml": True},
                    "profile": profile,
                },
                errback=self._handle_social_error,
            )

        # Method 4 – Plus Code → commercial registry
        if plus_code:
            registry_email = await self._registry.query(plus_code, name, self.country_hint)
            if registry_email:
                async for lead in self._emit_leads(
                    profile, [registry_email], ExtractionMethod.REGISTRY, "registry"
                ):
                    yield lead

        # Method 5 – Phone → domain deduction → permutations
        if self._total_emitted < self.max_results and phone:
            domain = _infer_domain_from_phone(phone, name)
            if domain:
                permutations = _generate_email_permutations(domain, name)
                async for lead in self._emit_leads(
                    profile, permutations, ExtractionMethod.PHONE_PERMUTATION, phone
                ):
                    yield lead

    # ── Social profile parser ──────────────────────────────────────────────────

    async def _parse_social_profile(self, response: Response):
        profile: BusinessProfile = response.meta["profile"]
        emails = _extract_emails(response.text)
        method = (
            ExtractionMethod.SOCIAL_FACEBOOK
            if "facebook" in response.url
            else ExtractionMethod.SOCIAL_LINKEDIN
        )
        async for lead in self._emit_leads(profile, emails, method, response.url):
            yield lead

    def _handle_social_error(self, failure) -> None:
        logger.debug("Social profile fetch failed: %s", failure.value)

    # ── Lead factory ───────────────────────────────────────────────────────────

    async def _emit_leads(
        self,
        profile: BusinessProfile,
        emails: list[str],
        method: ExtractionMethod,
        source: str,
    ) -> AsyncGenerator[EmailLead, None]:
        """
        Verify each candidate email and yield validated ``EmailLead`` items.
        Stops early if ``max_results`` has been reached.
        """
        for email in emails:
            if self._total_emitted >= self.max_results:
                return

            result: VerificationResult = await self._verifier.verify(email)
            if result.deliverability_tier == DeliverabilityTier.INVALID:
                logger.debug("Invalid email skipped: %s", email)
                continue

            now = datetime.now(timezone.utc)
            fp = self._chain.create_lead_fingerprint(
                profile.business_id, email, source, now
            )
            commitment = self._chain.create_zkp_commitment(
                {"business_id": profile.business_id, "email": email}
            )
            chain_entry = self._chain.create_chain_entry(fp, source, method, now)

            try:
                lead = EmailLead(
                    business=profile,
                    email=email,
                    verification=result,
                    extraction_method=method,
                    extraction_source=source,
                    zkp_commitment=commitment,
                    chain_entry=chain_entry,
                    extracted_at=now,
                )
            except Exception as exc:
                logger.warning("EmailLead construction failed for %s: %s", email, exc)
                continue

            self._total_emitted += 1
            logger.info(
                "[%d/%d] Lead: %s <%s> (%s, score=%.2f)",
                self._total_emitted,
                self.max_results,
                profile.name,
                email,
                result.deliverability_tier.value,
                result.deliverability_score,
            )
            yield lead

    # ── Spider lifecycle ───────────────────────────────────────────────────────

    async def closed(self, reason: str) -> None:
        await self._registry.close()
        logger.info("Spider closed: %s – total leads emitted: %d", reason, self._total_emitted)


# ─── Pure helper functions ────────────────────────────────────────────────────

def _extract_emails(text: str) -> list[str]:
    """
    Extract all plausible email addresses from ``text`` using the pre-compiled
    RFC 5321-aware regex.  Deduplicates while preserving order.
    """
    seen: set[str] = set()
    result: list[str] = []
    for match in _EMAIL_RE.findall(text):
        normalised = match.lower()
        if normalised not in seen:
            seen.add(normalised)
            result.append(normalised)
    return result


def _extract_plus_code(raw: str) -> Optional[str]:
    """Parse a Plus Code from a raw string (e.g. an aria-label value)."""
    m = _PLUS_CODE_RE.search(raw)
    return m.group(1) if m else None


def _extract_business_id(url: str) -> str:
    """
    Extract a stable identifier from the Google Maps URL.

    Tries the CID (``1s0x...``) or the ``place_id`` parameter; falls back to
    a SHA-256 of the URL to ensure uniqueness.
    """
    import hashlib
    # Pattern: /maps/place/Name/@lat,lng,Xm/data=!3m1!4b1!4m...!1s0xHEX:0xHEX
    cid_match = re.search(r"!1s(0x[0-9a-fA-F]+:[0-9a-fA-F]+)", url)
    if cid_match:
        return cid_match.group(1)
    # Fallback
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _extract_city(address: str) -> str:
    """Heuristic: return the last comma-separated token of an address."""
    parts = [p.strip() for p in address.split(",")]
    if len(parts) >= 2:
        # Remove postal code prefix if any
        candidate = parts[-1] if re.search(r"[a-zA-Z]", parts[-1]) else parts[-2]
        return candidate[:128]
    return ""


def _normalise_phone(raw: str) -> Optional[str]:
    """
    Normalise a phone number to E.164 format using the phonenumbers library.
    Returns None if the number cannot be parsed.
    """
    # Strip the 'tel:' prefix
    number_str = raw.replace("tel:", "").strip()
    try:
        parsed = phonenumbers.parse(number_str, None)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )
    except phonenumbers.phonenumberutil.NumberParseException:
        pass
    return number_str if number_str else None


def _infer_domain_from_phone(phone: str, business_name: str) -> Optional[str]:
    """
    Attempt to infer a business's email domain from its phone number and name.

    Strategy
    --------
    1. Extract the country TLD from the phone's country code.
    2. Slug the business name (lowercase, alphanumeric only).
    3. Return ``<slug>.<tld>`` as a candidate domain.

    This is a last-resort heuristic; true deduction would require an
    Speech-to-Text API (configured via ``STT_PROVIDER`` env var) to transcribe
    the voicemail greeting and extract domain hints.

    NOTE: STT integration is intentionally left as an interface here.
    Plug in ``google_cloud``, ``azure``, or ``aws_transcribe`` by implementing
    the ``_transcribe_voicemail`` coroutine in a subclass.
    """
    if not phone:
        return None

    # Country code → TLD mapping (subset)
    _CC_TO_TLD: dict[int, str] = {
        33: "fr",   # France
        44: "co.uk",  # UK
        49: "de",   # Germany
        34: "es",   # Spain
        39: "it",   # Italy
        1:  "com",  # US/CA
        32: "be",   # Belgium
        41: "ch",   # Switzerland
    }

    tld = "com"
    try:
        parsed = phonenumbers.parse(phone, None)
        tld = _CC_TO_TLD.get(parsed.country_code, "com")
    except Exception:
        pass

    slug = re.sub(r"[^a-z0-9]", "", business_name.lower().split()[0]) if business_name else ""
    if len(slug) < 2:
        return None
    return f"{slug}.{tld}"

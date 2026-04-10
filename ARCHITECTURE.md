# Architecture & Operations Manual
## `zyte_gmaps_scraper` – Auto-Repairing Email Extraction Agent

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Scrapy Process                              │
│                                                                      │
│  start_requests()                                                    │
│       │                                                              │
│       ▼                                                              │
│  ┌──────────────┐    Zyte API      ┌─────────────────────────────┐  │
│  │  Scheduler   │ ─────────────►  │  Residential Browser Proxy  │  │
│  │  (asyncio)   │ ◄─────────────  │  (TLS fingerprint rotation) │  │
│  └──────┬───────┘   browserHtml   └─────────────────────────────┘  │
│         │                                                            │
│         ▼                                                            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │            Spider Callback (async def)                        │   │
│  │  parse_search_results → filter zero-website → follow URLs    │   │
│  │  parse_business_profile → cascade extraction                 │   │
│  │    1. description / Google Posts text                        │   │
│  │    2. social profiles (Facebook / LinkedIn)                  │   │
│  │    3. Plus Code → registry API                               │   │
│  │    4. phone → domain → email permutations                    │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                             │ EmailLead items                        │
│                             ▼                                        │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ Item Pipeline                                                  │  │
│  │  100  InputValidationPipeline   (Pydantic v2)                 │  │
│  │  200  DeduplicationPipeline     (SHA-256 fingerprint set)     │  │
│  │  300  EmailVerificationPipeline (syntax→MX→SMTP ping)         │  │
│  │  400  CryptographicSigningPipeline (BLAKE2b + AES-256-GCM)   │  │
│  │  500  JsonLinesExportPipeline   (orjson → output/*.jsonl)     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Concurrency Model & Network Congestion Management

### 2.1 Twisted asyncio Reactor

Scrapy runs on **Twisted** with the `asyncioreactor` bridge, enabling native
`async def` / `await` inside spider callbacks and pipelines.  This gives a
**single-threaded cooperative multitasking** model: thousands of in-flight I/O
operations share one OS thread, eliminating GIL contention for I/O-bound work.

```
CONCURRENT_REQUESTS        = 128   # total in-flight Scrapy requests
CONCURRENT_REQUESTS_PER_DOMAIN = 32
AUTOTHROTTLE_TARGET_CONCURRENCY = 64  # adaptive target
```

### 2.2 AutoThrottle – Back-Pressure from Latency Signals

Scrapy's AutoThrottle measures the **download latency** of each response and
continuously adjusts the inter-request delay to keep the measured concurrency
near `AUTOTHROTTLE_TARGET_CONCURRENCY`.  This is equivalent to a AIMD
(Additive Increase / Multiplicative Decrease) congestion control loop:

```
if latency_rising:
    delay *= 2           # multiplicative decrease (back off)
else:
    delay -= small_step  # additive increase (fill pipe)
```

### 2.3 Domain-Level Token Bucket (`DomainRateLimitMiddleware`)

A secondary, **deterministic** rate limiter prevents any single target domain
from being overwhelmed even under AutoThrottle instability.  Each domain has a
configurable token bucket:

```yaml
DOMAIN_RATE_LIMIT:
  google.com:      { rate: 8, burst: 16 }
  facebook.com:    { rate: 4, burst: 8 }
  linkedin.com:    { rate: 2, burst: 4 }
```

Requests that arrive when the bucket is empty are silently dropped
(`IgnoreRequest`), preventing memory accumulation in the download queue.

### 2.4 Retry Strategy – Exponential Back-off with Full Jitter

```python
delay = min(cap, base * 2 ** attempt) * random.uniform(0, 1)
```

AWS "Full Jitter" prevents **thundering herd** after a target recovers from
an outage.  Configured via Scrapy's `RETRY_TIMES = 5` and the `tenacity`
library inside `AsyncEmailVerifier`.

### 2.5 Horizontal Scaling

A single Scrapy process is event-loop bound, not CPU-bound.  Horizontal scaling
is achieved by:

| Strategy | Description |
|---|---|
| **Multiple processes** | Run N `scrapy crawl` instances with disjoint query sets. |
| **Scrapyd** | Multi-process manager with HTTP job API. |
| **Kubernetes** | One pod per query shard; shared output via S3/GCS/NFS. |
| **Scrapy Cloud** | Managed Zyte platform; add spiders directly. |

The deduplication pipeline must be backed by a shared store (Redis, DynamoDB)
when running multi-process; replace `DeduplicationPipeline._seen` with a
`redis.asyncio` SSET.

---

## 3. Data Flow & Schema

```
Google Maps SERP
      │ browserHtml (Zyte API)
      ▼
BusinessProfile (Pydantic)
      │
      ├─► emails from text corpus ──────────────────────────┐
      ├─► emails from social profiles ──────────────────────┤
      ├─► emails from registry API ─────────────────────────┤
      └─► emails from phone permutations ──────────────────►┤
                                                             │
                                                             ▼
                                                    EmailLead (Pydantic)
                                                       │
                                              ┌────────┴──────────┐
                                              │  ZKPCommitment    │
                                              │  ChainEntry       │
                                              │  VerificationResult│
                                              └───────────────────┘
                                                       │
                                               output/leads_*.jsonl
```

---

## 4. Security Architecture

### 4.1 The 25 Verification Standards Shield

| # | Standard / Technology | Implementation |
|---|---|---|
| 1 | **OWASP ASVS 5.0 §V5** – Input Validation | `BusinessProfile` & `EmailLead` Pydantic validators; control-char rejection |
| 2 | **OWASP ASVS 5.0 §V5.2** – Sanitisation | Pre-compiled bounded regex; no `eval`/`exec` |
| 3 | **OWASP ASVS 5.0 §V7** – Cryptography | BLAKE2b-512, SHA3-256, AES-256-GCM (FIPS 140-3) |
| 4 | **OWASP ASVS 5.0 §V8** – Data Protection | PII encrypted at rest; commitments are public |
| 5 | **OWASP ASVS 5.0 §V2.10** – Credential hygiene | All secrets from env vars; `sys.exit` at startup if absent |
| 6 | **NIST SP 800-57** – Key management | 256-bit keys, CSPRNG nonces (`secrets.token_bytes`) |
| 7 | **NIST SP 800-188** – Data Provenance | `ChainEntry` tamper-evident ledger with chained BLAKE2b |
| 8 | **ISO 27001 §A.12.4** – Audit logging | Structured `structlog` with ISO 8601 timestamps |
| 9 | **GDPR Article 25** – Privacy by design | ZKP commitments; right-to-be-forgotten via key deletion |
| 10 | **GDPR Article 17** – Right to erasure | AES key deletion renders ciphertexts irreversible |
| 11 | **RFC 5321/5322** – Email syntax | `email-validator` with Unicode IDNA 2008 |
| 12 | **DNS / MX verification** | `dnspython` async resolver |
| 13 | **SMTP deliverability probe** | Silent RCPT TO ping via `aiosmtplib` |
| 14 | **Unicode IDNA 2008** – Internationalised addresses | `email-validator` `check_deliverability=True` path |
| 15 | **TLS fingerprint mitigation** | Zyte API managed browser proxies |
| 16 | **Behavioural analysis resistance** | `BehavioralMimicryMiddleware` – viewport + Accept-Language rotation |
| 17 | **DOM mutation adaptation** | `AdaptiveDOMMiddleware` + multi-selector fallback chains |
| 18 | **Anti-bot challenge bypass** | Escalation to full browser JS execution on challenge detection |
| 19 | **Type Safety** – Pydantic v2 | `model_validator`, `field_validator`, strict length bounds |
| 20 | **SCA – Supply chain security** | All deps pinned; `pip-audit` as CI gate |
| 21 | **HMAC data integrity** | `ChainEntry.hmac_signature` (HMAC-SHA3-256) |
| 22 | **ZKP-compatible commitments** | Pedersen-style `BLAKE2b(data ‖ nonce)` |
| 23 | **Exponential back-off + jitter** | `tenacity` + Scrapy AutoThrottle AIMD |
| 24 | **Dead-letter queue** | `DeadLetterMiddleware` → `dead_letter.jsonl` |
| 25 | **Scrapy DoS (unpatched) – layered mitigation** | See detail below |

**Standard #25 – full mitigation stack (no patch available for Scrapy >= 0.7, <= 2.14.1):**

* `ZyteApiEnforcementMiddleware` (priority 10) – architectural isolation: Scrapy's downloader never opens a direct TCP connection to an untrusted host; any request missing `zyte_api`/`zyte_api_automap` meta is rejected before the downloader sees it.
* `ResponseGuardMiddleware` (priority 595) – pre-decompression guard; runs immediately before `HttpCompressionMiddleware` (590) in `process_response` (descending order), so all five checks execute while the body is still compressed: (1) `Content-Length` header, (2) actual compressed body bytes, (3) stacked/unknown `Content-Encoding`, (4) header count cap, (5) header value length cap.
* `DOWNLOAD_MAXSIZE = 10 MB` – Scrapy-native body size hard cap.
* `DOWNLOAD_FAIL_ON_DATALOSS = True` – aborts mid-stream closures.
* `REDIRECT_MAX_TIMES = 5` – caps redirect chains (default is 20).
* `DOWNLOAD_TIMEOUT = 30 s` – limits slow-response exposure window.

### 4.2 Cryptographic Chain of Custody

Every lead generates a chained ledger entry:

```
genesis_hash = "000...0"   (512 zero bits)

entry[0].chain_hash = BLAKE2b-512( genesis_hash   ‖ fingerprint[0] )
entry[1].chain_hash = BLAKE2b-512( entry[0].chain_hash ‖ fingerprint[1] )
entry[N].chain_hash = BLAKE2b-512( entry[N-1].chain_hash ‖ fingerprint[N] )
```

Retroactive modification of any entry invalidates all subsequent hashes,
providing tamper-evidence equivalent to a blockchain without the overhead.

### 4.3 ZKP Commitment & GDPR Compliance

```
nonce            = CSPRNG(32 bytes)
commitment       = BLAKE2b-512( orjson.dumps(data) ‖ nonce )
data_ciphertext  = AES-256-GCM( orjson.dumps(data) )   # key = LEAD_ENCRYPTION_KEY
data_hash_sha3   = SHA3-256( orjson.dumps(data) )
```

**Stored publicly:** `commitment`, `data_hash_sha3`  
**Stored encrypted:** `data_ciphertext`  
**Never persisted in plaintext:** email address, business name

Right-to-be-forgotten: delete the `LEAD_ENCRYPTION_KEY`.  All ciphertexts
become computationally irreversible.  Commitments (hashes) remain on the audit
ledger without revealing PII.

---

## 5. Deployment

### 5.1 Dependencies & SCA Gate

```bash
# Install with hash verification (recommended)
pip install --require-hashes -r requirements.txt

# Audit for known CVEs (CI gate – fail on any finding)
pip-audit --requirement requirements.txt --strict
```

### 5.2 Environment Variables

Copy `.env.example` to `.env` and fill in all values:

```bash
cp .env.example .env
$EDITOR .env
```

Required at runtime:
- `ZYTE_API_KEY` – your Zyte API key
- `LEAD_ENCRYPTION_KEY` – 32-byte hex key for AES-256-GCM
- `CHAIN_HMAC_SECRET` – 32-byte hex key for HMAC-SHA3-256

Generate secure keys:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5.3 Running the Spider

```bash
# Single query, 100 results
scrapy crawl gmaps_zero_website \
  -a queries="plombiers Paris" \
  -a max_results=100 \
  -a country_hint="France"

# Multiple queries, large scale
scrapy crawl gmaps_zero_website \
  -a queries="electriciens Lyon,chauffagistes Bordeaux,serruriers Marseille" \
  -a max_results=5000 \
  -a country_hint="France" \
  -s CONCURRENT_REQUESTS=256
```

### 5.4 Horizontal Scaling with Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY . .
CMD ["scrapy", "crawl", "gmaps_zero_website", \
     "-a", "queries=${QUERIES}", \
     "-a", "max_results=${MAX_RESULTS}"]
```

```bash
# Scale to 8 parallel shards
for i in {1..8}; do
  docker run -d --env-file .env \
    -e QUERIES="services Paris shard${i}" \
    -e MAX_RESULTS=10000 \
    zyte-scraper
done
```

### 5.5 Output

Results are written to `./output/leads_<spider>_<timestamp>.jsonl`.
Each line is a JSON object matching the `EmailLead` schema.

---

## 6. Extending the Spider

### Adding a new registry provider

Implement `_query_<country>` in `_RegistryClient` and call it from `query()`:

```python
async def _query_belgium(self, name: str) -> Optional[str]:
    # CBE (Crossroads Bank for Enterprises) API
    ...
```

### Adding a Speech-to-Text fallback

Override `_infer_domain_from_phone` or implement `_transcribe_voicemail` in
a subclass of `GoogleMapsZeroWebsiteSpider`:

```python
async def _transcribe_voicemail(self, phone: str) -> Optional[str]:
    # Call Google Cloud Speech-to-Text, Azure Cognitive Services, etc.
    ...
```

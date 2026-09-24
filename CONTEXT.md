# 📖 CONTEXT.md — Attack Surface Intelligence Engine Context & Architecture

> **Framework:** Recon Framework v3.2.0  
> **Repository:** sozanga3/ReconFramework (`recon_framework-3.2.0`)  
> **Status:** Production-Ready Attack Surface Reconnaissance & Vulnerability Pipeline  
> **Primary Purpose:** Autonomous, high-precision asset discovery, security profiling, and intelligence extraction for penetration testers and red teams.

---

## 🧭 1. System Overview & Philosophy

Recon Framework is engineered around four core tenets:
1. **Intelligence Over Volume:** Rather than blindly collecting millions of junk URLs, the framework applies multi-layer filtering (extension blacklists, vendor JS elimination, entropy analysis) to isolate high-value attack surfaces.
2. **Recursive Feedback Loops:** Reconnaissance is not linear. Discovered JavaScript files and API routes often expose new internal domains. These newly discovered subdomains are dynamically fed back into DNS resolution and HTTP probing.
3. **Resilience & Graceful Degradation:** The framework operates with whatever tools are installed. While core tools (`httpx`, `subfinder`) are mandatory, missing optional tools (e.g., `amass`, `alterx`, `x8`, `gowitness`) trigger warnings rather than pipeline failure.
4. **Stateful Execution & Differential Monitoring:** Scans can be interrupted and resumed without repeating expensive operations (`--resume`), and subsequent runs highlight new or decommissioned assets (`--monitor`).

---

## 🏗️ 2. Architectural Blueprint & Codebase Map

```
recon_framework-3.2.0/
├── main.py                     # Primary pipeline coordinator & CLI entrypoint
├── parameters.txt              # Shared/default fuzzing and parameter dictionary
├── README.md                   # Operational quickstart and manual
├── AGENTS.md                   # AI agent coding guidelines & accuracy rules
├── CONTEXT.md                  # Comprehensive architectural knowledge base
│
├── config/                     # Configuration, settings, and tool paths
│   ├── __init__.py
│   ├── api_keys.py             # Active API tokens (Telegram, GitHub, Chaos)
│   ├── api_keys.py.example     # Template for credentials
│   ├── keywords.py             # Regex dictionaries for sensitive routes & params
│   ├── settings.py             # Concurrency, timeouts, rate limits, noise filters
│   ├── tools.py                # Binary resolution & availability checking
│   ├── wordlists.py            # Wordlist references and fallback resolvers
│   └── wordlists/              # Local dictionaries for DNS, resolvers, API routes
│
├── core/                       # Core engine services (tool-agnostic)
│   ├── filter.py               # Domain scope filtering across multi-domain inputs
│   ├── logger.py               # Centralized logging interface
│   ├── notifications.py        # Real-time Telegram alerting service
│   ├── output.py               # Output folder scaffolding, data sanitization, reports
│   ├── runner.py               # Subprocess management, timeouts, error logging
│   ├── scoring.py              # Multi-variable target scoring & prioritization algorithm
│   ├── state.py                # Checkpointing, run_or_resume, cache loaders
│   └── utils.py                # Dynamic latency calculation, domain cleanup, tool check
│
├── modules/                    # Reconnaissance stages & tool wrappers
│   ├── cloud_recon.py          # S3, GCP, Azure, DO storage asset discovery
│   ├── crawler.py              # Katana, Hakrawler, Gau, Waybackurls, Waymore
│   ├── github_recon.py         # Repository, endpoint, and secret discovery on GitHub
│   ├── httpx.py                # HTTP probing, technology detection, title extraction
│   ├── js_enum.py              # Jsluice, JSleak, Sourcemapper, xnLinkFinder
│   ├── js_filter.py            # Third-party JS de-noising & secret extraction
│   ├── nuclei_scan.py          # Vulnerability scanning on prioritized endpoints
│   ├── param_discovery.py      # Arjun, x8, ParamSpider, Kiterunner, qsreplace
│   ├── port_scan.py            # Open port discovery via Naabu
│   ├── screenshots.py          # Gowitness visual capture
│   ├── subdomains.py           # Multi-engine passive/active subdomain enumeration
│   └── waf_detector.py         # Wafw00f profiling and nomore403 bypass logic
│
└── output/                     # Generated scan results (organized by domain)
    └── <target_domain>/        # Target workspace
```

---

## 🔄 3. The 12-Stage Reconnaissance Pipeline

```
Target Domain(s)
       │
       ▼
[Stage 1: Subdomain Discovery] ──► (Passive + Active + Permutations)
       │
       ├───────────────────────────────┬───────────────────────────────┐
       ▼                               ▼                               ▼
[Stage 2: Takeover Check]     [Stage 3: Cloud Recon]         [Stage 4: Port Scan]
    (Subzy)                       (AWS, GCP, Azure, DO)          (Naabu top-1000)
       │                               │                               │
       └───────────────────────────────┼───────────────────────────────┘
                                       ▼
                       [Stage 5: WAF & Safety Profiling]
                           (Wafw00f + Dynamic Rate Limits)
                                       │
                                       ▼
                       [Stage 6: HTTP Probing & Scoring]
                           (httpx + Multi-Variable Scoring)
                                       │
                                       ▼
                       [Stage 7: Active & Passive Spidering]
                           (Katana, Hakrawler, Gau, Waymore)
                                       │
                                       ▼
                       [Stage 8: JavaScript Intelligence] ────────┐ (Recursive Loop:
                           (jsluice, jsleak, sourcemapper)        │  new subdomains feed
                                       │                          │  back to Stage 6)
                                       ├──────────────────────────┘
                                       ▼
                       [Stage 9: Parameter & API Discovery]
                           (Kiterunner, Arjun, x8, qsreplace)
                                       │
       ┌───────────────────────────────┴───────────────────────────────┐
       ▼                                                               ▼
[Stage 10: Nuclei Scanning]                                   [Stage 11: Visual Recon]
   (Prioritized endpoints & params)                               (Gowitness screenshots)
       │                                                               │
       └───────────────────────────────┬───────────────────────────────┘
                                       ▼
                       [Stage 12: Reporting & Diff Monitoring]
                           (stats.json, summary.txt, Telegram alerts)
```

### Detailed Breakdown of Each Stage:

#### Stage 1: Subdomain Discovery
- **Modules Involved:** [modules/subdomains.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/subdomains.py)
- **Engines:**
  - *Passive:* `subfinder`, `assetfinder`, `findomain`, `chaos`, `amass`, `crt.sh`, `subscraper`, `knockpy`, `tlsx` (SAN cert scraping).
  - *Active / Resolvers:* `puredns`, `massdns`, `shuffledns`, `dnsx` (brute-forcing with wordlists).
  - *Permutations:* `alterx` (smart mutations on verified alive subdomains).
- **Data Hygiene:** Normalizes subdomains to lowercase, strips wildcards/protocols, verifies strictly against `is_valid_subdomain()`.
- **Primary Output:** `output/<domain>/subdomains/all.txt`.

#### Stage 2: Subdomain Takeover Verification
- **Modules Involved:** [modules/subdomains.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/subdomains.py) & [main.py](file:///home/akram/Documents/recon_framework-3.2.0/main.py)
- **Tool:** `subzy run --targets <subdomains/all.txt> --hide_fails`
- **Output:** `output/<domain>/subdomains/takeovers.txt`.

#### Stage 3: Cloud Asset Discovery
- **Modules Involved:** [modules/cloud_recon.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/cloud_recon.py)
- **Targets:** Amazon AWS S3, Google Cloud Storage (GCP), Microsoft Azure Blob Storage, DigitalOcean Spaces.
- **Output:** `output/<domain>/cloud/cloud_assets.txt`.

#### Stage 4: Port Scanning
- **Modules Involved:** [modules/port_scan.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/port_scan.py)
- **Tool:** `naabu` scanning top 1000 ports (`--top-1000`).
- **Resilience:** Automatically detects whether raw socket privileges exist; falls back to unprivileged scanning (`-unprivileged`) if run without root/sudo.
- **Output:** `output/<domain>/ports/naabu_results.txt`.

#### Stage 5: WAF & Safety Profiling
- **Modules Involved:** [modules/waf_detector.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/waf_detector.py)
- **Tool:** `wafw00f`
- **Logic:** Evaluates apex and top targets. Calculates `waf_ratio`:
  - `waf_ratio > 0.5` -> **SAFE mode** (concurrency: 10, rate-limit: 20 req/s).
  - `0 < waf_ratio <= 0.5` -> **BALANCED mode** (concurrency: 15, rate-limit: 50 req/s).
  - `waf_ratio == 0` -> **AGGRESSIVE mode** (default settings applied).
- **Output:** `output/<domain>/safety_profile.json` and `safety_report.txt`.

#### Stage 6: HTTP Probing & Multi-Variable Target Scoring
- **Modules Involved:** [modules/httpx.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/httpx.py), [core/scoring.py](file:///home/akram/Documents/recon_framework-3.2.0/core/scoring.py)
- **Tool:** `httpx` with flags `-title -tech-detect -status-code -content-length -asn -cdn -favicon`
- **Scoring Algorithm:**
  - *Status Code:* 200 (+3), 301/302 (+1), 403 (+2 for bypass fuzzing), 500 (+2 for debug/leaks).
  - *Keywords:* High-value keywords in title/URL (e.g., `admin`, `api`, `internal`, `v1`, `v2`, `staging`, `dev`, `grafana`, `swagger`, `auth`, `login`, `vpn`) add +3 to +10 points.
  - *Technology Stack:* Outdated PHP (+3), ASP.NET/IIS (+1), WordPress/Drupal (+2), old Apache (+2).
  - *Cloud / ASN:* Non-CDN assets scored higher than Cloudflare-shielded endpoints.
- **Outputs:**
  - `output/<domain>/httpx/alive.txt` (list of alive URLs)
  - `output/<domain>/httpx/results.json` (raw httpx JSON data)
  - `output/<domain>/httpx/ranked.json` (ranked targets sorted by asset score descending)

#### Stage 7: Active & Passive Spidering
- **Modules Involved:** [modules/crawler.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/crawler.py)
- **Active Crawlers:** `katana` and `hakrawler` on prioritized top targets.
- **Passive Sources:** `gau`, `waybackurls`, `gospider`, `waymore`, `urlfinder`.
- **Outputs:**
  - `output/<domain>/endpoints/raw_crawls/katana_raw.txt`
  - `output/<domain>/endpoints/hakrawler_raw.txt`
  - `output/<domain>/endpoints/passive_urls.txt`

#### Stage 8: JavaScript Intelligence & Recursive Feedback Loop
- **Modules Involved:** [modules/js_enum.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/js_enum.py), [modules/js_filter.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/js_filter.py)
- **Tools:** `jsluice`, `jsleak`, `sourcemapper`, `SubDomainizer`, `SecretFinder`, `xnLinkFinder`.
- **Filtering:** Eliminates third-party vendor noise via `BAD_JS_PATTERNS`.
- **Recursive Feedback Loop:** Any new subdomains discovered in client-side JS bundles are extracted, cleaned, appended to `subdomains/all.txt`, probed with `httpx`, and re-scored. If `--deep-crawl` is enabled, newly discovered live hosts are recursively crawled.
- **Outputs:**
  - `output/<domain>/js/js_files_clean.txt`
  - `output/<domain>/js/endpoints_filtered.txt`
  - `output/<domain>/js/endpoints_high_risk.txt`
  - `output/<domain>/js/secrets_clean.txt`
  - `output/<domain>/js/subdomains_from_js.txt`

#### Stage 9: Parameter Discovery & API Routing
- **Modules Involved:** [modules/param_discovery.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/param_discovery.py)
- **API Routing:** `kiterunner` (`kr scan`) against top targets using built-in API routes.
- **Parameter Extraction:** Native query parsing + `unfurl` + `arjun` + `x8` + `paramspider`.
- **Noise Filter:** Removes analytics keys (`NOISE_PARAMS`) and checks Shannon entropy (`ENTROPY_THRESHOLD = 3.5`).
- **Fuzzable Generation:** Uses `qsreplace FUZZ` to generate immediately actionable URLs for scanners.
- **Outputs:**
  - `output/<domain>/params/all_params.txt`
  - `output/<domain>/params/scored_params.json`
  - `output/<domain>/params/endpoints_fuzzable.txt`
  - `output/<domain>/params/vuln_candidates/<category>.txt` (`xss.txt`, `ssrf.txt`, `sqli.txt`, `lfi.txt`, `idor.txt`)

#### Stage 10: 403 Bypass & Nuclei Vulnerability Scanning
- **Modules Involved:** [modules/waf_detector.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/waf_detector.py), [modules/nuclei_scan.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/nuclei_scan.py)
- **403 Bypass:** `nomore403` runs against 403 Forbidden endpoints to discover header or method bypasses.
- **Nuclei:** Optional (`--nuclei`). Runs targeted templates against:
  - Top ranked targets
  - High-risk endpoints from JS and parameter discovery
  - Fuzzable endpoints with query parameters
  - Identified cloud assets
- **Outputs:**
  - `output/<domain>/fuzzing/403_bypass/`
  - `output/<domain>/fuzzing/nuclei_results.txt`

#### Stage 11: Visual Reconnaissance
- **Modules Involved:** [modules/screenshots.py](file:///home/akram/Documents/recon_framework-3.2.0/modules/screenshots.py)
- **Tool:** `gowitness scan` against alive HTTP targets.
- **Output:** `output/<domain>/screenshots/*.png`.

#### Stage 12: Reporting, Continuous Monitoring & Alerts
- **Modules Involved:** [core/output.py](file:///home/akram/Documents/recon_framework-3.2.0/core/output.py), [core/notifications.py](file:///home/akram/Documents/recon_framework-3.2.0/core/notifications.py)
- **Stats Collection:** Computes complete metrics into `stats.json`.
- **Differential Monitoring:** When `--monitor` is passed, compares current metrics against previous `stats.json` and reports net asset changes (`+new`, `-removed`).
- **Alerting:** Sends real-time Telegram alerts on scan start, vulnerability discovery, and completion.
- **Outputs:**
  - `output/<domain>/stats.json`
  - `output/<domain>/summary.txt`

---

## 🗂️ 4. Canonical Output Directory Structure

Each scan creates an isolated, structured directory under `output/<domain>/`:

```
output/<domain>/
├── cloud/
│   └── cloud_assets.txt              # Discovered open/protected cloud storage buckets
├── endpoints/
│   ├── all_endpoints.txt             # Merged, deduplicated endpoints across all tools
│   ├── hakrawler_raw.txt             # Active endpoints from hakrawler
│   ├── passive_urls.txt              # Aggregated endpoints from gau, wayback, waymore
│   └── raw_crawls/
│       └── katana_raw.txt            # Katana crawling output
├── fuzzing/
│   ├── 403_bypass/                   # Output from nomore403 bypass attempts
│   └── nuclei_results.txt            # Verified vulnerabilities identified by Nuclei
├── httpx/
│   ├── alive.txt                     # Responsive URLs (e.g., https://sub.example.com)
│   ├── alive_report.txt              # Formatted status, titles, technologies, and sizes
│   ├── ranked.json                   # Targets prioritized by the scoring engine
│   └── results.json                  # Full JSON lines from httpx probe
├── js/
│   ├── endpoints_clean.txt           # Clean endpoints discovered inside JS files
│   ├── endpoints_filtered.txt        # Endpoints with noise and vendor scripts removed
│   ├── endpoints_high_risk.txt       # High-risk endpoints (admin, auth, api, upload)
│   ├── github_endpoints.txt          # Endpoints discovered via GitHub search
│   ├── github_secrets.txt            # Secrets leaked in related GitHub repositories
│   ├── js_files_clean.txt            # In-scope JavaScript URLs
│   ├── js_high_value.txt             # High-value JS bundles containing routes/logic
│   ├── secrets_clean.txt             # Extracted API keys, tokens, and credentials
│   └── subdomains_from_js.txt        # New subdomains discovered within JS bundles
├── params/
│   ├── all_params.txt                # Unified list of discovered query/body parameters
│   ├── endpoints_fuzzable.txt        # Endpoints formatted with FUZZ values for scanners
│   ├── scored_params.json            # Categorized parameters with risk scores
│   └── vuln_candidates/              # Target lists segmented by vulnerability type
│       ├── idor.txt                  # ID/user/account parameter candidates
│       ├── lfi.txt                   # Path/file/template parameter candidates
│       ├── sqli.txt                  # Query/db/filter parameter candidates
│       ├── ssrf.txt                  # URL/dest/webhook parameter candidates
│       └── xss.txt                   # Redirect/callback/input parameter candidates
├── ports/
│   └── naabu_results.txt             # Open host:port combinations from naabu
├── screenshots/
│   └── *.png                         # Headless browser page renders
├── subdomains/
│   ├── active_dns/                   # Intermediate results from dnsx and puredns
│   ├── all.txt                       # Final verified, unique subdomain list
│   ├── raw/                          # Raw unverified outputs from individual tools
│   ├── sources/                      # Tool-specific subdomain output files
│   └── takeovers.txt                 # Verified takeover candidates from Subzy
├── safety_profile.json               # WAF detection results and concurrency mode
├── safety_report.txt                 # Human-readable WAF assessment
├── state.json                        # Checkpoint state tracking completed steps
├── stats.json                        # Machine-readable scan summary & metrics
└── summary.txt                       # Executive quantitative recon summary
```

---

## 🛡️ 5. Data Hygiene, Filtering & Scope Engine

To ensure that data generated is **100% accurate, high-signal, and strictly in-scope**, the engine implements a multi-layer defense against out-of-scope domain leakage, noise, and data corruption:

### 1. The Scope Invariant & Hostname Validation ([core/utils.py](file:///home/akram/Documents/recon_framework-3.2.0/core/utils.py))
Every candidate domain or subdomain encountered across any stage MUST satisfy:
```python
candidate == target_domain or candidate.endswith("." + target_domain)
```
- **Strict Boundary Anchoring:** Loose matching (e.g. `target_domain in candidate` or `candidate.endswith(target_domain)` without a preceding dot) is strictly prohibited. Loose checks erroneously admit lookalikes (`target-corp.com`, `faketarget.com`, or `target.com.attacker.org`).
- **`is_valid_subdomain(candidate, target_domain)` Process:**
  1. Strip any protocol (`http://`, `https://`).
  2. Strip credentials (`user:pass@`).
  3. Strip path components (`/path...`) and query parameters (`?query...`).
  4. Strip port numbers (`:8080`, `:443`).
  5. Strip wildcards (`*.` or leading `*`).
  6. Convert to lowercase and trim whitespace.
  7. Verify RFC FQDN compliance: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`
  8. Assert `candidate == target_domain or candidate.endswith("." + target_domain)`.

### 2. Defenses Against the 6 Vectors of Out-of-Scope Leakage

| Leak Vector | Cause in Reconnaissance | Mitigation & Rule in Recon Framework |
| :--- | :--- | :--- |
| **1. Lookalike / Partial Matches** | Substring checks matching `badtarget.com` when target is `target.com`. | Dot-prefixed anchoring `candidate.endswith("." + target_domain)` ensures only true subdomains pass. |
| **2. Multi-Tenant SSL/TLS SANs** | Certificate logs (`tlsx`, `crt.sh`, `subscraper`) returning shared certificates covering hundreds of unrelated tenants (e.g. Cloudflare, Fastly shared certs). | Every SAN extracted from a certificate must pass `is_valid_subdomain` before ingestion. Non-matching SANs are discarded immediately. |
| **3. Third-Party CDN / Cloud CNAMEs** | DNS enumeration returning CNAME targets (e.g., `target.cdn.cloudflare.net` or `target.s3.amazonaws.com`). | CDN/Cloud provider domains are explicitly excluded from subdomain inventory unless they are CNAME pointers directly verified as alias records. Vendor domains (`*.cloudfront.net`, `*.azurewebsites.net`, etc.) are stripped. |
| **4. Client-Side JS Dependencies** | Webpack bundles and JS source maps referencing third-party APIs (`api.stripe.com`, `auth0.com`, `segment.io`). | The **Intelligence Feedback Loop** in Stage 8 passes all extracted URLs through `clean_subdomains(new_subs, domain)`. External domains are filtered out before being added to `all.txt` or fed into `httpx`. |
| **5. Wildcard DNS Catch-Alls** | Target domains configuring `*.target.com -> IP`, causing brute-force tools (`dnsx`, `alterx`) to report millions of phantom subdomains. | Active DNS stages utilize `puredns` and `dnsx` with automated wildcard filtering to detect and discard synthetic wildcard responses. |
| **6. Multi-Target Scope Bleed** | Scanning a list of targets (`-df targets.txt`) where memory sets or caches retain domains from prior runs. | Each target in `-df` is executed in a self-contained execution context with target-specific `paths` and fresh state isolation. `filter_urls_multi_domain()` enforces multi-domain scoping where explicitly required. |

### 3. Scope Ingestion & Data Preservation: `-d` vs `-df`

The framework strictly enforces scoping without discarding or corrupting legitimate discovered data:

- **Single Target Mode (`-d target.com`):**
  - Scope automatically includes the root domain and **all subdomains at any depth** (`*.target.com`, including `sub.target.com`, `deep.nested.sub.target.com`).
  - `effective_domains` is initialized to `[target.com]`.
- **Domain List Mode (`-df targets.txt`):**
  - Multiple target domains (e.g. `domainA.com`, `domainB.com`) are ingested and normalized.
  - `effective_domains = all_domains if all_domains else [domain]`.
  - Legitimate assets discovered during analysis that belong to *any* of the target domains in `all_domains` are preserved as in-scope and not discarded.
- **Data Preservation Guarantee (Zero Accidental Deletions):**
  - **Normalization Before Verification:** Raw tool output frequently contains protocols (`https://`), ports (`:443`), credentials (`user@`), and path fragments (`/`). The sanitization engine normalizes these elements *before* testing against the RFC FQDN pattern, ensuring that valid subdomains are never falsely discarded.
  - **Multi-Level Subdomain Protection:** Subdomains with multiple nested labels are 100% preserved.
  - **Isolated Storage:** When processing multiple domains via `-df`, each domain writes to its own isolated subfolder `output/<domain>/` so data from previous domains is never overwritten or deleted.

### 4. Module-Wide Scope Enforcement Matrix

| Module | Scope Filtering Logic & Implementation | Target Preservation Guarantee |
| :--- | :--- | :--- |
| **`modules/subdomains.py`** | `clean_subdomains(subs, domain)` normalizes candidate hostnames and verifies against `targets` (supports both single domain string and list). | Strips URLs/ports before FQDN check so valid subdomains with ports or protocols are kept. |
| **`modules/httpx.py`** | Probes inputs derived from verified subdomains and open ports. Formats canonical alive targets. | Only verified in-scope assets are saved to `alive.txt`. |
| **`modules/crawler.py`** | `run_katana`, `run_hakrawler`, and `run_url_collection` enforce `filter_urls_multi_domain` against `effective_domains`. | Only endpoints belonging to in-scope domains are retained. |
| **`modules/js_enum.py`** | `run_js_enum` enforces `filter_urls_multi_domain` on discovered JS URLs, endpoints, and subdomains against `effective_domains`. | Discards external CDN/vendor JS links while keeping all target JS assets. |
| **`modules/js_filter.py`** | `filter_js_files` and `filter_endpoints` validate hostnames against `effective_domains = all_domains if all_domains else [domain]`. Relative endpoints (`/...`) are preserved. | Valid endpoints on any target in `all_domains` are preserved; external third-party endpoints are pruned. |
| **`modules/param_discovery.py`** | `run_paramspider` and `run_param_discovery` validate URLs and endpoints using `filter_urls_multi_domain(..., effective_domains)`. | Discards out-of-scope crawler noise; scores only in-scope parameters. |
| **`main.py` (Feedback Loop)** | New subdomains discovered in JS are validated via `clean_subdomains` and `is_valid_subdomain` before appending to `all.txt` and triggering HTTP probing. | Prevents third-party API hosts (e.g. `stripe.com`) from polluting the subdomain inventory. |

### 5. File Extension Exclusions (`EXCLUDED_EXTENSIONS`)
The following static asset extensions are pruned from crawlers, URL collectors, and parameter parsers:
- **Images:** `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`, `.webp`
- **Media:** `.mp3`, `.mp4`, `.wav`, `.avi`, `.mov`, `.flv`
- **Fonts:** `.woff`, `.woff2`, `.ttf`, `.eot`, `.otf`
- **Styles:** `.css`, `.less`, `.scss`

### 6. Analytics Parameter Pruning (`NOISE_PARAMS`)
Common tracking and telemetry query parameters are filtered out to prevent combinatorial explosion:
- `utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `utm_content`
- `gclid`, `fbclid`, `ref`, `referrer`, `sessionid`, `sid`, `_ga`, `_gid`, `_fbp`, `_hs*`

### 7. Entropy Thresholding ([core/scoring.py](file:///home/akram/Documents/recon_framework-3.2.0/core/scoring.py))
- Calculates Shannon entropy on parameter values.
- Values with `entropy < 3.5` are flagged as predictable or static placeholders.
- High-entropy strings (> 3.5) are promoted to high-priority secret/credential candidates.

### 8. Vendor JS Pruning (`BAD_JS_PATTERNS`)
Client-side scripts matching known third-party libraries or CDNs (Google Analytics, Sentry, Cloudflare, jQuery, React, Stripe, Intercom, etc.) are excluded from deep reverse engineering to save compute and eliminate false positive endpoints.



---

## ⚙️ 6. Tool Resolution & Execution Mechanism

The framework does not rely on a fixed installation path for external tools.
In [config/tools.py](file:///home/akram/Documents/recon_framework-3.2.0/config/tools.py):
1. **Search Order:**
   - `$HOME/go/bin`
   - `$HOME/.local/bin`
   - `/usr/local/bin`
   - `/usr/bin`
   - Specialized directories (`/opt/subscraper`, `/opt/github-search`, `/opt/SubDomainizer`)
2. **Dynamic Resolution (`resolve_tool`):** Checks `shutil.which` and explicit fallback paths.
3. **Availability (`is_tool_available`):** Checks if the file exists and has executable permissions (`os.X_OK`).
4. **Execution Protocol (`core/runner.py`):**
   - Subprocesses are spawned using list arguments without `shell=True` to avoid argument injection and process isolation failure.
   - Timeouts are strictly enforced; dead processes are killed cleanly using process groups (`os.killpg`).

---

## 🚦 7. CLI Reference & Execution Examples

| Command / Flag | Purpose |
| :--- | :--- |
| `python3 main.py --check-tools` | Inspect availability and paths of all configured tools |
| `python3 main.py -d target.com` | Standard full reconnaissance on a single domain |
| `python3 main.py -df targets.txt` | Sequential multi-target recon |
| `python3 main.py -d target.com --resume` | Resume interrupted scan from last completed state |
| `python3 main.py -d target.com --monitor` | Diff current scan results against previous `stats.json` |
| `python3 main.py -d target.com --nuclei` | Enable Nuclei vulnerability scanning |
| `python3 main.py -d target.com --port-scan` | Enable Naabu open port scanning |
| `python3 main.py -d target.com --deep-crawl` | Recursively spider newly discovered subdomains |
| `python3 main.py -d target.com --bypass-waf` | Inject WAF evasion headers (`X-Forwarded-For`, etc.) |
| `python3 main.py -d target.com -rl 30` | Enforce global rate limit (30 requests/second) |
| `python3 main.py -d target.com -t 15` | Deep scan top 15 prioritized targets (default: 10) |
| `python3 main.py -d target.com -o /data/recon` | Specify custom root output folder |

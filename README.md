# ⚡ Recon Framework v3.2.0: Attack Surface Intelligence Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-brightgreen.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Production--Ready-success.svg)]()
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)]()
[![Security](https://img.shields.io/badge/Security-Zero--Scope--Bleed-red.svg)]()

> **Autonomous, high-precision asset discovery, security profiling, and intelligence extraction pipeline engineered for penetration testers, bug bounty hunters, and offensive security teams.**

---

## 🎯 System Overview & Philosophy

Modern external attack surfaces are dynamic, distributed across multi-cloud environments, and guarded by Web Application Firewalls (WAFs). Standard recon scripts often flood operators with noise, trigger IP bans, or leak scope. 

**Recon Framework v3.2.0** is engineered around four core tenets:

1. **Intelligence Over Volume**: Instead of hoarding millions of dead or duplicate URLs, the engine applies multi-layer filtering (extension pruning, third-party vendor JS elimination, entropy analysis, and RFC-compliant scope validation) to isolate exploitable, high-value assets.
2. **Recursive Intelligence Feedback Loops**: Discovered JavaScript bundles and API routes are parsed dynamically for new hostnames, which are validated against strict scope invariants and fed back into active DNS resolution and HTTP probing.
3. **Adaptive Safety & WAF Profiling**: The framework profiles target defenses before scanning, dynamically throttling rate limits, concurrency ceilings, and injecting evasion headers when WAFs (Cloudflare, Akamai, AWS CloudFront) are detected.
4. **Stateful Execution & Differential Monitoring**: Fully resumable operations (`--resume`) prevent duplicate work, while continuous monitoring (`--monitor`) automatically tracks asset changes (+new / -decommissioned assets) between engagement runs.

---

## 🔄 The 12-Stage Reconnaissance Pipeline

```
                       Target Domain / List (-d / -df)
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 1: SUBDOMAIN ENUMERATION & WILDCARD PRUNING                        │
│ • Passive Discovery : subfinder, assetfinder, findomain, crt.sh, chaos    │
│ • Certificate Intel : tlsx (SAN/CN extraction with strict scope check)   │
│ • Active Discovery  : amass (passive/active), knockpy, subscraper, github │
│ • Active Brute-Force: dnsx (curated wordlists) & shuffleDNS + massdns     │
│ • Permutations      : alterx smart mutations & puredns validation        │
│ • DNS Hygiene       : Wildcard DNS detection & pure resolver filtering   │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌───────────────┐             ┌───────────────┐             ┌───────────────┐
│ STAGE 2:      │             │ STAGE 3:      │             │ STAGE 4:      │
│ SUBDOMAIN     │             │ CLOUD RECON   │             │ PORT SCAN     │
│ TAKEOVER      │             │ Multi-cloud   │             │ Naabu top     │
│ Subzy engine  │             │ S3, GCP,      │             │ ports with    │
│ verification  │             │ Azure, DO     │             │ auto-fallback │
└───────┬───────┘             └───────┬───────┘             └───────┬───────┘
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 5: ADAPTIVE WAF PROFILING & SAFETY SCALING                         │
│ • Wafw00f inspection across apex and key targets                         │
│ • Auto-tuning of global rate limits (Safe / Balanced / Aggressive)       │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 6: HTTP PROBING & MULTI-VARIABLE ASSET SCORING                     │
│ • httpx probing: Status codes, content length, titles, technologies      │
│ • Metadata capture: ASN, CDN identification, Favicon hash               │
│ • Prioritization algorithm: Dynamic risk scoring based on tech & status  │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 7: ACTIVE SPIDERING & PASSIVE ARCHIVE AGGREGATION                  │
│ • Active Crawlers: Katana (headless/XHR) & Hakrawler                    │
│ • Archive Aggregation: gau, waybackurls, waymore, urlfinder, gospider    │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 8: JAVASCRIPT INTELLIGENCE & RECURSIVE FEEDBACK                    │
│ • Vendor de-noising (filtering analytics, trackers, ads)                 │
│ • Endpoint & secret extraction: jsluice, jsleak, SubDomainizer, xnLink   │
│ • Sourcemap unbundling via sourcemapper                                  │
│ 🔁 RECURSIVE FEEDBACK LOOP: Subdomains exposed in client code are parsed, │
│    scope-checked, and fed back into Stage 6 for continuous expansion     │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 9: API ROUTING & HIDDEN PARAMETER DISCOVERY                        │
│ • Kiterunner API route brute-forcing (non-interactive brute engine)      │
│ • Passive parameter extraction & entropy analysis                        │
│ • Active parameter mining via Arjun & x8 heuristic detection             │
│ • Automated fuzzable URL compilation with qsreplace                      │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ STAGE 10: 403 BYPASS & ACCESS CONTROL TESTING                            │
│ • nomore403 automated header, path, and method rewrite testing           │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┴─────────────────────────────┐
        ▼                                                           ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│ STAGE 11: NUCLEI TARGETED    │            │ STAGE 12: VISUAL ENUMERATION │
│ VULNERABILITY SCANNING       │            │ Gowitness headless browser   │
│ Scans top targets, high-risk │            │ screenshots & visual         │
│ endpoints, and cloud buckets │            │ reporting                    │
└──────────────────────────────┘            └──────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ FINAL STAGE: INTELLIGENCE SYNTHESIS & REPORTING                          │
│ • Structured statistics & metrics in stats.json                          │
│ • Instant Telegram notifications on scan completion & vulnerabilities    │
│ • Continuous monitoring asset diffing (+new / -removed)                  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tool Ecosystem & Verification

Recon Framework integrates 45+ premier offensive security tools while ensuring **graceful degradation**—if an optional binary is not installed, the framework issues a warning and proceeds without failure.

### Inspecting Installed Tools
Run the built-in diagnostic checker to inspect your environment:

```bash
python3 main.py --check-tools
```

Sample output:
```text
=================================================================
 🛠️  RECON FRAMEWORK - TOOL STATUS INSPECTION
=================================================================
 TOOL                 | STATUS       | PATH / RESOLUTION
-----------------------------------------------------------------
 alterx               | ✅ AVAILABLE  | /home/user/go/bin/alterx
 amass                | ✅ AVAILABLE  | /usr/lib/amass/amass
 anew                 | ✅ AVAILABLE  | /home/user/go/bin/anew
 arjun                | ✅ AVAILABLE  | /usr/bin/arjun
 assetfinder          | ✅ AVAILABLE  | /usr/bin/assetfinder
 dnsx                 | ✅ AVAILABLE  | /home/user/go/bin/dnsx
 findomain            | ✅ AVAILABLE  | /usr/bin/findomain
 httpx                | ✅ AVAILABLE  | /home/user/go/bin/httpx
 katana               | ✅ AVAILABLE  | /home/user/go/bin/katana
 kr                   | ✅ AVAILABLE  | /usr/bin/kr
 naabu                | ✅ AVAILABLE  | /home/user/go/bin/naabu
 nuclei               | ✅ AVAILABLE  | /usr/bin/nuclei
 puredns              | ✅ AVAILABLE  | /home/user/go/bin/puredns
 subfinder            | ✅ AVAILABLE  | /home/user/go/bin/subfinder
 ...
-----------------------------------------------------------------
 Total Tools: 45 | Ready: 45 | Missing: 0
=================================================================
```

---

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/sozanga3/ReconFramework.git
cd ReconFramework
```

### 2. Configure Python Environment
```bash
pip install -r requirements.txt
```
*(Dependencies include `requests`, `dnspython`, `urllib3`)*

### 3. API Keys & Notifications Configuration
Recon Framework integrates with Telegram and discovery APIs:

```bash
cp config/api_keys.py.example config/api_keys.py
```

Configure your credentials inside `config/api_keys.py` (or export environment variables):
```python
TELEGRAM_BOT_TOKEN = "your_bot_token"
TELEGRAM_CHAT_ID = "your_chat_id"
CHAOS_KEY = "your_chaos_api_key"
GITHUB_TOKEN = "your_github_token"
```

> **Security Guarantee:** `config/api_keys.py`, `.env`, and all credentials are automatically protected by `.gitignore` to prevent leaks.

---

## 💻 Usage Guide

### 1. Basic Single-Domain Scan
Run the complete discovery pipeline on a target:
```bash
python3 main.py -d example.com
```

### 2. Multi-Domain Batch Ingestion
Scan multiple targets sequentially with strict multi-domain scope preservation:
```bash
python3 main.py -df targets.txt
```

### 3. Deep Target Focus
Analyze the top 20 highest-scoring targets based on technology and risk profiling:
```bash
python3 main.py -d example.com --top 20
```

### 4. Stateful Resume
Resume an interrupted scan from its last saved milestone:
```bash
python3 main.py -d example.com --resume
```

### 5. Continuous Asset Monitoring (Diff Engine)
Compare new findings against previous scans to track newly spawned or decommissioned assets:
```bash
python3 main.py -d example.com --monitor
```

### 6. Full Offensive Pipeline (Nuclei & Port Scanning)
Activate port scanning via Naabu and targeted Nuclei vulnerability scans:
```bash
python3 main.py -d example.com --nuclei --port-scan
```

### 7. Stealth, WAF Bypass & Rate Limiting
Enforce conservative request rates and inject WAF bypass headers:
```bash
python3 main.py -d example.com --bypass-waf -rl 25
```

---

## 📖 CLI Flag Reference

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-d`, `--domain` | `<domain>` | Single target domain to scan |
| `-df`, `--domains-file` | `<path>` | File containing target domains (one per line) |
| `-o`, `--output` | `<dir>` | Custom output directory (default: `output/<domain>`) |
| `-t`, `--top` | `<int>` | Number of top-ranked targets to deep-scan (default: 10) |
| `--resume` | *None* | Resume previous scan from the last completed state |
| `--monitor` | *None* | Run differential comparison against previous scan stats |
| `--deep-crawl` | *None* | Recursively spider newly discovered subdomains |
| `--bypass-waf` | *None* | Inject WAF evasion headers (`X-Forwarded-For`, etc.) |
| `--nuclei` | *None* | Enable Nuclei vulnerability scanning on prioritized endpoints |
| `--port-scan` | *None* | Enable port scanning with Naabu (disabled by default) |
| `-rl`, `--rate-limit` | `<int>` | Global rate limit in requests/sec across all tools |
| `--check-tools` | *None* | Inspect and display availability of all configured tools |

---

## 📁 Output Directory Architecture

All scan data is structured deterministically under `output/<target_domain>/`:

```text
output/<domain>/
├── cloud/
│   └── cloud_assets.txt          # Discovered S3, GCP, Azure, DO storage buckets
├── endpoints/
│   ├── all_endpoints.txt         # Consolidated endpoints across all crawlers
│   ├── hakrawler_raw.txt         # Hakrawler crawl endpoints
│   ├── kiterunner_api.txt        # Verified API routes from Kiterunner
│   └── passive_urls.txt          # Passive archive URLs (gau, wayback, waymore)
├── fuzzing/
│   └── nuclei_results.txt        # Verified Nuclei vulnerability findings
├── httpx/
│   ├── alive.txt                 # Responsive HTTP/HTTPS services
│   ├── ranked.json               # Full JSON telemetry with asset scores
│   └── alive_report.txt          # Detailed human-readable host report
├── js/
│   ├── js_files_clean.txt        # De-noised in-scope JavaScript files
│   ├── endpoints_filtered.txt    # Extracted API routes and paths from JS
│   ├── secrets_clean.txt         # Extracted API keys, tokens, and credentials
│   └── subdomains_from_js.txt    # Newly discovered subdomains from code
├── params/
│   ├── all_params.txt            # Unique parameters discovered
│   ├── scored_params.json        # Categorized by risk (SSRF, SQLi, LFI, XSS, IDOR)
│   └── endpoints_fuzzable.txt    # qsreplace URL patterns ready for fuzzing
├── ports/
│   └── naabu_results.txt         # Open ports and services
├── screenshots/
│   └── *.png                     # Headless browser visual captures
├── subdomains/
│   ├── all.txt                   # Final resolved, verified unique subdomains
│   ├── takeovers.txt             # Subdomain takeover vulnerabilities (subzy)
│   └── puredns_raw.txt           # Wildcard-filtered DNS records
├── safety_profile.json           # WAF ratio and risk recommendation
├── stats.json                    # Quantitative scan metrics for monitoring
└── summary.txt                   # Executive reconnaissance summary
```

---

## 🛡️ Security, Privacy & Safety Guidelines

- **Zero Scope Bleed**: Strict domain invariants (`candidate == target or candidate.endswith("." + target)`) ensure third-party SaaS, CDNs, and multi-tenant certificate SANs are never probed.
- **Data Protection**: Real engagements, target findings (`results/`, `output/`), log files, and API keys are strictly excluded from git tracking.
- **Fail-Safe Design**: Process timeouts, memory limits, and isolated process groups prevent zombie processes or hung scans.

---

## 🗺️ Roadmap & Future Capabilities

For upcoming enhancements—including DNS zone transfer testing (`AXFR`), ASN/CIDR origin mapping, Favicon Murmur3 fingerprinting, and targeted sensitive content discovery via `ffuf`—see:
* **[docs/plans/recon_data_expansion_plan.md](docs/plans/recon_data_expansion_plan.md)**

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

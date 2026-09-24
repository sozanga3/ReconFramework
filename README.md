# ⚡ Recon Framework v3.2.0: Attack Surface Intelligence Engine

A modular, high-performance reconnaissance and vulnerability discovery framework engineered for bug bounty hunters, red teamers, and penetration testers.

---

## 🌟 Core Architecture & Pipeline

```
Target Domain(s)
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Subdomain Discovery (Passive + Active + Permutations)   │
│    • subfinder, assetfinder, findomain, tlsx (SAN certs)    │
│    • amass (passive + active), knockpy, crt.sh, subscraper  │
│    • dnsx brute-forcing (5,000-wordlist fallback hierarchy) │
│    • puredns resolution & wildcard filtering                │
│    • alterx smart mutations (verified alive only)           │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┼────────────────────────┐
       ▼                       ▼                        ▼
┌──────────────┐      ┌─────────────────┐      ┌────────────────┐
│ 2. Subdomain │      │ 3. Cloud Recon  │      │ 4. Port Scan   │
│    Takeover  │      │ (Multi-Threaded)│      │    (Naabu)     │
│    (Subzy)   │      │ AWS/GCP/Azure/DO│      │ Auto unpriv.   │
└──────────────┘      └─────────────────┘      └────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. WAF & Safety Profiling (wafw00f + nomore403 bypasses)    │
│    • Auto-adjusts rate limits & concurrency if WAF detected │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. HTTP Probing & Prioritization (httpx)                   │
│    • Title, status, tech-detect, ASN, CDN, favicon hash     │
│    • Dynamic multi-variable target scoring                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Active & Passive Spidering (Concurrent)                  │
│    • Katana & Hakrawler (active crawlers)                   │
│    • gau, waybackurls, gospider, waymore, urlfinder (passive)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. JavaScript Intelligence & Secret Hunting                 │
│    • Intelligent third-party vendor noise filter            │
│    • jsluice batch endpoint extraction & 66+ secret regexes │
│    • Source map reconstruction (sourcemapper)               │
│    • Deep JS endpoint discovery (jsleak, xnLinkFinder)      │
│    • Recursive feedback loop: subdomains found in JS feeded │
│      directly back into the resolution and probe engine     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. Parameter Discovery & API Routing                        │
│    • Kiterunner (API route brute-forcing)                   │
│    • Passive param extraction (unfurl)                      │
│    • Active param mining (Arjun + x8 3-pass heuristic)      │
│    • qsreplace fuzzable endpoint generation                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┴────────────────────────┐
       ▼                                                ▼
┌──────────────────────────────┐       ┌──────────────────────────────┐
│ 10. Nuclei Scan (Optional)   │       │ 11. Visual Recon (Gowitness) │
│     Fuzzing prioritized eps  │       │     Headless screenshots and │
│     and discovered params    │       │     interactive HTML report  │
└──────────────────────────────┘       └──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 12. Reporting & Continuous Differential Monitoring          │
│     • stats.json, summary.txt, alive_report.txt             │
│     • Telegram instant alert notifications                  │
│     • Differential monitoring diff (+new / -removed assets) │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Getting Started

### 1. Inspect Configured Tools

Verify your environment and check which tools are installed:
```bash
python3 main.py --check-tools
```

### 2. Configuration & API Keys

Copy the example configuration and add your API keys:
```bash
cp config/api_keys.py.example config/api_keys.py
```
Edit `config/api_keys.py` with your tokens (e.g. GitHub token, Telegram bot credentials, Chaos API key, etc.). You can also supply them via environment variables:
- `GITHUB_TOKEN`
- `TELEGRAM_BOT_TOKEN` & `TELEGRAM_CHAT_ID`
- `CHAOS_KEY`

---

## 🛠️ Usage & CLI Flags

### Basic Scan
Run a full reconnaissance scan on a single domain:
```bash
python3 main.py -d example.com
```

### Scan Target Domain with Custom Top Priority Targets
```bash
python3 main.py -d example.com --top 5
```

### Scan Multiple Domains Sequentially
```bash
python3 main.py -df targets.txt
```

### Resume an Interrupted Session
```bash
python3 main.py -d example.com --resume
```

### Continuous Monitoring (Diffing Against Previous Run)
```bash
python3 main.py -d example.com --monitor
```

### Enable Nuclei Vulnerability Scanning & Port Scanning
```bash
python3 main.py -d example.com --nuclei --port-scan
```

### Deep Crawl & WAF Bypass Headers
```bash
python3 main.py -d example.com --deep-crawl --bypass-waf -rl 30
```

---

## 📋 Complete CLI Reference

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-d`, `--domain` | `<domain>` | Single target domain to scan |
| `-df`, `--domains-file` | `<path>` | File containing target domains (one per line) |
| `-o`, `--output` | `<dir>` | Custom output directory (default: `output/<domain>`) |
| `-t`, `--top` | `<int>` | Number of top ranked targets to deep scan (default: 10) |
| `--resume` | Flag | Resume previous scan from last completed state |
| `--monitor` | Flag | Run differential comparison against previous scan stats |
| `--deep-crawl` | Flag | Recursively spider newly discovered subdomains |
| `--bypass-waf` | Flag | Inject WAF evasion headers (`X-Forwarded-For`, etc.) |
| `--nuclei` | Flag | Enable Nuclei vulnerability scanning on prioritized endpoints |
| `--port-scan` | Flag | Enable port scanning with naabu (disabled by default) |
| `-rl`, `--rate-limit` | `<int>` | Global rate limit in requests/sec across all tools |
| `--check-tools` | Flag | Inspect availability of all core and optional tools |

---

## 📁 Output Directory Structure

Each scan creates a clean, organized hierarchy under `output/<target_domain>/`:

```
output/<domain>/
├── cloud/
│   └── cloud_assets.txt          # Open/protected S3, GCP, Azure, DO buckets
├── endpoints/
│   ├── all_endpoints.txt         # Merged endpoints across all tools
│   ├── passive_urls.txt          # Merged passive discovery
│   └── ...
├── fuzzing/
│   └── nuclei_results.txt        # Nuclei vulnerability findings
├── httpx/
│   ├── alive.txt                 # Verified responsive HTTP targets
│   ├── ranked.json               # Prioritized targets by asset score
│   └── alive_report.txt          # Human-readable target details
├── js/
│   ├── js_files_clean.txt        # De-noised in-scope JavaScript files
│   ├── endpoints_filtered.txt    # Extracted JS endpoints
│   ├── secrets_clean.txt         # Detected API keys, tokens, and credentials
│   └── subdomains_from_js.txt    # Subdomains discovered within code
├── params/
│   ├── all_params.txt            # Extracted query/body parameters
│   ├── scored_params.json        # Classified params (XSS, SSRF, SQLi, LFI, IDOR)
│   └── endpoints_fuzzable.txt    # qsreplace formatted fuzzing targets
├── ports/
│   └── naabu_results.txt         # Open port scan results
├── screenshots/
│   └── *.png                     # Headless browser screenshots
├── subdomains/
│   ├── all.txt                   # Final resolved, verified unique subdomains
│   ├── takeovers.txt             # Subzy takeover vulnerability checks
│   └── sources/                  # Raw output from each individual subdomain tool
├── safety_profile.json           # WAF ratio and risk recommendation
├── stats.json                    # Machine-readable scan metrics
└── summary.txt                   # Executive quantitative recon summary
```

# 🤖 AGENTS.md — AI Engineering & Contribution Guidelines

> **Target Project:** `recon_framework-3.2.0` (Attack Surface Intelligence Engine)  
> **Audience:** AI Coding Assistants (Antigravity, Claude, ChatGPT, Cursor, Copilot, etc.) and Human Engineers.  
> **Core Objective:** Guarantee maximum code quality, execution safety, and 100% data accuracy across all reconnaissance pipeline operations.

---

## 🎯 1. Identity & Operating Principles

You are an expert offensive security engineer and systems programmer maintaining a mission-critical reconnaissance and vulnerability pipeline.

When modifying this repository, adhere strictly to these principles:

1. **Zero Hallucination of Tool Flags:** Recon tools (`subfinder`, `httpx`, `katana`, `nuclei`, `naabu`, `jsluice`, etc.) have specific, version-dependent CLI syntax. Never invent flags or CLI options. Verify them against installed versions or official documentation.
2. **Data Integrity Above All:** Recon output feeds directly into automated fuzzing, vulnerability scanners, and human bounty hunting. Corrupted domains, fake URLs, un-sanitized parameters, or broken JSON schemas ruin entire engagement workflows.
3. **Fail-Safe & Graceful Degradation:** Users may run this framework on minimal VPS environments where some optional tools are absent. Modules must **never crash** due to an absent optional binary.
4. **Stealth, Rate Limits, and Safety:** Automated recon can trigger WAF bans or cause accidental DoS. Never bypass rate limits, safety profiles, or concurrency ceilings set by `config/settings.py` or runtime CLI flags (`-rl`, `--bypass-waf`).

---

## 📜 2. The Golden Rules of Recon Framework Development

### Rule 1: Tool Execution via `core.runner`

- **NEVER** use raw `subprocess.Popen(..., shell=True)` directly in modules.
- **ALWAYS** call `core.runner.run_command` or `core.runner.run_command_with_input`.
- Pass arguments as lists: `[TOOL_PATH, "-flag", value]`.
- If shell piping is strictly required, use `core.runner.run_command_shell` which isolates process groups to prevent zombie processes and memory leaks on timeouts.
- Always specify a deterministic `timeout` and pass `cwd=...` when relative output files are written.

### Rule 2: Dynamic Tool Resolution & Availability Checking

- **NEVER** hardcode binary names (e.g., `"subfinder"`) or raw absolute paths (e.g., `"/usr/bin/subfinder"`) directly inside modules.
- **ALWAYS** import tool constants from [config/tools.py](file:///home/akram/Documents/recon_framework-3.2.0/config/tools.py) (e.g., `from config.tools import SUBFINDER, HTTPX, is_tool_available`).
- Check availability before invocation:

  ```python
  from config.tools import SUBZY, is_tool_available

  if is_tool_available(SUBZY):
      # run subzy
  else:
      logger.warning("Subzy not found. Skipping takeover verification.")
  ```

### Rule 3: Centralized Configuration (Zero Hardcoding)

- **NEVER** hardcode thread counts, timeouts, regex patterns, or rate limits inside `modules/*.py`.
- **ALWAYS** declare defaults in [config/settings.py](file:///home/akram/Documents/recon_framework-3.2.0/config/settings.py), [config/keywords.py](file:///home/akram/Documents/recon_framework-3.2.0/config/keywords.py), or [config/wordlists.py](file:///home/akram/Documents/recon_framework-3.2.0/config/wordlists.py).
- Respect user overrides passed from CLI args (`custom_rate_limit`, `dynamic_timeout`, `top_limit`).

### Rule 4: Strict Scope Enforcement & Exclusion of Out-of-Scope Domains (Zero Scope Bleed)

- **The Inviolable Scope Invariant:**
  - Every domain and subdomain stored, processed, probed, or reported MUST satisfy:

    ```python
    candidate == target_domain or candidate.endswith("." + target_domain)
    ```

  - **NEVER** use loose substring checks like `target_domain in candidate` or `candidate.endswith(target_domain)` without a preceding dot `.`.
    - *Why:* If the target is `target.com`, loose checks will falsely accept `attacker-target.com`, `not-target.com`, or `target.company`.
  - Always validate candidates against `core.utils.is_valid_subdomain(candidate, target_domain)`.
- **Multi-Tenant SSL/TLS & SAN Leakage Pruning:**
  - Tools querying certificate transparency logs or extracting Subject Alternative Names (SANs) (`tlsx`, `crt.sh`, `amass`, `subscraper`) frequently pull shared multi-tenant certificates (e.g., Cloudflare, Akamai, AWS, or Fastly shared edge certs).
  - Every SAN extracted from a certificate must pass strict scope validation before being added to candidate sets. Discard any domain that does not strictly anchor to `target_domain`.
- **Third-Party CDN & SaaS Hostname Filtering:**
  - Never allow third-party hosting, CDN, or vendor hostnames to leak into the subdomain inventory:
    - Prune vendor domains (`*.cloudfront.net`, `*.s3.amazonaws.com`, `*.azurewebsites.net`, `*.trafficmanager.net`, `*.cloudflare.com`, `*.github.io`, `*.wpengine.com`, `*.fastly.net`, `*.edgesuite.net`, `*.appspot.com`, `*.herokuapp.com`, `*.pantheonsite.io`).
  - Prune third-party tracking, social media, and analytics domains (`google-analytics.com`, `googletagmanager.com`, `doubleclick.net`, `facebook.com`, `twitter.com`, `sentry.io`, etc.).
- **Subdomain Sanitization & FQDN Normalization:**
  - Before scope checking, strip protocols (`https://`, `http://`), credentials (`user:pass@`), paths (`/endpoint`), ports (`:443`), trailing dots, and leading wildcards (`*.` or `*`).
  - Convert all hostnames to lowercase and strip all surrounding whitespace.
  - Reject hostnames containing bad characters: `{}[]|\\^<>"'`, backticks, spaces, or non-printable characters.
  - Every valid subdomain must conform to the RFC FQDN pattern:

    ```python
    re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
    ```

- **JavaScript Intelligence Feedback Loop Guard:**
  - In Stage 8, client-side JS bundles naturally contain references to third-party APIs (e.g. `api.stripe.com`, `login.microsoftonline.com`, `cdn.segment.com`).
  - The recursive feedback loop in `main.py` MUST run all newly extracted hosts through `clean_subdomains(new_subs, domain)` before feeding them into `subdomains/all.txt` or executing downstream `httpx` probes.
- **Wildcard DNS & Permutation Filtering:**
  - Targets with DNS wildcard records (`*.target.com -> IP`) return active responses for non-existent domains.
  - Active enumeration tools (`puredns`, `dnsx`) must enforce wildcard detection to purge phantom subdomains generated by permutation tools (`alterx`) or dictionary brute-forcing.
- **Multi-Target Ingestion & Scope Propagation (`-d` vs `-df`):**
  - **Single Target (`-d target.com`):** Scope strictly includes `target.com` and all arbitrary-depth subdomains (`*.target.com`, e.g., `a.b.c.target.com`).
  - **Domain List (`-df targets.txt`):** When multiple domains are provided, all listed domains and their respective subdomains are in scope (`effective_domains = all_domains if all_domains else [domain]`).
  - Every scanning module (`crawler.py`, `js_enum.py`, `js_filter.py`, `param_discovery.py`, `subdomains.py`) MUST accept `all_domains` and filter candidates against `effective_domains`.
- **Data Preservation Guarantee (Never Delete Legitimate In-Scope Data):**
  - **Clean Before Check:** Tools often emit URLs with schemes (`https://`), ports (`:443`), credentials (`user:pass@`), or trailing slashes (`/`). Modules MUST normalize the hostname *before* running regex/scope checks so valid in-scope subdomains are **never accidentally discarded or deleted**.
  - **Multi-Level Subdomains:** Deeply nested subdomains (e.g., `dev.api.internal.target.com`) are 100% valid and MUST NOT be truncated or discarded.
  - **Multi-Domain Batch Preservation:** In multi-target runs (`-df`), discovering an endpoint or subdomain that belongs to any of the domains in `all_domains` must be preserved as in-scope, not discarded.
- **URL & Parameter Sanitization:**
  - Strip blacklisted static extensions defined in `EXCLUDED_EXTENSIONS` (`.png`, `.css`, `.woff`, `.ico`, etc.).
  - Filter out analytics noise parameters in `NOISE_PARAMS` (`utm_*`, `fbclid`, `_ga`, etc.).
  - Parameter values must exceed `ENTROPY_THRESHOLD` (3.5) before being flagged as security candidates.
  - Third-party analytics/vendor JS files (`google-analytics`, `sentry`, `facebook`, etc.) must be pruned using `BAD_JS_PATTERNS`.
- **Deduplication:** Always pass raw collections through `unique_list()` or `clean_data()` from [core/output.py](file:///home/akram/Documents/recon_framework-3.2.0/core/output.py).

### Rule 5: State Persistence & Resume Protocol

- Every significant pipeline phase must support the `--resume` flag.
- Use `core.state.run_or_resume`:

  ```python
  from core.state import run_or_resume

  subs = run_or_resume(
      resume, paths, "subdomains",
      f"{paths['subdomains']}/all.txt", "list",
      enumerate_subdomains, domain, paths,
      base_latency=dynamic_timeout, rate_limit=custom_rate_limit
  )
  ```

- If writing a custom multi-step task, save state explicitly: `save_state(paths, "step_name")` and check `is_step_completed(paths, "step_name")`.

### Rule 6: Deterministic Output Contract

- All scans write to `output/<domain>/` (or custom `-o` directory) via `create_output_structure(domain, output_dir)`.
- Never write ad-hoc output files to `/tmp` or project root.
- All JSON files must be serialized with `indent=4` via `core.output.save_json`.
- Text reports must use Unix `\n` line endings via `core.output.save_txt`.

---

## 🏛️ 3. Architectural Boundaries

Follow the strict modular hierarchy:

```
recon_framework/
│
├── config/             # PURE DECLARATION & RESOLUTION
│   ├── settings.py     # Global rate limits, threads, timeouts, thresholds, exclusions
│   ├── tools.py        # Binary discovery (resolve_tool, is_tool_available, tool mappings)
│   ├── keywords.py     # High-value parameter/routing regexes & scoring keywords
│   └── wordlists.py    # Fallback wordlist paths and embedded resolvers
│
├── core/               # REUSABLE PIPELINE FOUNDATION (NO tool-specific scanning logic)
│   ├── runner.py       # Subprocess management, timeouts, error capturing
│   ├── output.py       # Folder structures, clean_data, save_txt, save_json, summaries
│   ├── state.py        # State management, run_or_resume, resume file loaders
│   ├── scoring.py      # Target prioritization algorithm (tech, status, keywords, entropy)
│   ├── logger.py       # Unified logging handler
│   ├── notifications.py# Telegram alerting system
│   ├── utils.py        # Domain validation, dynamic timeout discovery, tool check CLI
│   └── filter.py       # Scope filtering & multi-domain validation
│
├── modules/            # INDIVIDUAL RECONNAISSANCE STAGES (Implement standard interface)
│   ├── subdomains.py   # Multi-engine passive & active discovery + resolver brute-force
│   ├── httpx.py        # HTTP probing, technology detection, title extraction
│   ├── crawler.py      # Katana, Hakrawler, Gospider, Gau, Waybackurls, Waymore
│   ├── js_enum.py      # Jsluice, JSleak, Sourcemapper, SubDomainizer, xnLinkFinder
│   ├── js_filter.py    # Noise removal, vendor pruning, secret extraction, high-value JS
│   ├── param_discovery.py # Arjun, x8, ParamSpider, Kiterunner, qsreplace, unfurl
│   ├── waf_detector.py # Wafw00f profiling & nomore403 bypass logic
│   ├── cloud_recon.py  # Multi-cloud storage discovery (S3, GCP, Azure, DO)
│   ├── github_recon.py # GitHub search automation for repos, endpoints, secrets
│   ├── port_scan.py    # Naabu integration with automatic unprivileged fallback
│   ├── nuclei_scan.py  # Targeted Nuclei scans on prioritized endpoints
│   └── screenshots.py  # Headless visual verification with Gowitness
│
└── main.py             # CLI ENTRY POINT & PIPELINE ORCHESTRATOR
```

### Module Interface Contract

When modifying or adding a module under `modules/`:

1. Receive parameters: `(domain, paths, base_latency=..., rate_limit=..., ...)`
2. Do not crash if tools are missing: check `is_tool_available(TOOL)`. Return empty list `[]` or clean tuple if dependencies are missing.
3. Save canonical outputs directly into the corresponding directory mapped in `paths` (e.g. `paths['js']`, `paths['params']`).
4. Return clean, deduplicated in-memory structures for immediate handoff to downstream stages.

---

## 🔬 4. Data Schemas & Contracts

When producing or modifying data files, adhere strictly to these schemas:

### A. `stats.json` Schema (Written to `output/<domain>/stats.json`)

```json
{
    "domain": "example.com",
    "scan_date": "2026-09-24 14:00:00",
    "subdomains": 142,
    "alive": 89,
    "endpoints": 1250,
    "secrets": 4,
    "params": 312,
    "nuclei": 2,
    "ports": 12,
    "cloud_assets": 1,
    "safety": {
        "recommendation": "balanced",
        "waf_ratio": 0.25,
        "wafs": ["Cloudflare"]
    },
    "tool_metrics": {
        "secretfinder": 1,
        "paramspider": 85,
        "arjun": 12,
        "x8": 8,
        "kiterunner": 34,
        "github_endpoints": 15,
        "github_secrets": 0
    },
    "param_categories": {
        "xss": 18,
        "ssrf": 4,
        "sqli": 7,
        "lfi": 3,
        "idor": 9
    },
    "top_targets": [
        "https://api.example.com",
        "https://auth.example.com"
    ],
    "elapsed_seconds": 184.5
}
```

### B. `ranked.json` Schema (Written to `output/<domain>/httpx/ranked.json`)

```json
[
    {
        "url": "https://api.example.com",
        "score": 42,
        "status_code": 200,
        "content_length": 1450,
        "title": "Swagger UI",
        "technologies": ["OpenAPI", "Express"],
        "cdn": false,
        "asn": "AS13335"
    }
]
```

### C. `safety_profile.json` Schema (Written to `output/<domain>/safety_profile.json`)

```json
{
    "recommendation": "safe",
    "waf_ratio": 0.6,
    "wafs": ["Akamai", "Cloudflare"]
}
```

*Valid values for `recommendation`: `"aggressive"`, `"balanced"`, `"safe"`.*

---

## 🛠️ 5. Step-by-Step Agent Modification Workflow

Whenever you are asked to fix a bug, optimize a module, or implement a new feature:

1. **Investigate Context First:**
   - Read [CONTEXT.md](file:///home/akram/Documents/recon_framework-3.2.0/CONTEXT.md) to understand dependencies, data flow, and file locations.
   - Inspect the target file and any related modules before editing.
2. **Preserve Compatibility:**
   - Ensure changes do not break `--resume` or `--monitor`.
   - Maintain backward compatibility with existing command line flags in `main.py`.
3. **Validate Syntax & Dependencies:**
   - Run Python compilation checks:

     ```bash
     python3 -m py_compile main.py core/*.py modules/*.py config/*.py
     ```

   - Verify tool status command works:

     ```bash
     python3 main.py --check-tools
     ```

4. **Inspect Git Diffs:**
   - Review all modified lines to ensure no stray debug statements or broken imports were introduced.

---

## 🚫 6. Anti-Patterns to Avoid

- ❌ **NEVER** use `os.system()` or insecure string formatting for commands (`f"katana {url} | anew {file}"`).
- ❌ **NEVER** remove exception handling around tool executions.
- ❌ **NEVER** delete existing docstrings or inline comments explaining architectural reasoning.
- ❌ **NEVER** write mock/fake vulnerability results into `results/` or `output/`.
- ❌ **NEVER** flood targets with unrestrained thread pools; always respect `settings.py` thread constants.
- ❌ **NEVER** use loose scope checks like `target in candidate` or `candidate.endswith(target)` without a dot anchor.
- ❌ **NEVER** write raw tool output directly to canonical files (`all.txt`, `alive.txt`) without passing through `clean_subdomains()` and `is_valid_subdomain()`.
- ❌ **NEVER** leak third-party domains (e.g. AWS, Cloudflare, Akamai, Google, GitHub, Stripe) into subdomain lists.

# Agent Guidelines

See the full target context details here: @CONTEXT.md

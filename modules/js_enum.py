import re
import json
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qsl, urlunparse
from core.output import save_txt, save_json, unique_list, filter_scope, debug_log, clean_data
from core.utils import get_tool_timeout, is_valid_subdomain
from core.scoring import score_js

# -------------------------------------------------
# 📦 Endpoint deduplication helper
# -------------------------------------------------
def dedupe_endpoints(endpoints):
    """Normalize and deduplicate endpoint URLs.
    - Strips trailing slashes
    - Sorts query parameters for consistent ordering
    - Removes fragment identifiers
    Returns a list preserving original order of first occurrence.
    """
    seen = set()
    deduped = []
    for ep in endpoints:
        try:
            parsed = urlparse(ep)
            # Normalize path (remove trailing slash)
            path = parsed.path.rstrip('/')
            # Sort query parameters
            query = '&'.join([f"{k}={v}" for k, v in sorted(parse_qsl(parsed.query))])
            normalized = urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, query, ""))
        except Exception:
            normalized = ep
        if normalized not in seen:
            seen.add(normalized)
            deduped.append(ep)
    return deduped
from config.settings import (
    KATANA_THREADS, 
    KATANA_DEPTH, 
    JSLUICE_THREADS,
    JSLEAK_THREADS,
    SOURCEMAPPER_ENABLED,
    SUBDOMAINIZER_TIMEOUT,
    HTTPX_THREADS,
    XNLINKFINDER_TIMEOUT,
    XNLINKFINDER_DEPTH,
    GETJS_THREADS,
    DEEP_JS_SCAN,
    EXCLUDED_EXTENSIONS,
    HIGH_VALUE_EXTENSIONS
)
from config.tools import (
    GETJS, SUBJS, KATANA, 
    JSLUICE, JSLEAK, SOURCEMAPPER, SUBDOMAINIZER, SECRETFINDER,
    XNLINKFINDER, HTTPX, ANEW, is_tool_available
)
from core.runner import run_command, run_command_shell
from urllib.parse import urlparse

# =========================================================
# 🗺️ URL MAPPING LOGIC
# =========================================================
def load_js_url_mapping(download_path):
    mapping = {}
    # httpx -srd creates a 'response' directory containing an index.txt
    index_file = os.path.join(download_path, "response", "index.txt")
    if os.path.exists(index_file):
        with open(index_file, "r") as f:
            for line in f:
                parts = line.strip().split(" ")
                if len(parts) >= 2:
                    local_path = parts[0]
                    remote_url = parts[1]
                    # Map the absolute path
                    abs_local_path = os.path.abspath(local_path)
                    mapping[abs_local_path] = remote_url
                    # Map the basename as a fallback for relative matches
                    basename = os.path.basename(local_path)
                    mapping[basename] = remote_url
    return mapping

def get_remote_url(source_path, mapping):
    """Safely retrieves the remote URL from mapping, avoiding local path fallbacks."""
    if not source_path or source_path == "unknown":
        return ""
    
    # Try absolute path first
    abs_path = os.path.abspath(source_path)
    if abs_path in mapping:
        return mapping[abs_path]
        
    # Try basename next
    base = os.path.basename(source_path)
    if base in mapping:
        return mapping[base]
        
    return ""

def get_base_url(url):
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except:
        return ""
# 🛡️ DEEP REGEX PATTERNS (SECRETS)
# =========================================================
REGEX_PATTERNS = {
    # --- Cloud & Infrastructure ---
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9+/]{40})[\"']",
    "AWS Session Token": r"(?i)aws_session_token[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9+/]{128,})[\"']",
    "AWS Account ID": r"\b\d{12}\b",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Cloud Platform API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Cloud Platform OAuth": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Firebase URL": r"https://[a-z0-9.-]+\.firebaseio\.com",
    "Azure Client Secret": r"[0-9a-zA-Z]{3,4}~[0-9a-zA-Z]{3,4}~[0-9a-zA-Z]{30,40}",
    "DigitalOcean Access Token": r"dop_v1_[a-f0-9]{64}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Cloudinary Basic Auth": r"cloudinary://[0-9]{15}:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+",
    "Algolia API Key": r"algoliasearch\.initIndex\(['\"][a-zA-Z0-9_-]+['\"], ['\"][a-f0-9]{32}['\"]",

    # --- Social & Communication ---
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
    "GitLab Personal Access Token": r"glpat-[0-9a-zA-Z\-]{20}",
    "Discord Bot Token": r"\b(N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}\b",
    "Discord Webhook": r"https://discordapp\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
    "Telegram Bot Token": r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"[fF][aA][cC][eE][bB][oO][oO][kK].{0,30}['\" \t]([0-9a-f]{32})['\" \t]",
    "Twitter OAuth": r"[tT][wW][iI][tT][tT][eE][rR].{0,30}['\" \t]([0-9a-zA-Z]{35,44})['\" \t]",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Auth Token": r"(?i)twilio_auth_token[\"']?\s*[:=]\s*[\"']([a-f0-9]{32})[\"']",
    "Mailgun API Key": r"key-[0-9a-f]{32}",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",

    # --- Payments & E-commerce ---
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}\b",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24}\b",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}\b",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Razorpay API Key": r"rzp_(live|test)_[a-zA-Z0-9]{14}",
    "Razorpay API Secret": r"(?i)rzp_secret[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9]{24})[\"']",

    # --- Database & Storage ---
    "Database Connection String": r"(mongodb|postgres|mysql|redis|mssql):\/\/[^\s\"']+",
    "MongoDB Connection String": r"mongodb(\+srv)?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\/?[a-zA-Z0-9._%+-]*",
    "Redis Connection String": r"redis:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[0-9]{1,5}",
    "Amazon S3 Bucket": r"https?:\/\/([a-z0-9\.-]+)\.s3\.amazonaws\.com",
    "DigitalOcean Spaces": r"https?:\/\/([a-z0-9\.-]+)\.[a-z0-9-]+\.digitaloceanspaces\.com",
    "Google Storage Bucket": r"gs:\/\/[a-z0-9\.-]+",

    # --- Generic & High Value ---
    "Generic Secret": r"(?i)(key|secret|token|password|auth|api_key|access_key|private_key|auth_token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9-_]{16,})[\"']",
    "Bearer Token": r"Bearer\s+[a-zA-Z0-9\-\._\~\+\/]+",
    "JSON Web Token (JWT)": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "IP Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "Internal IP": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b",
    "URL with Credentials": r"[a-zA-Z0-9]+:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+",
    "Private Key (RSA)": r"-----BEGIN RSA PRIVATE KEY-----",
    "Private Key (Generic)": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    
    # --- Specialized Tools ---
    "New Relic License Key": r"NRAL-[a-f0-9]{20,40}",
    "Datadog API Key": r"(?i)(?:datadog|dd_api|dd_key|datadog_api_key)[\"']?\s*[:=]\s*[\"']([a-f0-9]{32})[\"']",
    "Artifactory API Key": r"\bAKC[a-zA-Z0-9]{60,}\b",
    "Jenkins Token": r"11[a-f0-9]{30}",
    "Docker Registry Token": r"docker_token\s*[:=]\s*[a-zA-Z0-9\-]{20,}",
    "Jira API Token": r"ATATT[a-zA-Z0-9-_=]{100,}"
}


# =========================================================
# 🔧 RUN COMMAND
# =========================================================

# =========================================================
# 🌐 PASSIVE URL COLLECTION
# =========================================================
def collect_urls(domain, targets, paths, base_latency=5):
    """Collect JS-specific URLs via getJS. gau/waybackurls are handled by crawler.py."""
    print("[+] Collecting JS URLs (getJS)")

    med_timeout = get_tool_timeout(base_latency, "medium")

    # Use actual targets instead of just the root domain, if available
    input_targets = targets if targets else [f"https://{domain}"]
    fd, tmp_targets = tempfile.mkstemp()
    with os.fdopen(fd, 'w') as f:
        for t in input_targets:
            f.write(f"{t}\n")
            
    try:
        cmd = [
            GETJS,
            "--input", tmp_targets,
            "--complete",
            "--timeout", f"{med_timeout}s",
            "--threads", str(GETJS_THREADS)
        ]
        debug_path = f"{paths.get('base', '')}/debug.txt" if paths.get('base') else None
        getjs_urls = run_command(
            cmd,
            timeout=med_timeout * 2,
            cwd=paths['js'],
            debug_path=debug_path
        )
        getjs_urls = [u.strip() for u in getjs_urls if u.strip().startswith("http")]
    finally:
        if os.path.exists(tmp_targets):
            os.remove(tmp_targets)

    # Save standalone getJS output
    save_txt(f"{paths['js']}/getjs_raw.txt", getjs_urls)
    print(f"  [getJS] {len(getjs_urls)} URLs")

    return unique_list(getjs_urls)


# =========================================================
# 🕷️ ACTIVE CRAWLING
# =========================================================
def crawl_targets(targets, paths, base_latency=5):
    """Active crawl with katana for JS discovery. gospider is handled by crawler.py."""
    if not targets:
        return []

    print(f"[+] Crawling {len(targets)} targets (katana — JS-focused)...")

    heavy_timeout = get_tool_timeout(base_latency, "heavy")

    def crawl_single(t):
        return run_command(
            [
                KATANA, "-u", t, "-jc", "-kf", "all",
                "-ef", "png,jpg,gif,jpeg,svg,css,woff,woff2,ttf,ico", "-xhr",
                "-rl", "50", "-retry", "2",
                "-c", str(KATANA_THREADS), "-d", str(KATANA_DEPTH), "-silent", "-timeout", str(heavy_timeout)
            ],
            timeout=heavy_timeout * 2,
            cwd=paths['endpoints']
        )

    with ThreadPoolExecutor(max_workers=min(len(targets), 5)) as executor:
        results = list(executor.map(crawl_single, targets))

    urls = []
    for r in results:
        urls.extend(r)

    return unique_list(urls)


# =========================================================
# 📦 EXTRACT JS FILES
# =========================================================
def extract_js(urls):
    print("[+] Extracting JS files")
    js_files = []
    for u in urls:
        u_lower = u.lower()
        # Global Exclusion Filter (Strict)
        if any(bad in u_lower for bad in EXCLUDED_EXTENSIONS):
            continue
            
        # Binary/Archive Filter (Discovery only, skip download)
        if any(hve in u_lower for hve in HIGH_VALUE_EXTENSIONS):
            continue

        if ".js" in u_lower:
            js_files.append(u.split("?")[0])

    return unique_list(js_files)


# =========================================================
# 📥 DOWNLOAD JS FILES (FOR ANALYSIS)
# =========================================================
def download_js_files(js_urls, download_path, base_latency=5, domain=None):
    print(f"[+] Downloading {len(js_urls)} JS files for analysis...")
    
    if not js_urls:
        return []
        
    os.makedirs(download_path, exist_ok=True)
    med_timeout = get_tool_timeout(base_latency, "medium")

    # Discover subdomains from discovered JS URLs
    subdomains = set()
    for u in js_urls:
        try:
            parsed_u = urlparse(u)
            host = parsed_u.netloc.split(":")[0]
            if host and (not domain or is_valid_subdomain(host, domain)):
                subdomains.add(host)
        except Exception:
            pass
    subdomains = list(subdomains)
    
    # Save URLs to a temp file for httpx
    fd, tmp_urls = tempfile.mkstemp()
    with os.fdopen(fd, 'w') as f:
        for url in js_urls:
            f.write(f"{url}\n")
            
    try:
        # httpx -sr (save response) -srd (save response directory)
        cmd = [HTTPX, "-l", tmp_urls, "-sr", "-srd", download_path, "-silent", "-threads", str(HTTPX_THREADS), "-timeout", str(med_timeout)]
        run_command(cmd, cwd=os.path.dirname(download_path))

        # Save standalone discovered subdomains from direct extraction
        if subdomains:
            subjs_out = os.path.join(os.path.dirname(download_path), "subdomains_from_js_urls.txt")
            save_txt(subjs_out, subdomains)
            print(f"  [js_intel] {len(subdomains)} hostnames extracted from JS URLs")

        # -----------------------------------------------------------------
        # Run SUBJS on the same JS URL list to discover additional subdomains
        # -----------------------------------------------------------------
        if js_urls and is_tool_available(SUBJS):
            fd_subjs, tmp_subjs = tempfile.mkstemp()
            try:
                with os.fdopen(fd_subjs, 'w') as f_sub:
                    for u in js_urls:
                        f_sub.write(f"{u}\n")
                subjs_cmd = [SUBJS, "-l", tmp_subjs]
                subjs_res = run_command(subjs_cmd, timeout=30, cwd=os.path.dirname(download_path))
                subjs_domains = [line.strip() for line in subjs_res if line.strip()]
                if subjs_domains:
                    subjs_extra_out = os.path.join(os.path.dirname(download_path), "subdomains_from_subjs.txt")
                    save_txt(subjs_extra_out, subjs_domains)
                    print(f"  [subjs] {len(subjs_domains)} additional subdomains extracted from JS URLs")
                    # Merge with previously found subdomains, ensuring uniqueness
                    subdomains = list(set(subdomains + subjs_domains))
            finally:
                if os.path.exists(tmp_subjs):
                    os.remove(tmp_subjs)

        return subdomains
    finally:
        if os.path.exists(tmp_urls):
            os.remove(tmp_urls)


# =========================================================
# 🔗 ENDPOINT EXTRACTION (SMART)
# =========================================================
def extract_endpoints(download_path):
    print("[+] Extracting endpoints from downloaded JS (jsluice - BATCHED)")
    
    if not os.path.exists(download_path) or not os.listdir(download_path):
        return [], {}

    endpoints_map = {} 
    
    mapping = load_js_url_mapping(download_path)
    
    try:
        files = []
        for root, _, filenames in os.walk(download_path):
            for f in filenames:
                if f == "index.txt": continue
                files.append(os.path.join(root, f))
                
        if not files:
            return [], {}
            
        files_input = "\n".join(files)
        cmd = [JSLUICE, "urls", "-c", str(JSLUICE_THREADS)]
        from core.runner import run_command_with_input
        res_lines = run_command_with_input(cmd, input_data=files_input, cwd=os.path.dirname(download_path))
        
        for line in res_lines:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                url = data.get("url")
                source_path = data.get("filename", data.get("source", "unknown"))
                
                if url:
                    origin_url = get_remote_url(source_path, mapping)
                    if origin_url:
                        # If url is relative, make it absolute using the origin host
                        if not url.startswith("http"):
                            base_host = get_base_url(origin_url)
                            if url.startswith("/"):
                                url = base_host + url
                            else:
                                url = base_host + "/" + url
                    
                    if url not in endpoints_map:
                        endpoints_map[url] = []
                    
                    # Store the clean origin URL as the source instead of the local path
                    display_source = origin_url if origin_url else "unknown_source"
                    if display_source not in endpoints_map[url]:
                        endpoints_map[url].append(display_source)
            except:
                continue

    except Exception as e:
        print(f"[-] Error in extract_endpoints: {e}")

    return list(endpoints_map.keys()), endpoints_map


# =========================================================
# 🔑 SECRET DETECTION (LIGHT)
# =========================================================
def detect_secrets(download_path):
    print("[+] Detecting secrets in downloaded JS (jsluice - BATCHED + Deep Regex)")
    
    if not os.path.exists(download_path) or not os.listdir(download_path):
        return [], {}

    secrets_map = {}
    mapping = load_js_url_mapping(download_path)
    
    # 1. BATCHED jsluice scan
    try:
        files = []
        for root, _, filenames in os.walk(download_path):
            for f in filenames:
                if f == "index.txt": continue
                files.append(os.path.join(root, f))
                
        if files:
            files_input = "\n".join(files)
            cmd = [JSLUICE, "secrets", "-c", str(JSLUICE_THREADS)]
            from core.runner import run_command_with_input
            res_lines = run_command_with_input(cmd, input_data=files_input, cwd=os.path.dirname(download_path))
            for line in res_lines:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    secret = f"{data.get('kind')}: {data.get('data')}"
                    source_path = data.get("filename", data.get("source", "unknown"))
                    
                    if secret not in secrets_map:
                        secrets_map[secret] = []
                    
                    origin_url = get_remote_url(source_path, mapping)
                    display_source = origin_url if origin_url else "unknown_source"
                    if display_source not in secrets_map[secret]:
                        secrets_map[secret].append(display_source)
                except:
                    continue
    except Exception as e:
        print(f"[-] Error in detect_secrets jsluice: {e}")

    # 2. Deep Regex (controlled by DEEP_JS_SCAN setting)
    if not DEEP_JS_SCAN:
        print("  [!] DEEP_JS_SCAN disabled — skipping regex scan")
        return list(secrets_map.keys()), secrets_map

    def scan_file_regex(f_path):
        local_secrets = {}
        
        # Skip overly large files to prevent OOM / ReDoS (jsluice already covers them)
        try:
            if os.path.getsize(f_path) > 3 * 1024 * 1024:  # 3 MB limit for regex
                return local_secrets
        except:
            pass

        try:
            with open(f_path, 'r', errors='ignore') as f:
                content = f.read()
                
            # Chunk the content to avoid catastrophic backtracking on single-line minified files
            chunk_size = 100 * 1024
            overlap = 1024
            
            chunks = []
            if len(content) > chunk_size:
                for i in range(0, len(content), chunk_size - overlap):
                    chunks.append(content[i:i+chunk_size])
            else:
                chunks = [content]

            for chunk in chunks:
                for name, pattern in REGEX_PATTERNS.items():
                    matches = re.findall(pattern, chunk)
                    for m in matches:
                        if isinstance(m, tuple): m = m[1]
                        m_str = str(m).strip()
                        # Exclude obvious low-entropy / placeholder false positives
                        if not m_str or len(m_str) < 4 or len(set(m_str)) <= 2: continue
                        if m_str.lower() in ["undefined", "null", "true", "false", "your_api_key_here"]: continue
                        if name == "IP Address":
                            # Ignore network addresses ending in .0.0.0 or broadcast/invalid prefixes
                            if m_str.endswith(".0.0.0") or m_str.startswith("0.") or m_str.startswith("255."): continue
                        found = f"{name}: {m_str}"
                        if found not in local_secrets:
                            local_secrets[found] = []
                        origin_url = get_remote_url(f_path, mapping)
                        display_source = origin_url if origin_url else "unknown_source"
                        local_secrets[found].append(display_source)
        except:
            pass
        return local_secrets

    files = []
    for root, _, filenames in os.walk(download_path):
        for f in filenames:
            if f == "index.txt": continue
            files.append(os.path.join(root, f))

    with ThreadPoolExecutor(max_workers=JSLUICE_THREADS) as executor:
        regex_results = list(executor.map(scan_file_regex, files))

    for res in regex_results:
        for secret, paths in res.items():
            if secret not in secrets_map:
                secrets_map[secret] = []
            secrets_map[secret].extend(paths)
            secrets_map[secret] = list(set(secrets_map[secret]))

    return list(secrets_map.keys()), secrets_map


# =========================================================
# 🏗️ DOMAIN & SUBDOMAIN EXTRACTION (DEEP)
# =========================================================
def extract_js_intel(download_path, domain):
    print("[+] Deep Intelligence Extraction (Domains & API Routes)")
    
    if not os.path.exists(download_path) or not os.listdir(download_path):
        return [], [], []

    domains = []
    subdomains = []
    api_routes = []
    mapping = load_js_url_mapping(download_path)
    
    # Patterns for extraction
    domain_pattern = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')
    # Support standard API paths and dynamic parameters like /api/v1/user/:id, /api/v2/items/{itemId}, and template style /api/v3/cart/${cartId} or $cartId
    api_pattern = re.compile(
        r'/(?:api|v[0-9]|graphql|rest|v1|v2|v3|wp-json|api-v1|api-v2)/[a-zA-Z0-9\-\._~%+/]*?(?::[a-zA-Z0-9_]+|\{[a-zA-Z0-9_]+\}|\$[a-zA-Z0-9_]+|\$\{[a-zA-Z0-9_]+\}|[a-zA-Z0-9\-\._~%+/])*'
    )
    # Support typical frontend SPA routes like path: '/dashboard/:userId' or component routes
    route_pattern = re.compile(
        r'(?:path|route|url)\s*:\s*["\'`](/[a-zA-Z0-9\-\._~%+/:]*?(?::[a-zA-Z0-9_]+|\{[a-zA-Z0-9_]+\}|\$[a-zA-Z0-9_]+|\$\{[a-zA-Z0-9_]+\}|[a-zA-Z0-9\-\._~%+/])*)["\'`]'
    )

    def analyze_content(f_path):
        local_domains = []
        local_subdomains = []
        local_api = []
        try:
            with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Extract domains
                found_domains = domain_pattern.findall(content)
                for d in found_domains:
                    d = d.strip().lower()
                    if len(d) < 4: continue
                    if is_valid_subdomain(d, domain):
                        local_subdomains.append(d)
                    else:
                        local_domains.append(d)
                
                # Extract API routes and resolve to absolute URLs using the origin host
                origin_url = get_remote_url(f_path, mapping)
                base_host = get_base_url(origin_url) if origin_url else f"https://{domain}"
                
                # Extract standard/dynamic API routes
                for api in api_pattern.findall(content):
                    api = api.strip()
                    if api:
                        # Clean trailing brackets/colons if any captured accidentally
                        api = api.rstrip(':').rstrip('/')
                        local_api.append(f"{base_host}{api}")

                # Extract frontend routing definitions
                for route in route_pattern.findall(content):
                    route = route.strip()
                    if route and route.startswith('/'):
                        local_api.append(f"{base_host}{route}")
                
        except:
            pass
        return list(set(local_domains)), list(set(local_subdomains)), list(set(local_api))

    files = []
    for root, _, filenames in os.walk(download_path):
        for f in filenames:
            if f == "index.txt": continue
            files.append(os.path.join(root, f))

    with ThreadPoolExecutor(max_workers=JSLUICE_THREADS) as executor:
        results = list(executor.map(analyze_content, files))

    for d_list, sd_list, api_list in results:
        domains.extend(d_list)
        subdomains.extend(sd_list)
        api_routes.extend(api_list)

    return unique_list(domains), unique_list(subdomains), unique_list(api_routes)

# =========================================================
# 🧬 XNLINKFINDER (DEEP DISCOVERY)
# =========================================================
def run_xnlinkfinder(domain, js_files, paths, base_latency=5):
    print("[+] Running xnLinkFinder for deep discovery")
    
    if not js_files or not is_tool_available(XNLINKFINDER):
        return [], []

    js_list_file = f"{paths['js']}/js_list_tmp.txt"
    out_file = f"{paths['js']}/xn_links.txt"
    param_file = f"{paths['js']}/xn_params.txt"
    
    # Cap target list to top 150 JS files to ensure high performance
    capped_js = js_files[:150]
    with open(js_list_file, "w") as f:
        for js in capped_js:
            f.write(f"{js}\n")
            
    links = []
    params = []
    try:
        from modules.js_filter import reconstruct_corrupted_url, normalize_and_clean_endpoint
        req_timeout = max(5, min(15, base_latency * 2))
        cmd = [
            XNLINKFINDER, "-i", js_list_file, "-o", out_file, "-op", param_file,
            "-sf", domain, "-t", str(req_timeout), "-d", "2", "-nb"
        ]
        wall_timeout = max(180, get_tool_timeout(base_latency, "medium", item_count=len(capped_js)))
        run_command(cmd, timeout=wall_timeout, cwd=paths['js'], debug_path=f"{paths['base']}/debug.txt")

        
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                for line in f:
                    ep = line.strip()
                    if ep:
                        ep = reconstruct_corrupted_url(ep, domain)
                        ep = normalize_and_clean_endpoint(ep)
                        if not ep.startswith("http"):
                            if ep.startswith("/"):
                                ep = f"https://{domain}{ep}"
                            else:
                                ep = f"https://{domain}/{ep}"
                        links.append(ep)

        if os.path.exists(param_file):
            with open(param_file, 'r') as f:
                for line in f:
                    p = line.strip()
                    if p and not p.startswith("#"):
                        params.append(p)

        return unique_list(links), unique_list(params)
    except Exception as e:
        print(f"[-] Error in xnLinkFinder: {e}")
        return [], []
    finally:
        if os.path.exists(js_list_file):
            try: os.remove(js_list_file)
            except: pass


# =========================================================
# 🔎 ENDPOINT PROBE
# =========================================================
def probe_endpoints(endpoints, domain, paths, base_latency=5):
    print(f"[+] Probing {len(endpoints)} discovered endpoints for validity...")
    
    if not endpoints:
        return []
        
    med_timeout = get_tool_timeout(base_latency, "medium")
    
    tmp_in = f"{paths['js']}/tmp_endpoints.txt"
    tmp_out = f"{paths['js']}/probed_endpoints.json"
    
    # Filter to keep only those that look like full URLs for probing
    to_probe = []
    for ep in endpoints:
        if ep.startswith("http"):
            to_probe.append(ep)
        elif ep.startswith("/"):
            # Fallback if any relative paths leaked
            to_probe.append(f"https://{domain}{ep}")
            
    if not to_probe:
        return []
        
    save_txt(tmp_in, to_probe)
    
    try:
        # Fast probe with httpx
        cmd = [HTTPX, "-l", tmp_in, "-status-code", "-silent", "-threads", str(HTTPX_THREADS), "-json", "-o", tmp_out, "-timeout", str(med_timeout)]
        run_command(cmd, cwd=paths['js'])
        
        probed = []
        if os.path.exists(tmp_out):
            with open(tmp_out, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    probed.append({
                        "url": data.get("url"),
                        "status": data.get("status_code"),
                        "length": data.get("content_length")
                    })
        return probed
    except:
        return []
    finally:
        if os.path.exists(tmp_in): os.remove(tmp_in)


# =========================================================
# 🗺️ SOURCE MAP EXTRACTION (SOURCEMAPPER)
# =========================================================
def extract_source_maps(download_path, js_urls, paths, base_latency=5):
    if not SOURCEMAPPER_ENABLED or not is_tool_available(SOURCEMAPPER) or not js_urls:
        return []
        
    print("[+] Extracting JavaScript Source Maps (sourcemapper)")
    sm_dir = os.path.join(paths['js'], "sourcemaps")
    os.makedirs(sm_dir, exist_ok=True)
    
    extracted_sources = []
    med_timeout = get_tool_timeout(base_latency, "medium")
    
    map_urls = set()
    for url in js_urls:
        if url.endswith(".js"):
            map_urls.add(f"{url}.map")
        elif ".js?" in url:
            base_url = url.split("?")[0]
            map_urls.add(f"{base_url}.map")
            
    for m_url in list(map_urls)[:30]:
        try:
            target_name = urlparse(m_url).netloc + "_" + os.path.basename(m_url).replace(".map", "")
            out_target = os.path.join(sm_dir, target_name)
            cmd = [SOURCEMAPPER, "-jsurl", m_url, "-output", out_target]
            run_command(cmd, timeout=med_timeout, cwd=paths['js'])
            if os.path.exists(out_target) and os.listdir(out_target):
                extracted_sources.append(out_target)
        except Exception:
            pass
            
    print(f"  [sourcemapper] Reconstructed source code from {len(extracted_sources)} source map(s)")
    return extracted_sources

# =========================================================
# ⚡ JSLEAK (FAST SECRETS & LINKS SCANNER)
# =========================================================
def run_jsleak(js_urls, paths, base_latency=5):
    if not js_urls or not is_tool_available(JSLEAK):
        return [], []
        
    print("[+] Running jsleak on JS URLs...")
    med_timeout = get_tool_timeout(base_latency, "medium")
    
    found_links = []
    found_secrets = []
    
    try:
        urls_input = "\n".join(js_urls[:200])
        cmd = [JSLEAK, "-s", "-l", "-c", str(JSLEAK_THREADS)]
        from core.runner import run_command_with_input
        res_lines = run_command_with_input(cmd, input_data=urls_input, timeout=med_timeout * 2, cwd=paths['js'])
        
        for line in res_lines:
            line = line.strip()
            if not line: continue
            
            link_match = re.search(r"\[\+\] Found link:\s*\[(.*?)\]\s*in\s*\[(.*?)\]", line, re.IGNORECASE)
            if link_match:
                extracted = link_match.group(1).strip()
                if extracted: found_links.append(extracted)
                continue
                
            secret_match = re.search(r"\[\+\] Found (?:Secret|secret):\s*\[(.*?)\]\s*in\s*\[(.*?)\]", line, re.IGNORECASE)
            if secret_match:
                extracted_sec = secret_match.group(1).strip()
                src_url = secret_match.group(2).strip()
                if extracted_sec: found_secrets.append(f"{extracted_sec} [{src_url}]")
                continue
    except Exception as e:
        print(f"[-] Error in jsleak: {e}")
        
    return unique_list(found_links), unique_list(found_secrets)

# =========================================================
# 🔍 SUBDOMAINIZER (PYTHON SECRETS & SUBDOMAIN FINDER)
# =========================================================
def run_subdomainizer(domain, js_urls, paths, base_latency=5):
    if not js_urls or not is_tool_available(SUBDOMAINIZER):
        return [], [], []
        
    print("[+] Running SubDomainizer on JS URLs...")
    
    tmp_list = os.path.join(paths['js'], "subdomainizer_input.txt")
    out_sub_file = os.path.join(paths['js'], "subdomainizer_subs.txt")
    out_sec_file = os.path.join(paths['js'], "subdomainizer_sec.txt")
    out_cloud_file = os.path.join(paths['js'], "subdomainizer_cloud.txt")
    
    save_txt(tmp_list, js_urls[:50])
    
    out_subdomains = []
    out_secrets = []
    out_cloud = []
    
    try:
        cmd = [
            "python3", SUBDOMAINIZER,
            "-l", tmp_list,
            "-d", domain,
            "-o", out_sub_file,
            "-sop", out_sec_file,
            "-cop", out_cloud_file,
            "-k"
        ]
        timeout = get_tool_timeout(base_latency, "medium")
        run_command(cmd, timeout=timeout, cwd=paths['js'])
        
        if os.path.exists(out_sub_file):
            with open(out_sub_file, "r") as f:
                for line in f:
                    s = line.strip()
                    if s: out_subdomains.append(s)
                    
        if os.path.exists(out_sec_file):
            with open(out_sec_file, "r") as f:
                for line in f:
                    s = line.strip()
                    if s: out_secrets.append(s)
                    
        if os.path.exists(out_cloud_file):
            with open(out_cloud_file, "r") as f:
                for line in f:
                    s = line.strip()
                    if s: out_cloud.append(s)
    except Exception as e:
        print(f"[-] Error in SubDomainizer: {e}")
    finally:
        for fpath in [tmp_list, out_sub_file, out_sec_file, out_cloud_file]:
            if os.path.exists(fpath):
                try: os.remove(fpath)
                except: pass
            
    print(f"  [subdomainizer] Discovered {len(out_subdomains)} subdomains, {len(out_secrets)} secrets, {len(out_cloud)} cloud assets")
    return unique_list(out_subdomains), unique_list(out_secrets), unique_list(out_cloud)


# =========================================================
# 🗝️ SECRETFINDER (API KEYS & ACCESS TOKENS IN JS)
# =========================================================
def run_secretfinder(domain, js_urls, download_path, paths, base_latency=5):
    """
    Runs SecretFinder (/opt/secretfinder/SecretFinder.py) against discovered JavaScript files.
    Scans downloaded local JS files (fastest and most reliable) or prioritized JS URLs.
    Extracts secrets and sensitive tokens via CLI mode (-o cli).
    """
    if not is_tool_available(SECRETFINDER):
        return []

    print("[+] Running SecretFinder on JavaScript files...")
    med_timeout = get_tool_timeout(base_latency, "medium")
    sf_secrets = []
    out_file = os.path.join(paths['js'], "secretfinder_secrets.txt")

    # Collect target files to scan
    target_files = []
    if download_path and os.path.exists(download_path):
        for root, _, filenames in os.walk(download_path):
            for f in filenames:
                if f == "index.txt": continue
                target_files.append(os.path.join(root, f))

    mapping = load_js_url_mapping(download_path) if download_path and os.path.exists(download_path) else {}

    def _scan_single_file(fpath):
        found = []
        try:
            cmd = ["python3", SECRETFINDER, "-i", fpath, "-o", "cli"]
            res = run_command(cmd, timeout=med_timeout, cwd=paths['js'])
            origin_url = get_remote_url(fpath, mapping) if mapping else None
            source_tag = f" [{origin_url}]" if origin_url else f" [{os.path.basename(fpath)}]"
            for line in res:
                line_s = line.strip()
                if not line_s or line_s.startswith("[ + ]") or line_s.startswith("Usage:") or "RequestsDependencyWarning" in line_s:
                    continue
                if "\t->\t" in line_s:
                    parts = line_s.split("\t->\t", 1)
                    sec_type = parts[0].strip()
                    sec_val = parts[1].strip()
                    if sec_val:
                        found.append(f"{sec_type}: {sec_val}{source_tag}")
                elif "->" in line_s:
                    parts = line_s.split("->", 1)
                    sec_type = parts[0].strip()
                    sec_val = parts[1].strip()
                    if sec_val:
                        found.append(f"{sec_type}: {sec_val}{source_tag}")
        except Exception:
            pass
        return found

    # If local downloaded files exist, scan them in parallel
    if target_files:
        workers = min(10, os.cpu_count() or 4)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            batch_results = list(executor.map(_scan_single_file, target_files[:100]))
            for b in batch_results:
                sf_secrets.extend(b)
    elif js_urls:
        # Fallback to scanning remote JS URLs directly
        def _scan_url(url):
            found = []
            try:
                cmd = ["python3", SECRETFINDER, "-i", url, "-o", "cli"]
                res = run_command(cmd, timeout=med_timeout, cwd=paths['js'])
                for line in res:
                    line_s = line.strip()
                    if not line_s or line_s.startswith("[ + ]") or line_s.startswith("Usage:") or "RequestsDependencyWarning" in line_s:
                        continue
                    if "\t->\t" in line_s or "->" in line_s:
                        sep = "\t->\t" if "\t->\t" in line_s else "->"
                        parts = line_s.split(sep, 1)
                        sec_type = parts[0].strip()
                        sec_val = parts[1].strip()
                        if sec_val:
                            found.append(f"{sec_type}: {sec_val} [{url}]")
            except Exception:
                pass
            return found

        workers = min(8, os.cpu_count() or 4)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            batch_results = list(executor.map(_scan_url, js_urls[:50]))
            for b in batch_results:
                sf_secrets.extend(b)

    sf_secrets = unique_list(sf_secrets)
    save_txt(out_file, sf_secrets)
    print(f"  [secretfinder] Discovered {len(sf_secrets)} secrets in JavaScript")
    return sf_secrets


# =========================================================
# 🧠 MAIN JS ENUM
# =========================================================
def run_js_enum(domain, targets, paths, debug=False, base_latency=5, extra_js=None):
    print("\n[+] JavaScript Enumeration (INTELLIGENCE LAYER)\n")

    # 1. Passive URLs (getJS only — gau/waybackurls handled by crawler.py)
    passive_urls = collect_urls(domain, targets, paths, base_latency=base_latency)

    # 2. Active crawl
    crawled_urls = crawl_targets(targets, paths, base_latency=base_latency)

    # 3. Merge & Filter Scope
    all_urls = unique_list(passive_urls + crawled_urls)
    scoped_urls = filter_scope(all_urls, domain)

    # 4. Extract JS Files + merge any pre-collected JS from crawlers
    js_files = extract_js(scoped_urls)
    if extra_js:
        js_files = unique_list(js_files + extra_js)

    # Pre-filter JS files to avoid downloading 3rd party vendor libraries
    from modules.js_filter import filter_js_files
    clean_js_candidate, _ = filter_js_files(js_files)
    download_targets = clean_js_candidate if clean_js_candidate else js_files

    # 5. Download & Deep Extraction (with mapping)
    download_path = f"{paths['js']}/downloads"
    js_subdomains_from_urls = download_js_files(download_targets, download_path, base_latency=base_latency, domain=domain)
    
    endpoints, endpoints_map = extract_endpoints(download_path)
    secrets, secrets_map = detect_secrets(download_path)
    
    # NEW: Deep Intel Extraction
    ext_domains, int_subdomains, api_routes = extract_js_intel(download_path, domain)

    # NEW: Run Sourcemapper, JSLeak, SubDomainizer, and SecretFinder
    extracted_sourcemaps = extract_source_maps(download_path, js_files, paths, base_latency=base_latency)
    jsleak_links, jsleak_secrets = run_jsleak(js_files, paths, base_latency=base_latency)
    subdom_subdomains, subdom_secrets, subdom_cloud = run_subdomainizer(domain, js_files, paths, base_latency=base_latency)
    sf_secrets = run_secretfinder(domain, js_files, download_path, paths, base_latency=base_latency)

    all_subdomains = unique_list((js_subdomains_from_urls if js_subdomains_from_urls else []) + int_subdomains + subdom_subdomains)
    secrets = unique_list(secrets + jsleak_secrets + subdom_secrets + sf_secrets)

    # 6. Deep extraction (xnLinkFinder)
    xn_endpoints, xn_params = run_xnlinkfinder(domain, js_files, paths, base_latency=base_latency)
    # Combine all discovered endpoint sources
    combined = endpoints + xn_endpoints + api_routes + jsleak_links
    # Deduplicate while normalizing URLs
    endpoints = dedupe_endpoints(unique_list(combined))

    # Save discovered parameters from xnLinkFinder
    if xn_params:
        save_txt(f"{paths['js']}/xn_params.txt", xn_params)

    # Save Cloud assets discovered from JS
    if subdom_cloud:
        save_txt(f"{paths['js']}/cloud_assets_from_js.txt", subdom_cloud)

    # Filter endpoints to keep clean and in-scope before probing
    from modules.js_filter import filter_endpoints
    clean_endpoints_for_probing = filter_endpoints(endpoints, domain)

    # 7. Probe filtered discovered endpoints
    probed_results = probe_endpoints(clean_endpoints_for_probing, domain, paths, base_latency=base_latency)

    # 8. Intelligence Mapping
    intelligence = {
        "domain": domain,
        "files_count": len(js_files),
        "endpoints_count": len(endpoints),
        "secrets_count": len(secrets),
        "subdomains_count": len(all_subdomains),
        "external_domains_count": len(ext_domains),
        "probed_alive": len(probed_results),
        "mappings": {
            "endpoints": endpoints_map,
            "secrets": secrets_map,
            "subdomains": all_subdomains,
            "external_domains": ext_domains
        }
    }

    # SAVE RAW OUTPUT (Originals)
    save_txt(f"{paths['js']}/urls.txt", scoped_urls)
    save_txt(f"{paths['js']}/js_files.txt", js_files)
    save_txt(f"{paths['js']}/endpoints.txt", endpoints)
    save_txt(f"{paths['js']}/secrets.txt", secrets)
    save_txt(f"{paths['js']}/subdomains_from_js.txt", all_subdomains)
    save_txt(f"{paths['js']}/external_domains.txt", ext_domains)
    save_txt(f"{paths['js']}/api_routes.txt", api_routes)
    
    # SAVE CLEANED & ORGANIZED OUTPUT (Beside originals)
    save_txt(f"{paths['js']}/urls_internal.txt", clean_data(scoped_urls))
    save_txt(f"{paths['js']}/urls_external.txt", clean_data([u for u in all_urls if not is_valid_subdomain(u, domain)]))
    save_txt(f"{paths['js']}/js_files_clean.txt", clean_data(js_files))
    save_txt(f"{paths['js']}/endpoints_clean.txt", clean_data(endpoints))
    save_txt(f"{paths['js']}/secrets_clean.txt", clean_data(secrets))
    
    save_json(f"{paths['js']}/intelligence_map.json", intelligence)
    save_json(f"{paths['js']}/probed_results.json", probed_results)

    # ---------------------------------
    # 🎯 SCORE JS FILES
    # ---------------------------------
    js_scores = []
    # urlparse already imported at module level
    for js_url in js_files:
        try:
            parsed = urlparse(js_url)
            # httpx saves to <domain>/<path>
            match_str = f"{parsed.netloc}{parsed.path}".strip("/")
        except:
            match_str = js_url

        file_endpoints = 0
        file_secrets = 0

        # Count endpoints found in this file
        for ep, sources in endpoints_map.items():
            if any(match_str in src or src in match_str for src in sources):
                file_endpoints += 1

        # Count secrets found in this file
        for sec, sources in secrets_map.items():
            if any(match_str in src or src in match_str for src in sources):
                file_secrets += 1

        # Calculate score (0 if no intel)
        score = score_js(js_url, file_endpoints, file_secrets)
        if score > 0:
            js_scores.append({
                "url": js_url,
                "score": score,
                "endpoints": file_endpoints,
                "secrets": file_secrets
            })

    # Sort descending
    js_scores = sorted(js_scores, key=lambda x: x["score"], reverse=True)
    save_json(f"{paths['js']}/js_scores.json", js_scores)

    # Save readable scores
    with open(f"{paths['js']}/js_scores.txt", "w") as f:
        f.write(f"--- JS FILES RANKED BY INTELLIGENCE SCORE ---\n\n")
        for item in js_scores:
            f.write(f"[Score: {item['score']:>3}] {item['url']} (Endpoints: {item['endpoints']}, Secrets: {item['secrets']})\n")

    # 📝 SAVE DETAILED READABLE VERSIONS
    with open(f"{paths['js']}/secrets_detailed.txt", "w") as f:
        f.write(f"--- SECRETS DISCOVERED IN {domain} ---\n\n")
        for secret, sources in secrets_map.items():
            f.write(f"SECRET: {secret}\n")
            f.write(f"SOURCE: {', '.join(sources)}\n")
            f.write("-" * 30 + "\n")

    with open(f"{paths['js']}/endpoints_detailed.txt", "w") as f:
        f.write(f"--- ENDPOINTS DISCOVERED IN {domain} ---\n\n")
        for ep, sources in endpoints_map.items():
            f.write(f"ENDPOINT: {ep}\n")
            f.write(f"SOURCE:   {', '.join(sources)}\n")
            f.write("-" * 30 + "\n")

    # =========================================================
    # 📊 READABLE SUMMARY
    # =========================================================
    print("-" * 50)
    print(f"💎 JS INTELLIGENCE SUMMARY: {domain}")
    print("-" * 50)
    print("-" * 50)
    print(f"📂 JS Files Found:      {len(js_files)}")
    print(f"🔗 Unique Endpoints:    {len(endpoints)}")
    print(f"🔑 Secrets Discovered:   {len(secrets)}")
    print(f"🌐 JS Subdomains:       {len(all_subdomains)}")
    print(f"📦 External Domains:    {len(ext_domains)}")
    print(f"✅ Probed (Alive):      {len(probed_results)}")
    print("-" * 50)

    if secrets:
        print("\n🔥 TOP SECRETS FOUND:")
        for s in secrets[:10]: # Show top 10
            # Try to find which file it came from
            source = secrets_map.get(s, ["unknown"])[0]
            print(f"   → {s}  [{source}]")
        if len(secrets) > 10:
            print(f"   ... and {len(secrets) - 10} more (see secrets.txt)")

    print("-" * 50 + "\n")

    return js_files, endpoints, secrets, all_subdomains
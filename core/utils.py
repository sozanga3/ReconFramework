import os
import re
import requests
import time
import shutil
from config.settings import HTTPX_TIMEOUT, AMASS_TIMEOUT
from config.tools import CORE_TOOLS, OPTIONAL_TOOLS, ALL_TOOLS, is_tool_available

def is_valid_subdomain(subdomain, target_domain):
    """
    Checks if subdomain is equal to target_domain or is a strict subdomain of target_domain (e.g. sub.target.com).
    Prevents false positives like 'app.linde-mh.com' or 'bakamh.com' matching target 'mh.com'.
    """
    if not subdomain or not target_domain:
        return False
    sub = str(subdomain).strip().lower()
    target = str(target_domain).strip().lower().lstrip(".")
    
    # Strip protocols, credentials, ports, paths
    if "://" in sub:
        sub = sub.split("://", 1)[1]
    sub = sub.split("/")[0]
    if "@" in sub:
        sub = sub.split("@")[-1]
    sub = sub.split(":")[0]
    
    # Strip leading wildcards (*.sub.domain.com -> sub.domain.com)
    if sub.startswith("*."):
        sub = sub[2:]
    elif sub.startswith("*"):
        sub = sub[1:].lstrip(".")

    if not (sub == target or sub.endswith("." + target)):
        return False

    fqdn_regex = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
    return bool(fqdn_regex.match(sub))

def validate_tools():
    """
    Checks availability of core and optional tools.
    Returns a dict with 'core_missing' and 'optional_missing'.
    """
    core_missing = []
    optional_missing = []
    available = []

    for name, cmd in CORE_TOOLS.items():
        if is_tool_available(cmd):
            available.append(name)
        else:
            core_missing.append(name)

    for name, cmd in OPTIONAL_TOOLS.items():
        if is_tool_available(cmd):
            available.append(name)
        else:
            optional_missing.append(name)

    return {
        "core_missing": core_missing,
        "optional_missing": optional_missing,
        "available": available
    }

def print_tools_status():
    """
    Prints a formatted status table of all tools configured in the framework.
    """
    status = validate_tools()
    print("\n" + "=" * 65)
    print(" 🛠️  RECON FRAMEWORK - TOOL STATUS INSPECTION")
    print("=" * 65)
    print(f" {'TOOL':<20} | {'STATUS':<12} | {'PATH / RESOLUTION'}")
    print("-" * 65)
    
    for name, cmd in sorted(ALL_TOOLS.items()):
        avail = is_tool_available(cmd)
        status_label = "✅ AVAILABLE" if avail else "❌ MISSING"
        print(f" {name:<20} | {status_label:<12} | {cmd}")

    print("-" * 65)
    total = len(ALL_TOOLS)
    installed = len(status['available'])
    print(f" Total Tools: {total} | Ready: {installed} | Missing: {len(status['optional_missing']) + len(status['core_missing'])}")
    if status["core_missing"]:
        print(f" [!] CRITICAL MISSING: {', '.join(status['core_missing'])}")
    if status["optional_missing"]:
        print(f" [*] Optional Missing: {', '.join(status['optional_missing'])}")
    print("=" * 65 + "\n")

def get_dynamic_timeout(target_url):
    """
    Measures latency to a target and returns a recommended base timeout.
    """
    print(f"[*] Measuring target responsiveness for {target_url}...")
    try:
        start = time.time()
        # Fast HEAD request to check latency
        r = requests.head(target_url, timeout=10, allow_redirects=True)
        latency = time.time() - start
        
        # Calculate a conservative base latency (clamped between 2 and 10s)
        base_latency = max(2, min(10, int(latency)))
        print(f"    → Measured Latency: {latency:.2f}s | Base Latency Set: {base_latency}s")
        return base_latency
    except Exception:
        print(f"    [!] Responsive check failed, using safe base: 5s")
        return 5

def get_tool_timeout(base_latency, tool_type="medium", item_count=1):
    """
    Returns an ultra-safe, tool-specific timeout based on target responsiveness.
    Always returns values in SECONDS.
    """
    configs = {
        "fast":   {"multiplier": 2, "buffer": 30},   # subfinder, assetfinder
        "medium": {"multiplier": 3, "buffer": 60},   # httpx, probing
        "heavy":  {"multiplier": 5, "buffer": 180},  # katana, hakrawler, port scan
        "deep":   {"multiplier": 8, "buffer": 300}   # nuclei, large wordlists
    }
    
    cfg = configs.get(tool_type, configs["medium"])
    base_timeout = (base_latency * cfg["multiplier"]) + cfg["buffer"]
    scaling_multiplier = 1 + (max(0, item_count - 1) * 0.03) # +3% per extra item
    timeout = base_timeout * scaling_multiplier
    floor = 60 if tool_type in ["heavy", "deep"] else 30
    
    return int(max(floor, timeout))

def get_amass_timeout(base_latency, is_active=False):
    """
    Returns Amass timeout in MINUTES based on settings.py.
    """
    base_timeout = AMASS_TIMEOUT
    if is_active:
        base_timeout += 10
    return int(base_timeout)

def get_api_timeout(base_latency):
    """
    Returns a tight timeout for simple web API calls (like crt.sh).
    """
    return int(max(10, min(60, (base_latency * 2) + 15)))

def clean_domain_input(raw_domain):
    """
    Normalizes a domain input by stripping protocols, paths, ports, wildcards, and whitespace.
    E.g. 'https://sub.example.com:8080/test' -> 'sub.example.com'
         '*.example.com/' -> 'example.com'
    """
    if not raw_domain:
        return ""
    d = raw_domain.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = re.split(r'[/?#]', d)[0]
    if "@" in d:
        d = d.split("@")[-1]
    if ":" in d:
        d = d.split(":", 1)[0]
    d = d.lstrip(".*")
    return d.strip()

# =========================================================
# 🌐 URL RECONSTRUCTION & VALIDATION ENGINE
# =========================================================
from urllib.parse import urlparse, urlunparse

COMMON_HTTPS_PORTS = {443, 8443, 4443, 9443, 10443, 2053, 2083, 2087, 2096}
COMMON_HTTP_PORTS = {80, 8080, 8000, 8888, 8088, 8880, 2052, 2082, 2086, 2095, 3000, 5000}

def is_valid_url(url: str) -> bool:
    """
    Checks if a string is a well-formed HTTP or HTTPS URL with a valid host.
    """
    if not url or not isinstance(url, str):
        return False
    u = url.strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return False
    try:
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            return False
        netloc = parsed.netloc.split("@")[-1].split(":")[0].strip()
        if not netloc:
            return False
        # Disallow raw illegal characters in hostname
        if any(c in netloc for c in "{}[]|\\^<>'\"` \t\r\n"):
            return False
        return True
    except Exception:
        return False

def reconstruct_url(raw_item: str, default_domain: str = None, default_scheme: str = "https") -> str:
    """
    Reconstructs any URL fragment, relative path, host:port, or partial URL
    into a strictly valid, well-formed URL format (https://... or http://...).

    Examples:
        - '/api/v1/users' + 'target.com' -> 'https://target.com/api/v1/users'
        - 'api/v1/users' + 'target.com' -> 'https://target.com/api/v1/users'
        - '//target.com/path' -> 'https://target.com/path'
        - 'sub.target.com:8443' -> 'https://sub.target.com:8443'
        - 'sub.target.com:80' -> 'http://sub.target.com'
        - 'sub.target.com/api' -> 'https://sub.target.com/api'
        - '[PUBLIC] AWS S3: https://bucket.s3.amazonaws.com' -> 'https://bucket.s3.amazonaws.com'
        - 'https://sub.target.com//v1///test' -> 'https://sub.target.com/v1/test'
    """
    if not raw_item or not isinstance(raw_item, str):
        return ""

    item = raw_item.strip().strip("\"'<>`()[],;").strip()
    if not item:
        return ""

    # Extract URL if embedded in tool log text (e.g. "[PUBLIC] AWS S3: https://...", "-> https://...", "Found link: [http://...]")
    embedded_match = re.search(r'https?://[^\s"\'<>`\[\]]+', item)
    if embedded_match:
        item = embedded_match.group(0).rstrip(".,;)]}>\"'")

    # Normalize default base domain / origin
    base_scheme = default_scheme or "https"
    base_host = ""
    if default_domain:
        d_str = str(default_domain).strip()
        if "://" in d_str:
            try:
                p_base = urlparse(d_str)
                base_scheme = p_base.scheme or base_scheme
                base_host = p_base.netloc or ""
            except Exception:
                pass
        if not base_host:
            # Strip trailing slash or path from default_domain
            base_host = d_str.split("/")[0].strip()

    # Handle corrupted artifacts like xn_params.txt or http:///home/
    if "xn_params.txt" in item.lower():
        idx = item.lower().find("xn_params.txt")
        rel = item[idx + len("xn_params.txt"):].lstrip("/")
        target_h = base_host or "target.com"
        item = f"{base_scheme}://{target_h}/{rel}"
    elif item.lower().startswith("http:///home/") or item.lower().startswith(":////home/") or item.lower().startswith(":////"):
        if base_host and base_host in item.lower():
            idx = item.lower().find(base_host)
            rel = item[idx + len(base_host):].lstrip("/")
            item = f"{base_scheme}://{base_host}/{rel}"
        elif base_host:
            item = f"{base_scheme}://{base_host}"

    # Handle protocol-relative URLs (//example.com/path or ///example.com/path)
    if item.startswith("//"):
        item_trimmed = item.lstrip("/")
        first_seg = item_trimmed.split("/")[0].split("?")[0].split("#")[0]
        if "." in first_seg and not first_seg.endswith(".js") and not first_seg.endswith(".php") and not first_seg.endswith(".html"):
            item = f"{base_scheme}://{item_trimmed}"
        elif base_host:
            item = f"{base_scheme}://{base_host}/{item_trimmed}"
        else:
            item = f"{base_scheme}://{item_trimmed}"

    # If already starts with http:// or https://
    if item.startswith("http://") or item.startswith("https://"):
        try:
            parsed = urlparse(item)
            netloc = parsed.netloc.strip()
            # If netloc is empty (e.g. http:///path), use base_host
            if not netloc and base_host:
                netloc = base_host
            if not netloc:
                return ""

            # Clean path
            path = re.sub(r'/+', '/', parsed.path)
            if not path:
                path = ""
            elif path != "/":
                is_dir = path.endswith("/")
                parts = []
                for segment in path.split("/"):
                    if segment in ("", "."):
                        continue
                    elif segment == "..":
                        if parts:
                            parts.pop()
                    else:
                        parts.append(segment)
                path = "/" + "/".join(parts) + ("/" if is_dir and parts else "")

            # Normalize default ports
            if (parsed.scheme == "https" and netloc.endswith(":443")) or (parsed.scheme == "http" and netloc.endswith(":80")):
                netloc = netloc.rsplit(":", 1)[0]

            return urlunparse((parsed.scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))
        except Exception:
            return ""

    # Check if item starts with a slash or dot-slash (relative URL)
    if item.startswith("/") or item.startswith("./") or item.startswith("../"):
        if not base_host:
            return ""
        q_split = item.split("?", 1)
        path_part = q_split[0]
        q_part = ("?" + q_split[1]) if len(q_split) > 1 else ""

        # Normalize relative path
        is_dir = path_part.endswith("/")
        parts = []
        for segment in path_part.split("/"):
            if segment in ("", "."):
                continue
            elif segment == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(segment)
        clean_path = "/" + "/".join(parts) + ("/" if is_dir and parts else "")
        return f"{base_scheme}://{base_host}{clean_path}{q_part}"

    # First segment before slash, query, or hash
    first_segment = item.split("/")[0].split("?")[0].split("#")[0]

    # Check for host:port pattern
    if ":" in first_segment:
        h_part, p_part = first_segment.split(":", 1)
        if p_part.isdigit():
            port_num = int(p_part)
            chosen_scheme = "https" if port_num in COMMON_HTTPS_PORTS else ("http" if port_num in COMMON_HTTP_PORTS else base_scheme)
            rest_of_url = item[len(first_segment):]
            if not rest_of_url.startswith("/") and rest_of_url:
                rest_of_url = "/" + rest_of_url
            final_netloc = first_segment
            if (chosen_scheme == "https" and port_num == 443) or (chosen_scheme == "http" and port_num == 80):
                final_netloc = h_part
            return f"{chosen_scheme}://{final_netloc}{rest_of_url}"

    # Check if first_segment looks like an FQDN / domain name
    is_domain = False
    if "." in first_segment:
        ext = first_segment.rsplit(".", 1)[-1].lower()
        non_domain_extensions = {
            "js", "jsx", "ts", "tsx", "html", "htm", "php", "asp", "aspx", "jsp",
            "json", "xml", "txt", "css", "png", "jpg", "jpeg", "gif", "svg", "ico",
            "pdf", "doc", "docx", "zip", "tar", "gz", "map", "woff", "woff2", "ttf"
        }
        if ext not in non_domain_extensions:
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$', first_segment):
                is_domain = True

    if is_domain:
        rest_of_url = item[len(first_segment):]
        if rest_of_url and not rest_of_url.startswith("/"):
            rest_of_url = "/" + rest_of_url
        return f"{base_scheme}://{first_segment}{rest_of_url}"

    # If not a domain, treat as a relative path
    if base_host:
        q_split = item.split("?", 1)
        path_part = q_split[0]
        q_part = ("?" + q_split[1]) if len(q_split) > 1 else ""
        if not path_part.startswith("/"):
            path_part = "/" + path_part
        return f"{base_scheme}://{base_host}{path_part}{q_part}"

    return ""

def reconstruct_urls_list(items, default_domain=None, default_scheme="https", effective_domains=None):
    """
    Takes an iterable of raw items, reconstructs every valid URL,
    optionally filters by scope, and returns deduplicated list preserving order.
    """
    if not items:
        return []
    result = []
    seen = set()

    norm_domains = []
    if effective_domains:
        norm_domains = [d.strip().lower().lstrip(".") for d in effective_domains if d and d.strip()]
    elif default_domain:
        d_clean = clean_domain_input(default_domain)
        if d_clean:
            norm_domains = [d_clean]

    for item in items:
        if not item:
            continue
        url = reconstruct_url(item, default_domain=default_domain, default_scheme=default_scheme)
        if not url or not is_valid_url(url):
            continue
        if norm_domains:
            try:
                host = urlparse(url).netloc.split(":")[0].lower()
                if not any(is_valid_subdomain(host, d) for d in norm_domains):
                    continue
            except Exception:
                continue
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result
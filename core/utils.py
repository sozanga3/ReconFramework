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
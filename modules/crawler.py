import subprocess
import os
import re
import requests
import concurrent.futures
from config.settings import (
    KATANA_THREADS, KATANA_DEPTH, KATANA_RATE_LIMIT, EXCLUDED_EXTENSIONS,
    HAKRAWLER_DEPTH, HAKRAWLER_THREADS,
    GAU_THREADS, GOSPIDER_DEPTH, GOSPIDER_THREADS,
    WAYMORE_TIMEOUT
)
from config.tools import (
    KATANA, HAKRAWLER, GAU, WAYBACKURLS, GOSPIDER, WAYMORE, URLFINDER, is_tool_available
)
from core.utils import get_tool_timeout
from core.output import save_txt, unique_list, debug_log
from core.runner import run_command, run_command_with_input
from core.filter import filter_urls_multi_domain

def run_katana(targets, paths, debug=False, base_latency=5, rate_limit=None, all_domains=None):
    if not targets or not is_tool_available(KATANA):
        return [], []
    print("\n[+] Running Katana (Active Spidering)")
        
    ep_raw_dir = paths.get('endpoints_raw', paths['endpoints'])
    input_file = f"{ep_raw_dir}/katana_targets.txt"
    output_file = f"{ep_raw_dir}/katana_raw.txt"
    
    save_txt(input_file, targets)
    
    rl = rate_limit if rate_limit else KATANA_RATE_LIMIT
    
    # Run Katana headless with settings
    timeout = get_tool_timeout(base_latency, "heavy", item_count=len(targets))
    cmd = [
        KATANA, "-list", input_file, "-jc", "-kf", "all",
        "-ef", "png,jpg,gif,jpeg,svg,css,woff,woff2,ttf,ico", "-xhr",
        "-rl", str(rl), "-retry", "2",
        "-c", str(KATANA_THREADS), "-d", str(KATANA_DEPTH), "-silent", "-o", output_file
    ]
    run_command(cmd, timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=ep_raw_dir)
    
    js_files = set()
    endpoints = set()
    
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                
                # Global Exclusion Filter
                if any(bad in url.lower() for bad in EXCLUDED_EXTENSIONS):
                    continue

                if url.endswith(".js") or ".js?" in url:
                    js_files.add(url)
                else:
                    endpoints.add(url)

    # 🌐 Scope filter — drop URLs not belonging to any scanned domain
    effective_domains = all_domains
    if not effective_domains and targets:
        from core.filter import _url_host
        effective_domains = list(set(_url_host(t) for t in targets if _url_host(t)))
    if effective_domains:
        js_files = set(filter_urls_multi_domain(list(js_files), effective_domains))
        endpoints = set(filter_urls_multi_domain(list(endpoints), effective_domains))
                    
    print(f"[+] Katana found {len(js_files)} JS files and {len(endpoints)} active endpoints")
    
    # 📝 SAVE HUMAN-READABLE REPORT
    with open(f"{ep_raw_dir}/katana_report.txt", "w") as f:
        f.write(f"🕷️ KATANA CRAWL REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"📂 JS Files: {len(js_files)}\n")
        f.write(f"🔗 Endpoints: {len(endpoints)}\n")
        f.write("-" * 60 + "\n")
        for ep in sorted(list(endpoints))[:50]: # Top 50
            f.write(f"• {ep}\n")
    
    return list(js_files), list(endpoints)

def run_hakrawler(targets, paths, debug=False, base_latency=5, all_domains=None):
    if not targets or not is_tool_available(HAKRAWLER):
        return [], []
    print("\n[+] Running Hakrawler (Fast Spidering)")
        
    ep_raw_dir = paths.get('endpoints_raw', paths['endpoints'])
    input_file = f"{ep_raw_dir}/hakrawler_targets.txt"
    output_file = f"{ep_raw_dir}/hakrawler_raw.txt"
    
    save_txt(input_file, targets)
    
    # Run hakrawler reading from input_file
    timeout = get_tool_timeout(base_latency, "heavy", item_count=len(targets))
    input_data = "\n".join(targets) + "\n"
    cmd = [HAKRAWLER, "-d", str(HAKRAWLER_DEPTH), "-t", str(HAKRAWLER_THREADS), "-u"]
    lines = run_command_with_input(cmd, input_data, timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=ep_raw_dir)
    save_txt(output_file, lines)
    
    js_files = set()
    endpoints = set()
    
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                
                # Global Exclusion Filter
                if any(bad in url.lower() for bad in EXCLUDED_EXTENSIONS):
                    continue

                if url.endswith(".js") or ".js?" in url:
                    js_files.add(url)
                else:
                    endpoints.add(url)

    # 🌐 Scope filter — drop URLs not belonging to any scanned domain
    effective_domains = all_domains
    if not effective_domains and targets:
        from core.filter import _url_host
        effective_domains = list(set(_url_host(t) for t in targets if _url_host(t)))
    if effective_domains:
        js_files = set(filter_urls_multi_domain(list(js_files), effective_domains))
        endpoints = set(filter_urls_multi_domain(list(endpoints), effective_domains))
                    
    print(f"[+] Hakrawler found {len(js_files)} JS files and {len(endpoints)} active endpoints")
    
    # 📝 SAVE HUMAN-READABLE REPORT
    with open(f"{ep_raw_dir}/hakrawler_report.txt", "w") as f:
        f.write(f"🕷️ HAKRAWLER CRAWL REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"📂 JS Files: {len(js_files)}\n")
        f.write(f"🔗 Endpoints: {len(endpoints)}\n")
        f.write("-" * 60 + "\n")
        for ep in sorted(list(endpoints))[:50]: # Top 50
            f.write(f"• {ep}\n")
    
    return list(js_files), list(endpoints)


# =========================================================
# 📡 PASSIVE URL COLLECTION — gau, waybackurls, gospider
# =========================================================

def _is_wayback_online(timeout=5):
    """Quick connectivity check for the Wayback Machine CDX API."""
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx?url=example.com&limit=1&output=json",
            timeout=timeout
        )
        # If we get HTML back (offline page) or non-200, treat as offline
        return r.status_code == 200 and r.text.strip().startswith("[")
    except Exception:
        return False

def _run_gau(domain, paths, base_latency=5):
    """Fetch archived URLs from AlienVault OTX, URLScan, Common Crawl, and Wayback via gau."""
    if not is_tool_available(GAU):
        return []
    output_file = f"{paths['endpoints']}/gau_raw.txt"
    timeout = get_tool_timeout(base_latency, "deep")

    # Build provider list — skip wayback if it's offline to avoid hanging/missing data
    all_providers = ["otx", "urlscan", "commoncrawl", "wayback"]
    if not _is_wayback_online():
        print("  [!] Wayback Machine offline — skipping wayback provider in gau")
        all_providers = [p for p in all_providers if p != "wayback"]
    providers_str = ",".join(all_providers)

    cmd = [
        GAU,
        "--threads", str(GAU_THREADS),
        "--providers", providers_str,
        "--subs",
        "--timeout", "30",
        "--retries", "2",
        "--blacklist", "png,jpg,gif,css,woff,svg",
        domain
    ]
    lines = run_command(cmd, timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=paths['endpoints'])
    lines = [l for l in lines if l.startswith("http")]
    save_txt(output_file, lines)
    print(f"  [gau]          {len(lines)} URLs")
    return lines


def _run_waybackurls(domain, paths, base_latency=5):
    """Fetch archived URLs from the Wayback Machine via waybackurls.

    Performs a fast CDX connectivity check before running to avoid silent
    zero-result failures when the Wayback Machine is offline or rate-limiting.
    """
    if not is_tool_available(WAYBACKURLS):
        return []
    output_file = f"{paths['endpoints']}/waybackurls_raw.txt"

    # Pre-flight: check if Wayback CDX API is reachable
    if not _is_wayback_online():
        print("  [!] Wayback Machine is currently offline — skipping waybackurls")
        return []

    # The Wayback CDX API can be very slow (~18-30s response times).
    # Give waybackurls enough time to complete its queries.
    timeout = max(120, get_tool_timeout(base_latency, "deep"))
    cmd = [WAYBACKURLS]
    lines = run_command_with_input(cmd, f"{domain}\n", timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=paths['endpoints'])
    lines = [l for l in lines if l.startswith("http")]
    save_txt(output_file, lines)
    print(f"  [waybackurls]  {len(lines)} URLs")
    return lines


def _run_gospider(targets, paths, base_latency=5):
    """Active-crawl top targets with gospider and extract all discovered URLs."""
    if not targets or not is_tool_available(GOSPIDER):
        return []
    output_file = f"{paths['endpoints']}/gospider_raw.txt"
    input_file  = f"{paths['endpoints']}/gospider_targets.txt"

    # We scan all passed targets (limit is handled upstream in main.py)
    capped = targets
    save_txt(input_file, capped)

    timeout = get_tool_timeout(base_latency, "heavy", item_count=len(capped))
    cmd = [GOSPIDER, "-S", input_file, "-d", str(GOSPIDER_DEPTH), "-t", str(GOSPIDER_THREADS), "-m", "15"]
    raw_lines = run_command(cmd, timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=paths['endpoints'])

    # gospider output can be "[url] - https://..." or plain URLs — extract with regex
    all_urls = []
    for line in raw_lines:
        found = re.findall(r'https?://[^\s\]"\'>]+', line)
        all_urls.extend(found)

    save_txt(output_file, all_urls)
    print(f"  [gospider]     {len(all_urls)} URLs")
    return all_urls


def _run_waymore(domain, paths, base_latency=5):
    """Fetch archived URLs from multiple provider sources via waymore."""
    if not is_tool_available(WAYMORE):
        return []
    output_file = f"{paths['endpoints']}/waymore_raw.txt"
    timeout = max(WAYMORE_TIMEOUT, get_tool_timeout(base_latency, "deep"))
    cmd = [WAYMORE, "-i", domain, "-mode", "U", "-n", "-oU", output_file, "-ow"]
    run_command(cmd, timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=paths['endpoints'])
    lines = []
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        with open(output_file, "r") as f:
            lines = [l.strip() for l in f if l.strip().startswith("http")]
        save_txt(output_file, lines)
    print(f"  [waymore]      {len(lines)} URLs")
    return lines


def _run_urlfinder(domain, paths, base_latency=5):
    """Fetch passive/crawled URLs via urlfinder."""
    if not is_tool_available(URLFINDER):
        return []
    output_file = f"{paths['endpoints']}/urlfinder_raw.txt"
    timeout = get_tool_timeout(base_latency, "deep")
    cmd = [URLFINDER, "-d", domain, "-silent"]
    lines = run_command(cmd, timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=paths['endpoints'])
    lines = [l.strip() for l in lines if l.strip().startswith("http")]
    save_txt(output_file, lines)
    print(f"  [urlfinder]    {len(lines)} URLs")
    return lines


def run_url_collection(domain, targets, paths, base_latency=5, all_domains=None):
    """
    Orchestrate gau, waybackurls, gospider, waymore, and urlfinder in parallel.
    Returns (js_files, endpoints) deduplicated and filtered.
    """
    print("\n[+] Passive URL Collection (gau | waybackurls | gospider | waymore | urlfinder)")

    # Run all five tools concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        fut_gau = pool.submit(_run_gau,         domain,  paths, base_latency)
        fut_wb  = pool.submit(_run_waybackurls,  domain,  paths, base_latency)
        fut_gs  = pool.submit(_run_gospider,     targets, paths, base_latency)
        fut_wm  = pool.submit(_run_waymore,      domain,  paths, base_latency)
        fut_uf  = pool.submit(_run_urlfinder,    domain,  paths, base_latency)

        gau_urls = fut_gau.result()
        wb_urls  = fut_wb.result()
        gs_urls  = fut_gs.result()
        wm_urls  = fut_wm.result()
        uf_urls  = fut_uf.result()

    all_raw  = unique_list(gau_urls + wb_urls + gs_urls + wm_urls + uf_urls)

    # 🌐 Scope filter — drop URLs not belonging to any scanned domain
    if all_domains:
        all_raw = filter_urls_multi_domain(all_raw, all_domains)

    js_files  = set()
    endpoints = set()

    for url in all_raw:
        if not url.startswith("http"):
            continue
        # Global exclusion filter
        if any(bad in url.lower() for bad in EXCLUDED_EXTENSIONS):
            continue
        if url.endswith(".js") or ".js?" in url:
            js_files.add(url)
        else:
            endpoints.add(url)

    # ── Save outputs ──────────────────────────────────────────
    ep_raw_dir = paths.get('endpoints_raw', paths['endpoints'])
    save_txt(f"{ep_raw_dir}/passive_urls.txt",      list(js_files | endpoints))
    save_txt(f"{ep_raw_dir}/passive_endpoints.txt", list(endpoints))
    save_txt(f"{ep_raw_dir}/passive_js.txt",        list(js_files))

    # ── Human-readable report ─────────────────────────────────
    with open(f"{ep_raw_dir}/passive_url_report.txt", "w") as f:
        f.write("📡 PASSIVE URL COLLECTION REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write("🔍 Source Breakdown:\n")
        f.write(f"  • gau:          {len(gau_urls)} URLs\n")
        f.write(f"  • waybackurls:  {len(wb_urls)} URLs\n")
        f.write(f"  • gospider:     {len(gs_urls)} URLs\n")
        f.write(f"  • waymore:      {len(wm_urls)} URLs\n")
        f.write(f"  • urlfinder:    {len(uf_urls)} URLs\n")
        f.write(f"\n📊 After Dedup & Filter:\n")
        f.write(f"  • JS Files:     {len(js_files)}\n")
        f.write(f"  • Endpoints:    {len(endpoints)}\n")
        f.write("\n" + "-" * 60 + "\n")
        f.write("🔗 Sample Endpoints (top 50):\n")
        for ep in sorted(list(endpoints))[:50]:
            f.write(f"  • {ep}\n")

    print(f"[+] Merged → {len(js_files)} JS files + {len(endpoints)} endpoints (saved to passive_urls.txt)")

    return list(js_files), list(endpoints)

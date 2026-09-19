import os
import json
from datetime import datetime
from config.settings import DEBUG_MODE

# ----------------------------
# 📁 CREATE DIRECTORY STRUCTURE
# ----------------------------
def create_output_structure(domain, base_path=None):
    if base_path:
        base = os.path.abspath(f"{base_path}/{domain}")
    else:
        base = os.path.abspath(f"output/{domain}")

    paths = {
        "base": base,
        "subdomains": f"{base}/subdomains",
        "subdomains_raw": f"{base}/subdomains/raw",
        "subdomains_dns": f"{base}/subdomains/active_dns",
        "subdomains_active": f"{base}/subdomains/active_dns",
        "httpx": f"{base}/httpx",
        "js": f"{base}/js",
        "params": f"{base}/params",
        "params_vuln": f"{base}/params/vuln_candidates",
        "fuzzing": f"{base}/fuzzing",
        "fuzzing_403": f"{base}/fuzzing/403_bypass",
        "endpoints": f"{base}/endpoints",
        "endpoints_raw": f"{base}/endpoints/raw_crawls",
        "ports": f"{base}/ports",
        "cloud": f"{base}/cloud",
        "screenshots": f"{base}/screenshots"
    }

    for path in paths.values():
        os.makedirs(path, exist_ok=True)

    return paths


# ----------------------------
# 💾 SAVE TEXT
# ----------------------------
def save_txt(path, data):
    with open(path, "w") as f:
        if data:
            for line in data:
                line_str = str(line).strip()
                if line_str:
                    f.write(line_str + "\n")



# ----------------------------
# 💾 SAVE JSON
# ----------------------------
def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


# ----------------------------
# 📊 GENERATE SUMMARY
# ----------------------------
def generate_summary(domain, paths, stats):
    summary_path = f"{paths['base']}/summary.txt"

    with open(summary_path, "w") as f:
        f.write(f"🎯 RECON INTELLIGENCE SUMMARY REPORT: {domain}\n")
        f.write("=" * 60 + "\n")
        f.write(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write("📊 QUANTITATIVE ASSET METRICS\n")
        f.write("-" * 30 + "\n")
        f.write(f"🔹 Unique Subdomains:    {stats.get('subdomains', 0)}\n")
        f.write(f"🔹 Open Ports Found:     {stats.get('ports', 0)}\n")
        f.write(f"🔹 Alive HTTP Hosts:    {stats.get('alive', 0)}\n")
        f.write(f"🔹 JS Files Discovered: {stats.get('js_files', 0)}\n")
        f.write(f"🔹 Unique Endpoints:    {stats.get('endpoints', 0)}\n")
        f.write(f"🔹 Discovered Secrets:  {stats.get('secrets', 0)}\n")
        f.write(f"🔹 Discovered Params:   {stats.get('params', 0)}\n")
        f.write(f"🔹 Cloud Storage Assets:{stats.get('cloud_assets', 0)}\n")
        f.write(f"🔹 Vulnerability Hits:  {stats.get('nuclei', 0)}\n\n")

        # SPECIALIZED RECON TOOL METRICS
        tools = stats.get("tool_metrics", {})
        if tools:
            f.write("🛠️ SPECIALIZED RECON TOOL METRICS\n")
            f.write("-" * 30 + "\n")
            f.write(f"🔹 SecretFinder (JS Secrets):     {tools.get('secretfinder', 0)}\n")
            f.write(f"🔹 ParamSpider (Discovered URLs): {tools.get('paramspider', 0)}\n")
            f.write(f"🔹 Arjun (Hidden Parameters):    {tools.get('arjun', 0)}\n")
            f.write(f"🔹 x8 (Fast Parameter Mining):   {tools.get('x8', 0)}\n")
            f.write(f"🔹 Kiterunner (API Routes):      {tools.get('kiterunner', 0)}\n")
            f.write(f"🔹 GitHub Endpoints:             {tools.get('github_endpoints', 0)}\n")
            f.write(f"🔹 GitHub Secrets:               {tools.get('github_secrets', 0)}\n\n")

        safety = stats.get("safety", {})
        if safety:
            f.write("🛡️ SAFETY & RISK PROFILE\n")
            f.write("-" * 30 + "\n")
            f.write(f"Recommendation: {safety.get('recommendation', 'UNKNOWN').upper()}\n")
            f.write(f"WAF Detection Ratio: {safety.get('waf_ratio', 0)*100:.0f}%\n")
            if safety.get("wafs"):
                f.write(f"Detected WAFs:       {', '.join(safety.get('wafs'))}\n")
            f.write("\n")

        # PARAMETER CATEGORY BREAKDOWN
        param_counts = stats.get("param_categories", {})
        if param_counts:
            f.write("🎯 VULNERABLE PARAMETER CANDIDATES\n")
            f.write("-" * 30 + "\n")
            f.write(f"🔹 XSS Candidates:  {param_counts.get('xss', 0)}\n")
            f.write(f"🔹 SSRF Candidates: {param_counts.get('ssrf', 0)}\n")
            f.write(f"🔹 SQLi Candidates: {param_counts.get('sqli', 0)}\n")
            f.write(f"🔹 LFI Candidates:  {param_counts.get('lfi', 0)}\n")
            f.write(f"🔹 IDOR Candidates: {param_counts.get('idor', 0)}\n\n")

        if stats.get("nuclei", 0) > 0:
            f.write("🔥 VULNERABILITIES FOUND (NUCLEI)\n")
            f.write("-" * 30 + "\n")
            results_file = f"{paths['fuzzing']}/nuclei_results.txt"
            if os.path.exists(results_file):
                with open(results_file, "r") as nf:
                    for line in nf.readlines()[:20]: # Top 20
                        f.write(f"• {line.strip()}\n")
            f.write("\n")

        f.write("🚀 TOP PRIORITIZED TARGETS\n")
        f.write("-" * 30 + "\n")
        top_targets = stats.get("top_targets", [])
        if top_targets:
            for i, t in enumerate(top_targets[:15], 1):
                f.write(f"{i}. {t}\n")
        else:
            f.write("No high-value targets identified.\n")

        f.write("\n📂 OUTPUT DIRECTORY\n")
        f.write("-" * 30 + "\n")
        f.write(f"Location: {os.path.abspath(paths['base'])}\n")
        f.write("\n" + "=" * 60 + "\n")
        f.write("Recon Complete.\n")


# ----------------------------
# 🧹 CLEAN + UNIQUE
# ----------------------------
def unique_list(data):
    if not data:
        return []
    return sorted(list(set(data)))


def clean_data(data):
    """
    Remove empty lines, strip whitespace, and normalize data.
    """
    if not data:
        return []
        
    cleaned = []
    for item in data:
        if item:
            item = str(item).strip()
            if item:
                cleaned.append(item)
                
    return sorted(list(set(cleaned)))


# ----------------------------
# 🧠 FILTER IN-SCOPE
# ----------------------------
from core.utils import is_valid_subdomain

def filter_scope(urls, domain):
    return [u for u in urls if is_valid_subdomain(u, domain)]


def debug_log(message, path=None):
    """
    Log debug message using central logger and optionally save to file.
    """
    from core.logger import get_logger
    logger = get_logger()
    if not DEBUG_MODE:
        return
    logger.debug(message)
    if path:
        try:
            with open(path, "a") as f:
                f.write(message + "\n")
        except Exception:
            pass
import re
import os
from core.output import save_txt, unique_list, debug_log
from config.api_keys import GITHUB_TOKEN
from config.tools import GITHUB_SUBDOMAINS, GITHUB_ENDPOINTS, GITHUB_SECRETS, is_tool_available
from core.runner import run_command, run_command_shell
from core.utils import is_valid_subdomain

# =========================================================
# 🐙 GITHUB RECON MODULE (DEEP DISCOVERY)
# =========================================================

def run_cmd(cmd_list, debug_path=None, timeout=300, cwd=None):
    if not GITHUB_TOKEN or GITHUB_TOKEN == "YOUR_GITHUB_TOKEN":
        return []
    return run_command(cmd_list, timeout=timeout, debug_path=debug_path, cwd=cwd)


def github_subdomains(domain, paths):
    """
    Finds subdomains on GitHub.
    """
    if not GITHUB_TOKEN or not is_tool_available(GITHUB_SUBDOMAINS):
        return []
    print(f"[+] Running github-subdomains for {domain}")
    cmd = ["python3", GITHUB_SUBDOMAINS, "-d", domain, "-t", GITHUB_TOKEN]
    raw_results = run_cmd(cmd, debug_path=f"{paths['base']}/debug.txt", cwd=paths['subdomains'])
    
    cleaned = []
    for line in raw_results:
        line_s = line.strip()
        if not line_s or "RequestsDependencyWarning" in line_s or line_s.startswith("[-]"):
            continue
        if is_valid_subdomain(line_s, domain):
            cleaned.append(line_s)
            
    cleaned = unique_list(cleaned)
    save_txt(f"{paths['subdomains']}/github_subdomains.txt", cleaned)
    print(f"  [github-subdomains] Discovered {len(cleaned)} subdomains on GitHub")
    return cleaned


def github_endpoints(domain, paths):
    """
    Finds endpoints/URLs on GitHub.
    """
    if not GITHUB_TOKEN or not is_tool_available(GITHUB_ENDPOINTS):
        return []
    print(f"[+] Running github-endpoints for {domain}")
    cmd = ["python3", GITHUB_ENDPOINTS, "-d", domain, "-t", GITHUB_TOKEN]
    raw_results = run_cmd(cmd, debug_path=f"{paths['base']}/debug.txt", cwd=paths['js'])
    
    cleaned = []
    for line in raw_results:
        line_s = line.strip()
        if not line_s or "RequestsDependencyWarning" in line_s or line_s.startswith("[-]"):
            continue
        if line_s.startswith("http://") or line_s.startswith("https://"):
            if is_valid_subdomain(line_s, domain):
                cleaned.append(line_s)
            
    cleaned = unique_list(cleaned)
    save_txt(f"{paths['js']}/github_endpoints.txt", cleaned)
    print(f"  [github-endpoints] Discovered {len(cleaned)} endpoints on GitHub")
    return cleaned


def github_secrets(domain, paths):
    """
    Searches for secrets related to the domain on GitHub.
    Streams output directly to disk to ensure partial findings are never lost
    even if the search hits GitHub API rate limits or connection timeouts.
    """
    if not GITHUB_TOKEN or not is_tool_available(GITHUB_SECRETS):
        return []
    print(f"[+] Running github-secrets for {domain}")
    raw_out = f"{paths['js']}/github_secrets_raw.txt"
    out_file = f"{paths['js']}/github_secrets.txt"
    
    # Run via shell redirection so stdout streams directly to disk
    cmd_str = f"python3 {GITHUB_SECRETS} -s {domain} -t {GITHUB_TOKEN} > {raw_out} 2>&1"
    run_command_shell(cmd_str, timeout=300, debug_path=f"{paths['base']}/debug.txt", cwd=paths['js'])
    
    parsed_secrets = []
    current_url = ""
    
    if os.path.exists(raw_out):
        try:
            with open(raw_out, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_s = line.strip()
                    if not line_s or "RequestsDependencyWarning" in line_s or line_s.startswith("[-]"):
                        continue
                    if line_s.startswith(">>> "):
                        current_url = line_s.replace(">>> ", "").strip()
                        continue
                    if current_url and line_s:
                        parsed_secrets.append(f"{line_s} [{current_url}]")
                    elif line_s:
                        parsed_secrets.append(line_s)
        except Exception:
            pass
            
    parsed_secrets = unique_list(parsed_secrets)
    save_txt(out_file, parsed_secrets)
        
    with open(f"{paths['js']}/github_report.txt", "w") as f:
        f.write(f"🐙 GITHUB RECON REPORT: {domain}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"🔑 Secrets Found: {len(parsed_secrets)}\n")
        f.write("-" * 60 + "\n")
        for r in parsed_secrets:
            f.write(f"• {r}\n")
            
    print(f"  [github-secrets] Discovered {len(parsed_secrets)} secrets on GitHub")
    return parsed_secrets

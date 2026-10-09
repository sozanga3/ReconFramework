import subprocess
import os
import re
from core.output import debug_log, save_txt, unique_list
from config.settings import NUCLEI_RATE_LIMIT, NUCLEI_CONCURRENCY, NUCLEI_RETRIES, NUCLEI_TIMEOUT
from core.utils import get_tool_timeout, reconstruct_url, reconstruct_urls_list, is_valid_url
from core.runner import run_command
from config.tools import NUCLEI, is_tool_available

# =========================================================
# 🚀 NUCLEI MODULE (SMART + LOW NOISE)
# =========================================================
def run_nuclei(domain, targets, paths, rate_limit=None, concurrency=None, debug=False, base_latency=5, bypass_waf=False, custom_headers=None):
    if not targets or not is_tool_available(NUCLEI):
        return []
    print("\n[+] Running Nuclei (Smart Scan)\n")

    # Ensure all targets are strictly valid URLs
    clean_targets = reconstruct_urls_list(targets, default_domain=domain)
    if not clean_targets:
        print("[-] No valid targets for Nuclei scan.")
        return []
    
    timeout = get_tool_timeout(base_latency, "deep")
    # Nuclei -timeout is per-request, usually much shorter (e.g. 5-10s)
    # We'll use a scaled per-request timeout
    req_timeout = max(5, min(15, base_latency * 2))
    
    # Use provided values or fall back to defaults from settings
    rl = rate_limit if rate_limit else NUCLEI_RATE_LIMIT
    cc = concurrency if concurrency else NUCLEI_CONCURRENCY

    # output files
    targets_file = f"{paths['fuzzing']}/nuclei_targets.txt"
    raw_results_file = f"{paths['fuzzing']}/nuclei_raw.txt"
    results_file = f"{paths['fuzzing']}/nuclei_results.txt"
    urls_file = f"{paths['fuzzing']}/nuclei_urls.txt"

    # save targets as pure URLs
    save_txt(targets_file, clean_targets)

    try:
        # ✅ SMART Nuclei command with direct output saving from settings
        cmd = [
            NUCLEI,
            "-l", targets_file,
            "-severity", "medium,high,critical",
            "-etags", "dos,fuzz,intrusive",
            "-rl", str(rl),
            "-c", str(cc),
            "-timeout", str(req_timeout),      # dynamic per-request timeout
            "-retries", str(NUCLEI_RETRIES),
            "-mhe", "10",
            "-silent",
            "-no-color",
            "-o", raw_results_file
        ]

        if bypass_waf:
            cmd.extend(["-H", "X-Forwarded-For: 127.0.0.1", "-H", "X-Originating-IP: 127.0.0.1"])

        if custom_headers:
            for header in custom_headers:
                cmd.extend(["-H", header])

        res_lines = run_command(
            cmd,
            timeout=min(NUCLEI_TIMEOUT, 3600),
            cwd=paths['fuzzing']
        )

        # ✅ Read raw results from file since nuclei saved them there
        raw_lines = []
        if os.path.exists(raw_results_file):
            with open(raw_results_file, "r") as f:
                raw_lines = [line.strip() for line in f if line.strip()]

        if debug:
            debug_log(f"nuclei results:\n{'\n'.join(res_lines)}", f"{paths['base']}/debug.txt")

        # Extract and reconstruct pure valid URLs from findings
        vuln_urls = []
        for line in raw_lines:
            match = re.search(r'https?://[^\s\]\)\'\"]+', line)
            if match:
                url_str = match.group(0).rstrip(']').rstrip(')')
                valid_u = reconstruct_url(url_str, default_domain=domain)
                if valid_u and is_valid_url(valid_u):
                    vuln_urls.append(valid_u)
            else:
                # If line contains an endpoint or path
                parts = line.split()
                for p in parts:
                    clean_p = p.strip("[](),'\"")
                    if clean_p.startswith("/") or "." in clean_p:
                        valid_u = reconstruct_url(clean_p, default_domain=domain)
                        if valid_u and is_valid_url(valid_u):
                            vuln_urls.append(valid_u)
                            break

        vuln_urls = unique_list(vuln_urls)
        # Save pure valid URLs to nuclei_results.txt and nuclei_urls.txt
        save_txt(results_file, vuln_urls)
        save_txt(urls_file, vuln_urls)

        # 📝 SAVE HUMAN-READABLE VULNERABILITY REPORT
        vuln_report = f"{paths['fuzzing']}/vulnerability_report.txt"
        with open(vuln_report, "w") as f:
            f.write(f"🛡️ VULNERABILITY REPORT: {domain}\n")
            f.write("=" * 60 + "\n\n")
            if not raw_lines:
                f.write("No vulnerabilities found (Medium/High/Critical severity).\n")
            else:
                f.write(f"🔥 Total Findings: {len(raw_lines)}\n")
                f.write(f"🌐 Vulnerable URLs: {len(vuln_urls)}\n")
                f.write("-" * 60 + "\n")
                for line in raw_lines:
                    f.write(f"• {line}\n")
            f.write("\n" + "=" * 60 + "\n")

        print(f"[+] Nuclei findings: {len(raw_lines)} ({len(vuln_urls)} unique URLs)")

        return vuln_urls

    except Exception as e:
        print(f"[!] Nuclei error: {e}")
        return []
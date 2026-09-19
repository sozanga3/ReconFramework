import subprocess
import os
from core.output import debug_log
from config.settings import NUCLEI_RATE_LIMIT, NUCLEI_CONCURRENCY, NUCLEI_RETRIES, NUCLEI_TIMEOUT
from core.utils import get_tool_timeout
from core.runner import run_command
from config.tools import NUCLEI, is_tool_available

# =========================================================
# 🚀 NUCLEI MODULE (SMART + LOW NOISE)
# =========================================================
def run_nuclei(domain, targets, paths, rate_limit=None, concurrency=None, debug=False, base_latency=5, bypass_waf=False):
    if not targets or not is_tool_available(NUCLEI):
        return []
    print("\n[+] Running Nuclei (Smart Scan)\n")
    
    timeout = get_tool_timeout(base_latency, "deep")
    # Nuclei -timeout is per-request, usually much shorter (e.g. 5-10s)
    # We'll use a scaled per-request timeout
    req_timeout = max(5, min(15, base_latency * 2))
    
    # Use provided values or fall back to defaults from settings
    rl = rate_limit if rate_limit else NUCLEI_RATE_LIMIT
    cc = concurrency if concurrency else NUCLEI_CONCURRENCY

    # output files
    targets_file = f"{paths['fuzzing']}/nuclei_targets.txt"
    results_file = f"{paths['fuzzing']}/nuclei_results.txt"

    # save targets
    with open(targets_file, "w") as f:
        for t in targets:
            f.write(t + "\n")

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
            "-o", results_file
        ]

        if bypass_waf:
            cmd.extend(["-H", "X-Forwarded-For: 127.0.0.1", "-H", "X-Originating-IP: 127.0.0.1"])

        res_lines = run_command(
            cmd,
            timeout=min(NUCLEI_TIMEOUT, 3600),
            cwd=paths['fuzzing']
        )

        # ✅ Read results from file since nuclei saved them there
        output_lines = []
        if os.path.exists(results_file):
            with open(results_file, "r") as f:
                output_lines = [line.strip() for line in f if line.strip()]

        if debug:
            debug_log(f"nuclei results:\n{'\n'.join(res_lines)}", f"{paths['base']}/debug.txt")

        # 📝 SAVE HUMAN-READABLE VULNERABILITY REPORT
        vuln_report = f"{paths['fuzzing']}/vulnerability_report.txt"
        with open(vuln_report, "w") as f:
            f.write(f"🛡️ VULNERABILITY REPORT: {domain}\n")
            f.write("=" * 60 + "\n\n")
            if not output_lines:
                f.write("No vulnerabilities found (Medium/High/Critical severity).\n")
            else:
                f.write(f"🔥 Total Findings: {len(output_lines)}\n")
                f.write("-" * 60 + "\n")
                for line in output_lines:
                    f.write(f"• {line}\n")
            f.write("\n" + "=" * 60 + "\n")

        print(f"[+] Nuclei findings: {len(output_lines)}")

        return output_lines

    except Exception as e:
        print(f"[!] Nuclei error: {e}")
        return []
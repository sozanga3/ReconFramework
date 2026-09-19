import subprocess
import os
from core.output import debug_log
from config.settings import GOWITNESS_THREADS
from config.tools import GOWITNESS, is_tool_available


# =========================================================
# 📸 SCREENSHOT MODULE (gowitness)
# =========================================================
def run_screenshots(targets, paths, debug=False):
    if not targets or not is_tool_available(GOWITNESS):
        return
    print("\n[+] Taking Screenshots (gowitness)\n")

    output_dir = f"{paths['base']}/screenshots"
    os.makedirs(output_dir, exist_ok=True)

    targets_file = f"{output_dir}/targets.txt"

    # save targets
    with open(targets_file, "w") as f:
        for t in targets:
            f.write(t + "\n")

    try:
        json_file = f"{output_dir}/gowitness.jsonl"
        zip_file = f"{paths['base']}/screenshots_report.zip"

        cmd = [
            GOWITNESS,
            "scan", "file",
            "-f", targets_file,
            "-s", output_dir,
            "--threads", str(GOWITNESS_THREADS),
            "--write-jsonl",
            "--write-jsonl-file", json_file
        ]

        # Use run_command with a calculated timeout
        from core.runner import run_command
        timeout = 600 + (len(targets) * 5)  # 10 minutes base + 5 seconds per target
        
        stdout_lines = run_command(cmd, timeout=timeout)

        if debug:
            debug_log(f"gowitness scan stdout:\n{'\n'.join(stdout_lines)}", f"{paths['base']}/debug.txt")

        # Generate HTML report zip
        report_cmd = [
            GOWITNESS,
            "report", "generate",
            "--json-file", json_file,
            "--screenshot-path", output_dir,
            "--zip-name", zip_file
        ]
        
        run_command(report_cmd, timeout=300)

        print(f"[+] Screenshots saved in: {output_dir}")
        print(f"[+] HTML Report generated at: {zip_file}\n")

    except Exception as e:
        print(f"[!] Screenshot error: {e}")
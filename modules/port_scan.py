import subprocess
import os
import json
from config.settings import NAABU_PORTS, NAABU_THREADS, NAABU_RATE_LIMIT
from config.tools import NAABU, is_tool_available
from core.output import save_txt, unique_list, debug_log
from core.utils import get_tool_timeout, reconstruct_url, is_valid_url
from core.runner import run_command

def run_port_scan(subdomains, paths, base_latency=5, rate_limit=None):
    if not subdomains:
        return []

    if not is_tool_available(NAABU):
        print("\n[*] Port scan: naabu is not available, skipping.")
        return []

    print(f"\n[+] Running Port Scan (Naabu) on {len(subdomains)} subdomains")
    
    input_file = f"{paths['ports']}/targets.txt"
    raw_output = f"{paths['ports']}/naabu_raw.json"
    output_file = f"{paths['ports']}/naabu_results.txt"
    
    save_txt(input_file, subdomains)
    
    timeout = get_tool_timeout(base_latency, "heavy", item_count=len(subdomains))
    rl = rate_limit if rate_limit else NAABU_RATE_LIMIT
    
    if NAABU_PORTS in ["top-100", "top-1000"]:
        port_val = NAABU_PORTS.replace("top-", "")
        port_args = ["-tp", port_val]
    elif NAABU_PORTS == "full":
        port_args = ["-p", "-"]
    else:
        port_args = ["-p", NAABU_PORTS]

    cmd = [
        NAABU,
        "-l", input_file,
        "-c", str(NAABU_THREADS),
        "-rate", str(rl),
        "-verify",
        "-o", raw_output,
        "-json",
        "-silent"
    ] + port_args

    # Check privileges: if running as non-root, use connect scan (-s connect) to prevent raw socket error
    try:
        if os.geteuid() != 0:
            cmd.extend(["-s", "connect"])
    except AttributeError:
        pass

    run_command(cmd, timeout=timeout, debug_path=f"{paths['base']}/debug.txt", cwd=paths['ports'])
    
    found_urls = []
    raw_entries = []
    if os.path.exists(raw_output):
        with open(raw_output, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                h_val = None
                p_val = None
                try:
                    data = json.loads(line)
                    h_val = data.get("host")
                    p_val = data.get("port")
                except Exception:
                    if ":" in line:
                        parts = line.split(":", 1)
                        h_val = parts[0]
                        p_val = parts[1]
                if h_val and p_val:
                    raw_str = f"{h_val}:{p_val}"
                    raw_entries.append(raw_str)
                    url = reconstruct_url(raw_str)
                    if url and is_valid_url(url):
                        found_urls.append(url)
                        
    found_urls = unique_list(found_urls)
    save_txt(output_file, found_urls)
    print(f"[+] Naabu found {len(found_urls)} open port targets (reconstructed to URLs)")
    
    with open(f"{paths['ports']}/report.txt", "w") as f:
        f.write(f"🔌 PORT SCAN REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"📂 Open Port URLs Found: {len(found_urls)}\n")
        f.write("-" * 60 + "\n")
        for u in found_urls:
            f.write(f"• {u}\n")
            
    return found_urls

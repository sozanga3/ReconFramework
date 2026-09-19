import subprocess
import os
import json
from config.settings import NAABU_PORTS, NAABU_THREADS, NAABU_RATE_LIMIT
from config.tools import NAABU, is_tool_available
from core.output import save_txt, unique_list, debug_log
from core.utils import get_tool_timeout
from core.runner import run_command

def run_port_scan(subdomains, paths, base_latency=5, rate_limit=None):
    if not subdomains:
        return []

    if not is_tool_available(NAABU):
        print("\n[*] Port scan: naabu is not available, skipping.")
        return []

    print(f"\n[+] Running Port Scan (Naabu) on {len(subdomains)} subdomains")
    
    input_file = f"{paths['ports']}/targets.txt"
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
        "-o", output_file,
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
    
    found_ports = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host")
                    port = data.get("port")
                    if host and port:
                        found_ports.append(f"{host}:{port}")
                except Exception:
                    if ":" in line:
                        found_ports.append(line)
                        
    found_ports = unique_list(found_ports)
    print(f"[+] Naabu found {len(found_ports)} open ports")
    
    with open(f"{paths['ports']}/report.txt", "w") as f:
        f.write(f"🔌 PORT SCAN REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"📂 Open Ports Found: {len(found_ports)}\n")
        f.write("-" * 60 + "\n")
        for p in found_ports:
            f.write(f"• {p}\n")
            
    return found_ports

import os
import re
from config.tools import WAFW00F, NOMORE403, is_tool_available
from core.output import save_txt, unique_list
from core.utils import get_tool_timeout
from core.runner import run_command

# Standard WAF bypass injection headers
WAF_BYPASS_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1")
]

# =========================================================
# 🛡️ WAF DETECTOR MODULE (SMART SAFETY)
# =========================================================

def detect_waf(url):
    """
    Runs wafw00f on a single target to detect WAF presence.
    Returns the WAF name or None.
    """
    if not is_tool_available(WAFW00F):
        return None

    print(f"[?] Checking for WAF on {url}")
    try:
        cmd = [WAFW00F, "-a", url]
        res_lines = run_command(cmd, timeout=45)
        output = "\n".join(res_lines)
        
        match = re.search(r"is behind (.*)", output)
        if match:
            waf_name = match.group(1).strip()
            print(f"[!] WAF Detected: {waf_name}")
            return waf_name
        
        return None
    except Exception:
        return None


def get_safety_profile(targets, limit=5):
    """
    Checks a sample of targets and returns a global safety recommendation.
    """
    if not is_tool_available(WAFW00F):
        return {
            "waf_ratio": 0,
            "wafs": [],
            "recommendation": "aggressive"
        }

    print(f"\n[+] Analyzing safety profile for top {min(len(targets), limit)} targets...")
    waf_count = 0
    detected_wafs = set()
    sample = targets[:limit]
    
    for t in sample:
        waf = detect_waf(t)
        if waf:
            waf_count += 1
            detected_wafs.add(waf)
            
    waf_ratio = waf_count / len(sample) if sample else 0
    profile = {
        "waf_ratio": waf_ratio,
        "wafs": list(detected_wafs),
        "recommendation": "aggressive"
    }
    
    if waf_ratio >= 0.5:
        profile["recommendation"] = "safe"
    elif waf_ratio > 0:
        profile["recommendation"] = "balanced"
        
    print(f"[+] Safety profile analysis complete. Risk level: {profile['recommendation'].upper()}")
    if detected_wafs:
        print(f"[+] Detected WAF types: {', '.join(detected_wafs)}")
        
    return profile


# =========================================================
# 🔓 403 FORBIDDEN BYPASS MODULE (NOMORE403)
# =========================================================
def run_nomore403(endpoints_403, paths, base_latency=5):
    """
    Runs nomore403 on endpoints returning 403 status code to attempt bypass.
    """
    if not endpoints_403:
        return []

    if not is_tool_available(NOMORE403):
        print("\n[*] 403 Bypass: nomore403 is not available, skipping.")
        return []
        
    print(f"\n[+] Running 403 Bypass Testing (nomore403) on {len(endpoints_403)} target(s)...")
    med_timeout = get_tool_timeout(base_latency, "medium")
    bypassed = []
    
    for ep in endpoints_403[:15]:
        try:
            cmd = [NOMORE403, "-u", ep]
            lines = run_command(cmd, timeout=med_timeout, cwd=paths['endpoints'])
            for l in lines:
                l_str = l.strip()
                if "200 OK" in l_str or "302 Found" in l_str or "301 Moved" in l_str:
                    bypassed.append(f"[BYPASS SUCCESS] {ep} -> {l_str}")
        except Exception:
            pass
            
    if bypassed:
        fuzz_403_dir = paths.get('fuzzing_403', paths['fuzzing'])
        save_txt(f"{fuzz_403_dir}/bypassed_403.txt", bypassed)
        print(f"[!] Successfully bypassed 403 restrictions on {len(bypassed)} endpoint(s)!")
    else:
        print("[*] No 403 bypasses achieved.")
        
    return bypassed

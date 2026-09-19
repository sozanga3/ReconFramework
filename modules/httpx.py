import subprocess
import json
from core.output import save_txt, save_json, debug_log
from core.scoring import score_http_target
from config.settings import HTTPX_RETRIES, HTTPX_THREADS, HTTPX_TIMEOUT, HTTPX_RATE_LIMIT
from core.utils import get_tool_timeout
from config.tools import HTTPX
from core.runner import run_command

# =========================================================
# ⚙️ RUN HTTPX
# =========================================================
def run_httpx(subdomains, paths, debug=False, suffix="", base_latency=5, bypass_waf=False, rate_limit=None):
    print("\n[+] Running httpx (deep probe + scoring)")

    per_host_timeout = get_tool_timeout(base_latency, "medium")

    input_file = f"{paths['httpx']}/input{suffix}.txt"
    output_file = f"{paths['httpx']}/raw{suffix}.json"

    # save input
    save_txt(input_file, subdomains)

    # Wall-clock budget: each host gets `per_host_timeout` seconds but httpx
    # runs them in parallel with HTTPX_THREADS threads.
    # We must account for retries and HTTP/HTTPS dual-probing which multiplies per-host time.
    host_count   = max(1, len(subdomains))
    parallel_est = max(1, host_count / HTTPX_THREADS)
    
    # max time per host in httpx = timeout * (retries + 1) * 2 (http/https)
    max_httpx_time_per_host = HTTPX_TIMEOUT * (HTTPX_RETRIES + 1) * 2
    
    wall_timeout = int(parallel_est * max(per_host_timeout, max_httpx_time_per_host) + 300)

    rl = rate_limit if rate_limit else HTTPX_RATE_LIMIT

    cmd = [
        HTTPX,
        "-l", input_file,
        "-json",
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-follow-redirects",
        "-cdn",
        "-asn",
        "-favicon",
        "-rl", str(rl),
        "-timeout", str(HTTPX_TIMEOUT),
        "-retries", str(HTTPX_RETRIES),
        "-threads", str(HTTPX_THREADS),
        "-o", output_file,
    ]

    if bypass_waf:
        cmd.extend(["-H", "X-Forwarded-For: 127.0.0.1", "-H", "X-Originating-IP: 127.0.0.1"])

    try:
        debug_file = f"{paths['httpx']}/debug.txt"
        run_command(cmd, timeout=wall_timeout, debug_path=debug_file, cwd=paths['httpx'])
    except Exception as e:
        debug_log(f"[httpx error] {type(e).__name__}: {e}", debug_file)
        return []

    return parse_httpx(output_file, paths, debug, suffix)


# =========================================================
# 📊 PARSE + SCORE
# =========================================================
def parse_httpx(file_path, paths, debug=False, suffix=""):
    results = []

    try:
        with open(file_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())

                    record = {
                        "url": data.get("url"),
                        "status_code": data.get("status_code"),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "length": data.get("content_length", 0),
                    }

                    # 🧠 SCORING
                    record["score"] = score_http_target(record)

                    results.append(record)

                except Exception:
                    continue

    except Exception as e:
        debug_log(f"[parse error] {e}")

    # ----------------------------
    # SAVE CLEAN OUTPUT
    # ----------------------------
    save_json(f"{paths['httpx']}/results{suffix}.json", results)

    # ----------------------------
    # SORT BY SCORE
    # ----------------------------
    ranked = sorted(results, key=lambda x: x["score"], reverse=True)

    save_json(f"{paths['httpx']}/ranked{suffix}.json", ranked)

    # ----------------------------
    # EXTRACT URLS
    # ----------------------------
    alive_urls = [r["url"] for r in ranked if r.get("url")]

    save_txt(f"{paths['httpx']}/alive{suffix}.txt", alive_urls)

    # 📝 SAVE HUMAN-READABLE ALIVE REPORT
    with open(f"{paths['httpx']}/alive_report{suffix}.txt", "w") as f:
        f.write(f"🌐 HTTP ALIVE REPORT\n")
        f.write("=" * 60 + "\n\n")
        for r in ranked:
            f.write(f"URL:    {r['url']}\n")
            f.write(f"SCORE:  {r['score']}\n")
            f.write(f"STATUS: {r['status_code']}\n")
            f.write(f"TITLE:  {r.get('title', 'N/A')}\n")
            f.write(f"TECH:   {', '.join(r.get('tech', []))}\n")
            f.write("-" * 40 + "\n")

    print(f"[+] httpx: {len(results)} alive HTTP targets")

    # ----------------------------
    # PRINT TOP TARGETS
    # ----------------------------
    print("\n🔥 Top Targets:")
    for r in ranked[:10]:
        print(f"{r['score']} → {r['url']}")

    return ranked
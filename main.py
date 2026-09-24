import argparse
import sys
import re
import os
import json
import time
from datetime import datetime

from modules.subdomains import enumerate_subdomains, clean_subdomains
from modules.httpx import run_httpx
from modules.js_enum import run_js_enum
from modules.js_filter import run_js_filter
from modules.param_discovery import run_param_discovery
from core.output import (
    create_output_structure,
    save_txt,
    save_json,
    unique_list,
    generate_summary
)
from core.utils import get_dynamic_timeout, validate_tools, print_tools_status, is_valid_subdomain, clean_domain_input
from core.notifications import notify_scan_start, notify_vuln_found, notify_scan_complete
from core.scoring import rank_targets
from modules.screenshots import run_screenshots
from modules.nuclei_scan import run_nuclei
from modules.crawler import run_katana, run_hakrawler, run_url_collection
from modules.waf_detector import get_safety_profile
from modules.cloud_recon import run_cloud_recon
from modules.github_recon import github_endpoints, github_secrets
from modules.port_scan import run_port_scan
from core.state import is_step_completed, save_state, run_or_resume, load_list_from_file, load_json_from_file
from config.tools import SUBZY, is_tool_available
from config.settings import DEBUG_MODE
from core.runner import run_command

BANNER = """
================================================================================
⚡ RECON FRAMEWORK v3.2.0: THE INTELLIGENCE ENGINE
High-Performance Attack Surface Discovery & Vulnerability Pipeline
================================================================================
"""

# =========================================================
# 🚀 MAIN PIPELINE
# =========================================================
def main(domain, output_dir=None, top_limit=10, resume=False, monitor=False, deep_crawl=False, bypass_waf=False, run_nuclei_flag=False, run_port_scan_flag=False, custom_rate_limit=None, all_domains=None):
    start_time = time.time()
    print(BANNER)
    print(f"🎯 Target Domain : {domain}")
    print(f"📅 Start Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # 🔍 TOOL VALIDATION
    status = validate_tools()
    if status["core_missing"]:
        print("[!] CRITICAL ERROR: The following required core tools are missing:")
        for m in status["core_missing"]:
            print(f"    - {m}")
        print("\n[!] Please install them to proceed. Exiting.")
        sys.exit(1)

    if status["optional_missing"]:
        print(f"[*] Note: {len(status['optional_missing'])} optional tool(s) not found ({', '.join(status['optional_missing'][:5])}...). Associated modules will degrade gracefully.")

    print(f"[*] Sending start notification to Telegram...")
    notify_scan_start(domain)

    # ---------------------------------
    # 📁 OUTPUT STRUCTURE & MONITORING
    # ---------------------------------
    paths = create_output_structure(domain, output_dir)
    
    previous_stats = {}
    if monitor:
        stats_file = f"{paths['base']}/stats.json"
        if os.path.exists(stats_file):
            print("[+] Monitor Mode: Loaded previous run stats for diffing.")
            try:
                with open(stats_file, "r") as f:
                    previous_stats = json.load(f)
            except Exception:
                pass
            
    # ⏱️ DYNAMIC TIMEOUT CALCULATION
    target_for_timeout = f"https://{domain}" 
    dynamic_timeout = get_dynamic_timeout(target_for_timeout)

    # ---------------------------------
    # 🌐 SUBDOMAIN ENUMERATION
    # ---------------------------------
    subs = run_or_resume(resume, paths, "subdomains", f"{paths['subdomains']}/all.txt", "list",
                         enumerate_subdomains, domain, paths, debug=DEBUG_MODE, base_latency=dynamic_timeout, rate_limit=custom_rate_limit)

    print(f"\n[🔥] FINAL UNIQUE SUBDOMAINS: {len(subs)}\n")

    if not subs:
        print("[-] No subdomains discovered. Aborting pipeline to prevent cascading errors.")
        return

    # ---------------------------------
    # 🚨 SUBDOMAIN TAKEOVER CHECK (SUBZY)
    # ---------------------------------
    if is_tool_available(SUBZY) and subs:
        if not resume or not is_step_completed(paths, "subzy_takeover"):
            print("\n[+] Checking for Subdomain Takeovers (subzy)...")
            takeover_file = f"{paths['subdomains']}/takeovers.txt"
            sub_input_file = f"{paths['subdomains']}/all.txt"
            takeover_res = run_command([SUBZY, "run", "--targets", sub_input_file, "--hide_fails"], timeout=180, cwd=paths['subdomains'])
            if takeover_res:
                save_txt(takeover_file, takeover_res)
                print(f"[!] Subzy check finished. Results saved to: {takeover_file}")
            save_state(paths, "subzy_takeover")

    # ---------------------------------
    # ☁️ CLOUD RECON
    # ---------------------------------
    cloud_assets = run_or_resume(resume, paths, "cloud_recon", f"{paths['cloud']}/cloud_assets.txt", "list",
                                 run_cloud_recon, domain, paths, base_latency=dynamic_timeout)

    # ---------------------------------
    # 🔌 PORT SCANNING (NAABU)
    # ---------------------------------
    open_ports = []
    if run_port_scan_flag:
        open_ports = run_or_resume(resume, paths, "port_scan", f"{paths['ports']}/naabu_results.txt", "list",
                                   run_port_scan, subs, paths, base_latency=dynamic_timeout, rate_limit=custom_rate_limit)
    else:
        print("[*] Skipping port scan (disabled by default, use --port-scan flag to enable)")
    
    httpx_input = unique_list(subs + open_ports)

    # ---------------------------------
    # 🛡️ EARLY WAF DETECTION & SAFETY PROFILE
    # ---------------------------------
    safety_profile = {"recommendation": "aggressive", "waf_ratio": 0, "wafs": []}
    safety_json = f"{paths['base']}/safety_profile.json"
    if resume and is_step_completed(paths, "waf") and os.path.exists(safety_json):
        print("[*] Skipping waf (already completed) - Loading safety profile...")
        try:
            with open(safety_json, "r") as f:
                safety_profile = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Could not load safety profile JSON - {e}")
    else:
        apex_targets = [f"https://{domain}", f"https://www.{domain}"]
        safety_profile = get_safety_profile(apex_targets)
    
    dynamic_rl = custom_rate_limit
    dynamic_cc = None
    if not dynamic_rl:
        if safety_profile.get("recommendation") == "safe":
            print("[!] High WAF presence detected. Switching to SAFE mode.")
            dynamic_rl = 20
            dynamic_cc = 10
        elif safety_profile.get("recommendation") == "balanced":
            print("[!] WAFs detected. Switching to BALANCED mode.")
            dynamic_rl = 50
            dynamic_cc = 15

    # ---------------------------------
    # 🌐 HTTPX PROBE + SCORING
    # ---------------------------------
    http_results = run_or_resume(resume, paths, "httpx", f"{paths['httpx']}/results.json", "json",
                                 run_httpx, httpx_input, paths, base_latency=dynamic_timeout, bypass_waf=bypass_waf, rate_limit=dynamic_rl)

    ranked = http_results or []
    top_targets = [r["url"] for r in ranked[:top_limit] if isinstance(r, dict) and r.get("url")]

    print(f"\n🔥 Top {len(top_targets)} Targets (Ranked):")
    for r in ranked[:top_limit]:
        if isinstance(r, dict):
            print(f"{r.get('score', 0)} → {r.get('url', '')}")

    # Refine safety profile across top ranked targets if not resumed
    if not (resume and is_step_completed(paths, "waf") and os.path.exists(safety_json)):
        if top_targets:
            full_safety = get_safety_profile(top_targets)
            if full_safety.get("wafs"):
                safety_profile["wafs"] = unique_list(safety_profile["wafs"] + full_safety["wafs"])
                safety_profile["recommendation"] = full_safety["recommendation"]
                safety_profile["waf_ratio"] = max(safety_profile["waf_ratio"], full_safety["waf_ratio"])
        
        with open(f"{paths['base']}/safety_report.txt", "w") as f:
            f.write(f"🛡️ SAFETY & WAF REPORT: {domain}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Risk Recommendation: {safety_profile.get('recommendation', 'UNKNOWN').upper()}\n")
            f.write(f"WAF Detection Ratio: {safety_profile.get('waf_ratio', 0)*100:.1f}%\n")
            f.write(f"Detected WAFs:       {', '.join(safety_profile.get('wafs', [])) if safety_profile.get('wafs') else 'None'}\n\n")
        save_json(safety_json, safety_profile)
        save_state(paths, "waf")

    # ---------------------------------
    # 🖥️ ACTIVE CRAWLING & PASSIVE
    # ---------------------------------
    katana_js, katana_ep = run_or_resume(resume, paths, "katana", f"{paths['endpoints_raw']}/katana_raw.txt", "tuple",
                                         run_katana, top_targets, paths, base_latency=dynamic_timeout, rate_limit=dynamic_rl, all_domains=all_domains) or ([], [])
    hakrawler_js, hakrawler_ep = run_or_resume(resume, paths, "hakrawler", f"{paths['endpoints']}/hakrawler_raw.txt", "tuple",
                                                run_hakrawler, top_targets, paths, base_latency=dynamic_timeout, all_domains=all_domains) or ([], [])
    passive_js, passive_ep = run_or_resume(resume, paths, "passive", f"{paths['endpoints']}/passive_urls.txt", "tuple",
                                            run_url_collection, domain, top_targets, paths, base_latency=dynamic_timeout, all_domains=all_domains) or ([], [])

    pre_collected_js = unique_list(katana_js + hakrawler_js + passive_js)

    # ---------------------------------
    # 📜 JS ENUMERATION & INTELLIGENCE
    # ---------------------------------
    if not resume or not is_step_completed(paths, "js_enum"):
        js_files, endpoints, secrets, js_subs = run_js_enum(
            domain, top_targets, paths, base_latency=dynamic_timeout, extra_js=pre_collected_js,
            all_domains=all_domains
        )
        save_state(paths, "js_enum")
    else:
        print("[*] Skipping js_enum (already completed)")
        js_files = load_list_from_file(f"{paths['js']}/js_files_clean.txt")
        endpoints = load_list_from_file(f"{paths['js']}/endpoints_clean.txt")
        secrets = load_list_from_file(f"{paths['js']}/secrets_clean.txt")
        js_subs = load_list_from_file(f"{paths['js']}/subdomains_from_js.txt")

    # Update main subdomain list with those found in JS
    if js_subs:
        js_subs = clean_subdomains(js_subs, domain)
        subs = clean_subdomains(unique_list(subs + js_subs), domain)
        save_txt(f"{paths['subdomains']}/all.txt", subs)
    
    # 🐙 GITHUB RECON
    gh_endpoints = run_or_resume(resume, paths, "github_ep", f"{paths['js']}/github_endpoints.txt", "list",
                                 github_endpoints, domain, paths) or []
    gh_secrets = run_or_resume(resume, paths, "github_sec", f"{paths['js']}/github_secrets.txt", "list",
                               github_secrets, domain, paths) or []
    
    # MERGE ALL SOURCES
    js_files = unique_list(js_files + katana_js + hakrawler_js + passive_js)
    endpoints = unique_list(endpoints + katana_ep + hakrawler_ep + gh_endpoints + passive_ep)
    secrets = unique_list(secrets + gh_secrets)

    # ---------------------------------
    # 🧹 JS FILTERING
    # ---------------------------------
    if not resume or not is_step_completed(paths, "js_filter"):
        clean_js, high_js, clean_endpoints, high_ep = run_js_filter(domain, js_files, endpoints, paths, all_domains=all_domains)
        save_state(paths, "js_filter")
    else:
        print("[*] Skipping js_filter (already completed) - Loading filtered data...")
        clean_js = load_list_from_file(f"{paths['js']}/js_filtered.txt")
        high_js = load_list_from_file(f"{paths['js']}/js_high_value.txt")
        clean_endpoints = load_list_from_file(f"{paths['js']}/endpoints_filtered.txt")
        high_ep = load_list_from_file(f"{paths['js']}/endpoints_high_risk.txt")

    # ---------------------------------
    # 🔄 INTELLIGENCE FEEDBACK LOOP
    # ---------------------------------
    if not resume or not is_step_completed(paths, "feedback_loop"):
        print("\n[+] Intelligence Feedback Loop (checking for new subdomains)")
        from urllib.parse import urlparse
        new_subs = set()
        for ep in clean_endpoints:
            if ep.startswith("http"):
                try:
                    netloc = urlparse(ep).netloc
                    if ":" in netloc:
                        netloc = netloc.split(":")[0]
                    if netloc and is_valid_subdomain(netloc, domain):
                        clean_netloc = re.split(r'[?&#=/]', netloc)[0]
                        if clean_netloc and is_valid_subdomain(clean_netloc, domain) and not any(c in clean_netloc for c in "{}[]|\\^`<>"):
                            new_subs.add(clean_netloc.lower())
                except Exception:
                    pass
        
        discovered_new = [s for s in new_subs if s not in subs]
        if discovered_new:
            discovered_new = clean_subdomains(discovered_new, domain)
            discovered_new = [s for s in discovered_new if s not in subs]
            
            if discovered_new:
                print(f"[+] Found {len(discovered_new)} NEW subdomains inside JS code!")
                for s in discovered_new:
                    print(f"    ⭐ {s}")
                subs = clean_subdomains(unique_list(subs + discovered_new), domain)
                save_txt(f"{paths['subdomains']}/all.txt", subs)
                
                new_http = run_httpx(discovered_new, paths, suffix="_feedback", base_latency=dynamic_timeout, bypass_waf=bypass_waf, rate_limit=dynamic_rl)
                http_results += new_http
                save_json(f"{paths['httpx']}/results.json", http_results)
                save_txt(f"{paths['httpx']}/alive.txt", [r["url"] for r in http_results if isinstance(r, dict) and r.get("url")])
                
                ranked = rank_targets(http_results)
                save_json(f"{paths['httpx']}/ranked.json", ranked)
                top_targets = [r["url"] for r in ranked[:top_limit + 5] if isinstance(r, dict) and r.get("url")]
                
                if deep_crawl:
                    print("[+] Deep Crawl: Active spidering on newly discovered assets!")
                    new_alive = [r["url"] for r in new_http if isinstance(r, dict) and r.get("url")]
                    if new_alive:
                        new_k_js, new_k_ep = run_katana(new_alive, paths, base_latency=dynamic_timeout, all_domains=all_domains)
                        new_h_js, new_h_ep = run_hakrawler(new_alive, paths, base_latency=dynamic_timeout, all_domains=all_domains)
                        endpoints = unique_list(endpoints + new_k_ep + new_h_ep)
                        js_files = unique_list(js_files + new_k_js + new_h_js)
                        clean_endpoints = unique_list(clean_endpoints + new_k_ep + new_h_ep)
                        high_ep = unique_list(high_ep + new_k_ep + new_h_ep)
                        
        save_state(paths, "feedback_loop")

    # ---------------------------------
    # PARAM DISCOVERY & API RECON (KR)
    # ---------------------------------
    if not resume or not is_step_completed(paths, "param_discovery"):
        from modules.param_discovery import run_kiterunner
        kr_routes = run_kiterunner(top_targets, paths, base_latency=dynamic_timeout, rate_limit=dynamic_rl)
        if kr_routes:
            endpoints = unique_list(endpoints + kr_routes)
            clean_endpoints = unique_list(clean_endpoints + kr_routes)
            save_txt(f"{paths['endpoints']}/all_endpoints.txt", clean_endpoints)
            
        all_params, scored_params = run_param_discovery(domain, clean_endpoints, top_targets, paths, base_latency=dynamic_timeout, all_domains=all_domains)
        save_state(paths, "param_discovery")
    else:
        print("[*] Skipping param_discovery")
        all_params = load_list_from_file(f"{paths['params']}/all_params.txt")
        scored_params = load_json_from_file(f"{paths['params']}/scored_params.json")

    # ---------------------------------
    # 🔓 403 BYPASS TESTING (NOMORE403)
    # ---------------------------------
    if not resume or not is_step_completed(paths, "bypass_403"):
        from modules.waf_detector import run_nomore403
        status_403_urls = [r["url"] for r in http_results if isinstance(r, dict) and r.get("status_code") == 403 and r.get("url")]
        eps_403 = status_403_urls if status_403_urls else [ep for ep in high_ep if ep.startswith("http")][:15]
        run_nomore403(eps_403, paths, base_latency=dynamic_timeout)
        save_state(paths, "bypass_403")

    # ---------------------------------
    # 🎯 NUCLEI TARGET PREPARATION
    # ---------------------------------
    nuclei_targets = []
    nuclei_targets += top_targets
    raw_endpoints = high_ep + [p["endpoint"] for p in scored_params if isinstance(p, dict) and p.get("params") and p.get("endpoint")]
    
    # Load fuzzable endpoints generated by qsreplace
    fuzzable_eps = load_list_from_file(f"{paths['params']}/endpoints_fuzzable.txt")
    if fuzzable_eps:
        raw_endpoints += fuzzable_eps
    
    for ep in raw_endpoints:
        if ep.startswith("http"):
            nuclei_targets.append(ep)
        elif ep.startswith("/"):
            for base in top_targets:
                nuclei_targets.append(f"{base.rstrip('/')}/{ep.lstrip('/')}")

    if cloud_assets:
        for a in cloud_assets:
            match = re.search(r'https?://[^\s]+', a)
            if match:
                nuclei_targets.append(match.group(0))

    nuclei_targets = unique_list(nuclei_targets)

    # Nuclei scan
    nuclei_results = []
    if run_nuclei_flag:
        nuclei_results = run_or_resume(resume, paths, "nuclei", f"{paths['fuzzing']}/nuclei_results.txt", "list",
                                       run_nuclei, domain, nuclei_targets, paths, rate_limit=dynamic_rl, 
                                       concurrency=dynamic_cc, debug=True, base_latency=dynamic_timeout, bypass_waf=bypass_waf)
        
        if nuclei_results:
            notify_vuln_found(domain, len(nuclei_results))
    else:
        print("[*] Skipping Nuclei scan (disabled by default, use --nuclei flag to enable)")

    # Screenshots (gowitness)
    if not resume or not is_step_completed(paths, "screenshots"):
        all_urls = [r["url"] for r in ranked if isinstance(r, dict) and r.get("url")]
        run_screenshots(all_urls, paths, debug=True)
        save_state(paths, "screenshots")

    # ---------------------------------
    # 📊 FINAL SUMMARY & MONITORING
    # ---------------------------------
    elapsed_time = time.time() - start_time

    tool_metrics = {
        "secretfinder": len(load_list_from_file(f"{paths['js']}/secretfinder_secrets.txt")),
        "paramspider": len(load_list_from_file(f"{paths['params']}/paramspider.txt")),
        "arjun": len(load_list_from_file(f"{paths['params']}/arjun_params.txt")),
        "x8": len(load_list_from_file(f"{paths['params']}/x8_params.txt")),
        "kiterunner": len(load_list_from_file(f"{paths['endpoints']}/kiterunner_api.txt")),
        "github_endpoints": len(load_list_from_file(f"{paths['js']}/github_endpoints.txt")),
        "github_secrets": len(load_list_from_file(f"{paths['js']}/github_secrets.txt"))
    }

    stats = {
        "subdomains": len(subs),
        "alive": len(http_results),
        "js_files": len(js_files),
        "endpoints": len(endpoints),
        "params": len(all_params),
        "nuclei": len(nuclei_results),
        "top_targets": top_targets,
        "secrets": len(secrets),
        "ports": len(open_ports),
        "cloud_assets": len(cloud_assets),
        "safety": safety_profile,
        "tool_metrics": tool_metrics,
        "elapsed_seconds": round(elapsed_time, 2)
    }
    
    # Specialized Tool Output Metrics Display
    print("\n" + "="*60)
    print("🛠️ SPECIALIZED RECON TOOL METRICS")
    print("="*60)
    print(f" • SecretFinder (JS Secrets):     {tool_metrics['secretfinder']}")
    print(f" • ParamSpider (Discovered URLs): {tool_metrics['paramspider']}")
    print(f" • Arjun (Hidden Parameters):    {tool_metrics['arjun']}")
    print(f" • x8 (Fast Parameter Mining):   {tool_metrics['x8']}")
    print(f" • Kiterunner (API Routes):      {tool_metrics['kiterunner']}")
    print(f" • GitHub Endpoints:             {tool_metrics['github_endpoints']}")
    print(f" • GitHub Secrets:               {tool_metrics['github_secrets']}")
    print("="*60)

    if monitor and previous_stats:
        print("\n" + "="*60)
        print("📈 CONTINUOUS MONITORING DIFF")
        print("="*60)
        diff_keys = ["subdomains", "alive", "endpoints", "secrets", "params", "nuclei", "ports"]
        for key in diff_keys:
            old_val = previous_stats.get(key, 0)
            new_val = stats.get(key, 0)
            diff = new_val - old_val
            if diff > 0:
                print(f" [+] {key.capitalize()}: +{diff} new findings! (Total: {new_val})")
            elif diff < 0:
                print(f" [-] {key.capitalize()}: {diff} removed. (Total: {new_val})")
        print("="*60 + "\n")

    # Save stats.json for future monitoring
    save_json(f"{paths['base']}/stats.json", stats)
    
    generate_summary(domain, paths, stats)
    notify_scan_complete(domain, stats)
    print(f"\n[+] Recon session completed in {round(elapsed_time, 1)}s!")
    print(f"[+] Summary report saved at: {paths['base']}/summary.txt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="⚡ Recon Framework - Attack Surface Intelligence Engine")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-df", "--domains-file", help="File containing a list of domains to scan (one per line)")
    parser.add_argument("-o", "--output", help="Custom output directory")
    parser.add_argument("-t", "--top", type=int, default=10, help="Number of top targets to deep scan (default: 10)")
    parser.add_argument("--resume", action="store_true", help="Resume from the last completed state in the output directory")
    parser.add_argument("--monitor", action="store_true", help="Enable continuous monitoring (diffing against previous run)")
    parser.add_argument("--deep-crawl", action="store_true", help="Enable recursive crawling on newly discovered subdomains")
    parser.add_argument("--bypass-waf", action="store_true", help="Inject WAF bypass headers in probes")
    parser.add_argument("--nuclei", action="store_true", help="Enable Nuclei vulnerability scanning")
    parser.add_argument("--port-scan", action="store_true", help="Enable port scanning with naabu (disabled by default)")
    parser.add_argument("-rl", "--rate-limit", type=int, default=None, help="Global rate limit in requests per second (e.g. 30, 50, 100)")
    parser.add_argument("--check-tools", action="store_true", help="Inspect and display status of all configured reconnaissance tools")

    args = parser.parse_args()

    # Tool inspection mode
    if args.check_tools:
        print_tools_status()
        sys.exit(0)

    if not args.domain and not args.domains_file:
        parser.error("Either --domain (-d) or --domains-file (-df) must be provided. Use --check-tools to inspect installed tools.")

    domains = []
    if args.domain:
        cleaned_d = clean_domain_input(args.domain)
        if cleaned_d:
            domains.append(cleaned_d)
        
    if args.domains_file:
        if not os.path.exists(args.domains_file):
            print(f"[!] Error: Domains file '{args.domains_file}' not found.")
            sys.exit(1)
        with open(args.domains_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    cleaned_d = clean_domain_input(line)
                    if cleaned_d:
                        domains.append(cleaned_d)

    domains = unique_list(domains)
    if not domains:
        print("[!] No valid domains to scan.")
        sys.exit(1)

    print(f"[+] Starting scanning pipeline for {len(domains)} target domain(s) sequentially...")
    for idx, dom in enumerate(domains, 1):
        print("\n" + "="*80)
        print(f"🚀 [{idx}/{len(domains)}] RUNNING RECON PIPELINE ON: {dom}")
        print("="*80)
        try:
            main(
                dom,
                output_dir=args.output,
                top_limit=args.top,
                resume=args.resume,
                monitor=args.monitor,
                deep_crawl=args.deep_crawl,
                bypass_waf=args.bypass_waf,
                run_nuclei_flag=args.nuclei,
                run_port_scan_flag=args.port_scan,
                custom_rate_limit=args.rate_limit,
                all_domains=domains
            )
        except Exception as e:
            print(f"[!] Critical error occurred while scanning {dom}: {e}")
            import traceback
            traceback.print_exc()
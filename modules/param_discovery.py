
import re
import tempfile
import os
import json
import shutil
from urllib.parse import urlparse
from core.output import save_txt, save_json, unique_list, clean_data, debug_log
from core.utils import get_tool_timeout, is_valid_subdomain
from core.scoring import score_params, keyword_score, entropy_score
from config.settings import ARJUN_THREADS, X8_THREADS, PARAMSPIDER_TIMEOUT, KITERUNNER_RATE_LIMIT, NOISE_PARAMS, ENTROPY_THRESHOLD
from config.tools import ARJUN, X8, KR, PARAMSPIDER, UNFURL, QSREPLACE, is_tool_available
from core.runner import run_command


# =========================================================
# 🔧 RUN COMMAND
# =========================================================



# =========================================================
# 🔗 EXTRACT PARAMS FROM URL
# =========================================================
def extract_params_from_urls(urls):
    if not urls:
        return []
    params = set()
    
    # 1. Native query param extraction (instant, zero external dependency)
    for u in urls:
        try:
            if "?" in u:
                q = urlparse(u).query
                for pair in q.split("&"):
                    if "=" in pair:
                        k = pair.split("=")[0].strip()
                        if k: params.add(k)
                    elif pair.strip():
                        params.add(pair.strip())
        except Exception:
            pass

    # 2. Deep extraction with unfurl if available
    if is_tool_available(UNFURL):
        fd, tmp_path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'w') as f:
                for u in urls:
                    f.write(f"{u}\n")
            cmd = [UNFURL, "keys", tmp_path]
            res_lines = run_command(cmd, timeout=30, cwd=os.path.dirname(tmp_path))
            for line in res_lines:
                k = line.strip()
                if k:
                    params.add(k)
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except: pass

    return list(params)


# =========================================================
# 🤖 RUN ARJUN
# =========================================================
def run_arjun(targets, paths, base_latency=5, custom_wordlist=None):
    if not targets or not is_tool_available(ARJUN):
        return []

    print("[+] Running Arjun (Bulk Mode)")
    timeout = get_tool_timeout(base_latency, "heavy")
    found_params = set()

    fd_in, tmp_in = tempfile.mkstemp()
    fd_out, tmp_out = tempfile.mkstemp()
    os.close(fd_out)  # We only need the path; the tool writes to it by name
    
    with os.fdopen(fd_in, 'w') as f:
        for t in targets:
            f.write(f"{t}\n")
            
    try:
        # Pass 1: Custom Intelligent Wordlist (GET & JSON)
        if custom_wordlist and os.path.exists(custom_wordlist):
            print("  -> Pass 1: Intelligent Wordlist (GET)")
            run_command([ARJUN, "-i", tmp_in, "-oJ", f"{tmp_out}_custom", "-w", custom_wordlist, "-t", str(ARJUN_THREADS), "-q"], timeout=timeout * 5)
            
            print("  -> Pass 2: Intelligent Wordlist (JSON Body)")
            run_command([ARJUN, "-i", tmp_in, "-oJ", f"{tmp_out}_custom_json", "-m", "JSON", "-w", custom_wordlist, "-t", str(ARJUN_THREADS), "-q"], timeout=timeout * 5)
            
            for out_file in [f"{tmp_out}_custom", f"{tmp_out}_custom_json"]:
                if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                    with open(out_file, 'r') as f:
                        try:
                            data = json.load(f)
                            for target_url, info in data.items():
                                if "params" in info:
                                    for p in info["params"]: found_params.add(p)
                        except: pass
                    os.remove(out_file)

        # Pass 3: Default Tool Wordlist (GET)
        print("  -> Pass 3: Default Tool Wordlist (GET)")
        run_command([ARJUN, "-i", tmp_in, "-oJ", tmp_out, "-t", str(ARJUN_THREADS), "-q"], timeout=timeout * 10, cwd=paths['params'])
        
        # Read the JSON output
        if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
            try:
                with open(tmp_out, 'r') as f:
                    data = json.load(f)
                save_json(f"{paths['params']}/arjun_raw.json", data)
                    
                for target_url, info in data.items():
                    if "params" in info:
                        for p in info["params"]:
                            found_params.add(p)
            except Exception:
                pass
    except Exception as e:
        print(f"[-] Arjun exception: {e}")
    finally:
        if os.path.exists(tmp_in): os.remove(tmp_in)
        if os.path.exists(tmp_out): os.remove(tmp_out)

    arjun_list = unique_list(list(found_params))
    save_txt(f"{paths['params']}/arjun_params.txt", arjun_list)
    print(f"  [arjun] Discovered {len(arjun_list)} hidden parameters")
    return arjun_list


# =========================================================
# 🚀 RUN X8 (THE SPEED KING)
# =========================================================
def run_x8(targets, paths, base_latency=5, custom_wordlist=None):
    if not targets or not is_tool_available(X8):
        return []

    print("[+] Running x8 (Bulk Mode)")
    timeout = get_tool_timeout(base_latency, "heavy")
    found_params = set()

    fd_in, tmp_in = tempfile.mkstemp()
    fd_out, tmp_out = tempfile.mkstemp()
    os.close(fd_out)  # We only need the path; the tool writes to it by name
    
    with os.fdopen(fd_in, 'w') as f:
        for t in targets:
            f.write(f"{t}\n")
            
    try:
        # Pass 1 & 2: Custom Intelligent Wordlist (GET & POST)
        def _extract_x8_params(file_path):
            extracted = set()
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                return extracted
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "found_params" in item:
                            for p in item["found_params"]:
                                if isinstance(p, dict) and "name" in p:
                                    p_name = str(p["name"]).strip()
                                    if re.match(r'^[a-zA-Z0-9_\-\.\[\]]+$', p_name) and not p_name.startswith("diffs"):
                                        extracted.add(p_name)
                                elif isinstance(p, str):
                                    p_name = p.strip().strip('"\'')
                                    if re.match(r'^[a-zA-Z0-9_\-\.\[\]]+$', p_name) and not p_name.startswith("diffs"):
                                        extracted.add(p_name)
            except Exception:
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    for p_name in re.findall(r'"name"\s*:\s*"([^"]+)"', content):
                        p_name = p_name.strip()
                        if re.match(r'^[a-zA-Z0-9_\-\.\[\]]+$', p_name) and not p_name.startswith("diffs"):
                            extracted.add(p_name)
                except Exception:
                    pass
            return extracted

        # Pass 1 & 2: Custom Intelligent Wordlist (GET & POST)
        if custom_wordlist and os.path.exists(custom_wordlist):
            print("  -> Pass 1: Intelligent Wordlist (GET)")
            run_command([X8, "-u", tmp_in, "-o", f"{tmp_out}_custom", "-O", "json", "-w", custom_wordlist, "--disable-progress-bar", "-W", str(X8_THREADS)], timeout=timeout * 5)
            
            print("  -> Pass 2: Intelligent Wordlist (POST Body)")
            run_command([X8, "-u", tmp_in, "-o", f"{tmp_out}_custom_post", "-O", "json", "-w", custom_wordlist, "-X", "POST", "--disable-progress-bar", "-W", str(X8_THREADS)], timeout=timeout * 5)
            
            for out_file in [f"{tmp_out}_custom", f"{tmp_out}_custom_post"]:
                found_params.update(_extract_x8_params(out_file))
                if os.path.exists(out_file):
                    os.remove(out_file)

        # Pass 3: Default Tool Wordlist
        print("  -> Pass 3: Default Tool Wordlist (GET)")
        run_command([X8, "-u", tmp_in, "-o", tmp_out, "-O", "json", "--disable-progress-bar", "-W", str(X8_THREADS)], timeout=timeout * 5, cwd=paths['params'])
        
        if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
            try:
                shutil.copy(tmp_out, f"{paths['params']}/x8_raw.json")
                found_params.update(_extract_x8_params(tmp_out))
            except Exception:
                pass
    except Exception as e:
        print(f"[-] x8 exception: {e}")
    finally:
        if os.path.exists(tmp_in): os.remove(tmp_in)
        if os.path.exists(tmp_out): os.remove(tmp_out)

    x8_list = unique_list(list(found_params))
    save_txt(f"{paths['params']}/x8_params.txt", x8_list)
    print(f"  [x8] Discovered {len(x8_list)} hidden parameters")
    return x8_list



# =========================================================
# 🕸️ RUN PARAMSPIDER (ARCHIVE MINING)
# =========================================================
def run_paramspider(domain, paths, base_latency=5):
    if not domain:
        return []
    print(f"[+] Running ParamSpider for {domain}")
    
    found_urls = []
    out_file = f"{paths['params']}/paramspider.txt"
    
    try:
        timeout = max(PARAMSPIDER_TIMEOUT, get_tool_timeout(base_latency, "deep"))  # Use setting as floor
        
        # Use run_command_shell to avoid zombie processes and pipeline hangs
        from core.runner import run_command_shell
        cmd_string = f"{PARAMSPIDER} -d {domain} --stream"
        
        lines = run_command_shell(
            cmd_string, 
            timeout=timeout, 
            debug_path=f"{paths['base']}/debug.txt", 
            cwd=paths['params']
        )
        
        # Parse stdout
        for line in lines:
            line = line.strip()
            # Tightened URL extraction to avoid progress bars or status messages
            if line.startswith("http") and is_valid_subdomain(line, domain):
                found_urls.append(line)
        
        # Fallback: ParamSpider might write its results to a file
        results_file = f"{paths['params']}/results/{domain}.txt"
        if os.path.exists(results_file):
            with open(results_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("http") and is_valid_subdomain(line, domain):
                        found_urls.append(line)
            # Cleanup the results folder
            shutil.rmtree(f"{paths['params']}/results", ignore_errors=True)
            
        found_urls = unique_list(found_urls)
        
        # If no URLs were found, debug log
        if not found_urls:
            debug_log(f"ParamSpider returned no URLs.", f"{paths['base']}/debug.txt")

        # Save results (even if empty, to show the tool ran)
        save_txt(out_file, found_urls)
        print(f"  [paramspider] Discovered {len(found_urls)} parameter URLs")
            
    except Exception as e:
        print(f"[-] ParamSpider error: {e}")
    return found_urls


# =========================================================
# 🚀 RUN KITERUNNER (API ROUTE DISCOVERY)
# =========================================================
def run_kiterunner(targets, paths, base_latency=5, rate_limit=None):
    if not targets or not is_tool_available(KR):
        return []
        
    # Prioritize targets with API keywords, capped to top 15 targets to prevent timeout
    api_prioritized = []
    others = []
    for t in targets:
        t_low = t.lower()
        if any(keyword in t_low for keyword in ["api", "app", "gateway", "rest", "v1", "v2", "graphql", "dev", "staging"]):
            api_prioritized.append(t)
        else:
            others.append(t)
            
    kr_targets = (api_prioritized + others)[:15]
    print(f"\n[+] Running Kiterunner (API Route Brute-forcing) on {len(kr_targets)} prioritized targets...")
    
    discovered_endpoints = []
    out_file = f"{paths['endpoints']}/kiterunner_api.txt"
    
    try:
        timeout = get_tool_timeout(base_latency, "heavy", item_count=len(kr_targets))
        
        # Write target hosts to temporary file
        fd, tmp_targets = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            for t in kr_targets:
                f.write(f"{t}\n")
                
        # Check for cached .kite wordlist or use assetnote route specification with focused depth (2500)
        cached_kite = os.path.expanduser("~/.cache/kiterunner/wordlists/httparchive_apiroutes_2026_02_27.kite")
        if os.path.exists(cached_kite):
            cmd = [
                KR, "scan", tmp_targets,
                "-w", cached_kite,
                "-q",
                "-o", "json",
                "-x", "5",
                "-j", "20",
                "--quarantine-threshold", "5"
            ]
        else:
            cmd = [
                KR, "scan", tmp_targets,
                "-A", "apiroutes-210228:2500",
                "-q",
                "-o", "json",
                "-x", "5",
                "-j", "20",
                "--quarantine-threshold", "5"
            ]
        
        res_lines = run_command(cmd, timeout=timeout, cwd=paths['endpoints'])
        
        for line in res_lines:
            line_str = line.strip()
            if not line_str: continue
            try:
                data = json.loads(line_str)
                # Kiterunner JSON hit format: {"target":"https://host","path":"/api/v1","responses":[...]}
                if "target" in data and "path" in data:
                    t_base = str(data["target"]).rstrip("/")
                    p_path = str(data["path"]).lstrip("/")
                    discovered_endpoints.append(f"{t_base}/{p_path}")
                elif "url" in data:
                    discovered_endpoints.append(data["url"])
                elif "target" in data:
                    discovered_endpoints.append(data["target"])
            except Exception:
                # Text parsing fallback
                if "http" in line_str:
                    match = re.search(r'https?://[^\s]+', line_str)
                    if match:
                        discovered_endpoints.append(match.group(0))

        if os.path.exists(tmp_targets):
            os.remove(tmp_targets)

        discovered_endpoints = unique_list(discovered_endpoints)
        save_txt(out_file, discovered_endpoints)
        print(f"  [kiterunner] Discovered {len(discovered_endpoints)} active API routes")

    except Exception as e:
        print(f"[-] Kiterunner error: {e}")

    return discovered_endpoints


# =========================================================
# 📚 WORDLIST-BASED PARAM GUESSING (SMART)
# =========================================================
COMMON_PARAMS = [
    # Core IDOR, Business Logic & Data retrieval
    "id", "user", "username", "email", "account", "profile", "order", "cart", 
    "number", "customer", "role", "group", "item", "product", "category",
    "client_id", "account_id", "user_id", "org_id", "shop_id", "invoice_id", 
    "ticket_id", "receipt_id", "transaction", "ref", "reference", "amount", 
    "price", "discount", "coupon", "promo", "wallet_id", "member_id", "emp_id",
    
    # Auth, Tokens & Secrets
    "token", "auth", "key", "api_key", "secret", "password", "pass", "pwd", 
    "session", "cookie", "jwt", "admin", "login", "credential", "signature",
    "passwd", "pin", "api_token", "auth_token", "access_token", "refresh_token", 
    "client_secret", "secret_key", "public_key", "private_key", "cert", "certificate",
    
    # LFI, Path Traversal & File Inclusion
    "file", "path", "folder", "dir", "document", "doc", "root", "pg", 
    "style", "pdf", "template", "include", "layout", "page", "view",
    "file_name", "file_path", "filepath", "document_id", "doc_id", "img", 
    "image", "video", "media", "download", "load", "import", "export", "source", "src",
    
    # SSRF, Open Redirect & Network
    "url", "redirect", "return", "next", "uri", "continue", "window", 
    "to", "out", "site", "domain", "host", "callback", "target", "dest", "destination",
    "link", "host_url", "ping", "ip", "address", "host_name", "domain_name", 
    "endpoint", "req", "request", "fetch", "forward", "proxy", "proxy_url",
    
    # SQLi, NoSQLi, Filtering & Search
    "search", "query", "q", "sort", "filter", "limit", "offset", "type", 
    "action", "action_id", "row", "col", "start", "end", "date",
    "sort_by", "order_by", "asc", "desc", "keyword", "term", "q_search", "search_term", 
    "fields", "expand", "include_docs", "exclude", "page_size", "per_page", 
    "max", "min", "start_date", "end_date", "from", "lang", "locale", "jsonp", "cb",
    
    # RCE, Debug, Config & Admin
    "config", "setup", "debug", "test", "mode", "env", "version", "v",
    "admin_id", "role_id", "is_admin", "superuser", "privilege", "cmd", 
    "exec", "command", "run", "eval", "execute", "daemon", "service", "system"
]


def guess_params(endpoints):
    guessed = set()

    for ep in endpoints:
        try:
            parsed = urlparse(ep)
            # 1. Native extraction of query params (fallback for unfurl)
            if parsed.query:
                for param_pair in parsed.query.split('&'):
                    if '=' in param_pair:
                        guessed.add(param_pair.split('=')[0].lower())
                    else:
                        guessed.add(param_pair.lower())

            # 2. Intelligent guessing based on URL path segments
            segments = [s.lower() for s in parsed.path.split('/') if s]
            for segment in segments:
                # Remove file extensions
                clean_seg = segment.split('.')[0]
                
                # Exact match against common params
                if clean_seg in COMMON_PARAMS:
                    guessed.add(clean_seg)
                
                # Plural to ID guessing (e.g., /users/ -> user_id)
                if clean_seg.endswith('s') and clean_seg[:-1] + '_id' in COMMON_PARAMS:
                    guessed.add(clean_seg[:-1] + '_id')
                    
                # Direct id guessing (e.g., /user/ -> user_id)
                if clean_seg + '_id' in COMMON_PARAMS:
                    guessed.add(clean_seg + '_id')
        except:
            pass

    return list(guessed)


# =========================================================
# 🎯 GENERATE FUZZABLE ENDPOINTS (QSREPLACE)
# =========================================================
def generate_fuzzable_endpoints(endpoints, paths):
    """
    Passes endpoints with parameters through qsreplace to generate FUZZ-ready targets.
    """
    param_urls = [ep for ep in endpoints if "?" in ep and ep.startswith("http")]
    if not param_urls:
        return []
        
    print(f"[+] Generating fuzz-ready endpoints with qsreplace ({len(param_urls)} targets)...")
    
    tmp_in = os.path.join(paths['params'], "tmp_fuzz_in.txt")
    save_txt(tmp_in, param_urls)
    
    fuzzable = []
    try:
        cmd = f"cat {tmp_in} | {QSREPLACE} FUZZ"
        from core.runner import run_command_shell
        lines = run_command_shell(cmd, cwd=paths['params'])
        fuzzable = unique_list([l.strip() for l in lines if l.strip().startswith("http")])
        save_txt(f"{paths['params']}/endpoints_fuzzable.txt", fuzzable)
        print(f"  [qsreplace] Generated {len(fuzzable)} fuzzable endpoints")
    except Exception as e:
        print(f"[-] Error generating fuzzable endpoints: {e}")
    finally:
        if os.path.exists(tmp_in):
            try: os.remove(tmp_in)
            except: pass
            
    return fuzzable


# =========================================================
# 🧠 MAIN PARAM DISCOVERY
# =========================================================
def run_param_discovery(domain, endpoints, top_targets, paths, base_latency=5):
    print("\n[+] Parameter Discovery (PRO)\n")

    # 1. Passive Discovery
    url_params = extract_params_from_urls(endpoints)
    ps_urls = run_paramspider(domain, paths, base_latency=base_latency)
    
    # ---------------------------------------------
    # 💀 DEAD-URL FILTERING (CROSS-REFERENCE HOSTS)
    # ---------------------------------------------
    alive_hosts = set()
    for t in top_targets:
        try:
            parsed_host = urlparse(t).netloc
            if parsed_host:
                alive_hosts.add(parsed_host)
            else:
                alive_hosts.add(t) # Fallback if no protocol
        except: pass

    filtered_ps_urls = []
    for u in ps_urls:
        try:
            u_host = urlparse(u).netloc.lower()
            if not alive_hosts or u_host in alive_hosts or is_valid_subdomain(u_host, domain):
                filtered_ps_urls.append(u)
        except: pass

    ps_urls = unique_list(filtered_ps_urls)
    ps_params = extract_params_from_urls(ps_urls)
    print(f"  [paramspider] Filtered to {len(ps_urls)} active in-scope targets ({len(ps_params)} unique params)")
    
    guessed_params = guess_params(endpoints)

    # 2. Build Custom Wordlist from Passive Intelligence
    custom_params = unique_list(url_params + ps_params + guessed_params)
    custom_wordlist_path = f"{paths['params']}/custom_wordlist.txt"
    save_txt(custom_wordlist_path, custom_params)
    print(f"[+] Saved {len(custom_params)} intelligent params to feed into active fuzzers")

    # 3. Preserve ParamSpider URLs for Vulnerability Scanning!
    # By merging them into endpoints, they get scored and passed to Nuclei
    if ps_urls:
        endpoints = unique_list(endpoints + ps_urls)

    # 4. Active Discovery (Feeding the Custom Wordlist)
    arjun_params = run_arjun(top_targets, paths, base_latency=base_latency, custom_wordlist=custom_wordlist_path)
    x8_params = run_x8(top_targets, paths, base_latency=base_latency, custom_wordlist=custom_wordlist_path)

    # 5. Merge and sanitize all discovered params
    raw_all_params = unique_list(custom_params + arjun_params + x8_params)
    clean_all_params = []
    for p in raw_all_params:
        p_clean = str(p).strip().strip('"\'')
        if p_clean and re.match(r'^[a-zA-Z0-9_\-\.\[\]]+$', p_clean) and not p_clean.startswith("diffs"):
            clean_all_params.append(p_clean)
            
    # Filter out analytics noise parameters (keep authentic discovered params)
    filtered_params = [p for p in clean_all_params if p.lower() not in NOISE_PARAMS]
    all_params = unique_list(filtered_params)

    # 6. Generate fuzzable endpoints using qsreplace
    fuzzable_endpoints = generate_fuzzable_endpoints(endpoints, paths)

    # 7. Score per endpoint
    scored_targets = []

    for ep in endpoints:
        params_in_ep = []

        if "?" in ep:
            params_in_ep = [
                p.split("=")[0]
                for p in ep.split("?")[1].split("&")
            ]

        score = score_params(ep, params_in_ep)

        # bonus if sensitive keywords
        if keyword_score(ep) >= 4:
            score += 3

        scored_targets.append({
            "endpoint": ep,
            "params": params_in_ep,
            "score": score
        })

    scored_targets = sorted(scored_targets, key=lambda x: x["score"], reverse=True)

    # 8. Categorize endpoints by vulnerability types
    sqli_keywords = ["id", "select", "sort", "order", "query", "filter", "row", "limit", "col", "by", "search"]
    ssrf_keywords = ["url", "redirect", "dest", "destination", "next", "return", "callback", "uri", "to", "out", "host", "target", "site", "link", "fetch", "forward", "proxy"]
    lfi_keywords = ["file", "path", "dir", "folder", "document", "doc", "root", "pg", "style", "pdf", "template", "include", "view", "media", "load", "download", "import", "source", "src"]
    idor_keywords = ["user_id", "account_id", "order_id", "ticket_id", "invoice_id", "customer_id", "member_id", "org_id", "client_id", "profile_id", "item_id", "doc_id", "file_id"]
    xss_keywords = ["q", "query", "search", "name", "msg", "message", "title", "text", "comment", "desc", "keyword", "term"]

    endpoints_sqli = []
    endpoints_ssrf = []
    endpoints_lfi = []
    endpoints_idor = []
    endpoints_xss = []

    for ep in endpoints:
        if "?" not in ep: continue
        query_str = ep.split("?")[1].lower()
        params_keys = [p.split("=")[0] for p in query_str.split("&")]

        if any(p in sqli_keywords for p in params_keys):
            endpoints_sqli.append(ep)
        if any(p in ssrf_keywords for p in params_keys):
            endpoints_ssrf.append(ep)
        if any(p in lfi_keywords for p in params_keys):
            endpoints_lfi.append(ep)
        if any(p in idor_keywords or p.endswith("_id") for p in params_keys):
            endpoints_idor.append(ep)
        if any(p in xss_keywords for p in params_keys):
            endpoints_xss.append(ep)

    endpoints_sqli = unique_list(endpoints_sqli)
    endpoints_ssrf = unique_list(endpoints_ssrf)
    endpoints_lfi = unique_list(endpoints_lfi)
    endpoints_idor = unique_list(endpoints_idor)
    endpoints_xss = unique_list(endpoints_xss)

    vuln_dir = paths.get('params_vuln', paths['params'])
    save_txt(f"{vuln_dir}/endpoints_sqli.txt", endpoints_sqli)
    save_txt(f"{vuln_dir}/endpoints_ssrf.txt", endpoints_ssrf)
    save_txt(f"{vuln_dir}/endpoints_lfi.txt", endpoints_lfi)
    save_txt(f"{vuln_dir}/endpoints_idor.txt", endpoints_idor)
    save_txt(f"{vuln_dir}/endpoints_xss.txt", endpoints_xss)

    # SAVE
    save_txt(f"{paths['params']}/all_params.txt", all_params)
    save_txt(f"{paths['params']}/all_params_clean.txt", clean_data(all_params))
    save_json(f"{paths['params']}/scored_params.json", scored_targets)

    # 📝 SAVE HUMAN-READABLE PARAMETER REPORT
    with open(f"{paths['params']}/parameter_report.txt", "w") as f:
        f.write(f"🎯 PARAMETER DISCOVERY REPORT: {domain}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"📦 Total Unique Parameters Found: {len(all_params)}\n")
        f.write(f"⚡ Fuzzable Endpoints Generated:  {len(fuzzable_endpoints)}\n\n")
        
        f.write("🎯 VULNERABILITY TARGET BREAKDOWN\n")
        f.write("-" * 30 + "\n")
        f.write(f"💉 SQLi Targets:  {len(endpoints_sqli)}\n")
        f.write(f"🌐 SSRF Targets:  {len(endpoints_ssrf)}\n")
        f.write(f"📁 LFI Targets:   {len(endpoints_lfi)}\n")
        f.write(f"🔑 IDOR Targets:  {len(endpoints_idor)}\n")
        f.write(f"⚡ XSS Targets:   {len(endpoints_xss)}\n\n")

        f.write("📦 POPULAR DISCOVERED PARAMETERS\n")
        f.write("-" * 30 + "\n")
        f.write(", ".join(all_params[:50])) # Show first 50
        if len(all_params) > 50:
            f.write(f" ... and {len(all_params) - 50} more\n")
        f.write("\n\n")

        f.write("🔥 TOP SCORED ENDPOINTS (WITH PARAMS)\n")
        f.write("=" * 60 + "\n")
        for st in scored_targets[:30]: # Top 30
            if st["params"]:
                f.write(f"Endpoint: {st['endpoint']}\n")
                f.write(f"Params:   {', '.join(st['params'])}\n")
                f.write(f"Score:    {st['score']}\n")
                f.write("-" * 30 + "\n")

    print(f"[+] Total params found: {len(all_params)}")
    print(f"  [breakdown] passive/custom: {len(custom_params)} | arjun: {len(arjun_params)} | x8: {len(x8_params)}")
    print(f"[+] Fuzzable endpoints generated: {len(fuzzable_endpoints)}")
    print(f"[+] Vulnerability targets -> SQLi:{len(endpoints_sqli)} SSRF:{len(endpoints_ssrf)} LFI:{len(endpoints_lfi)} IDOR:{len(endpoints_idor)} XSS:{len(endpoints_xss)}")
    print(f"[+] High-value endpoints: {len(scored_targets)}")

    return all_params, scored_targets
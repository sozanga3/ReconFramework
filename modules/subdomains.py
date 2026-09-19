import subprocess
import json
from core.output import save_txt, save_json, debug_log, unique_list
from config.api_keys import CHAOS_KEY
from config.wordlists import DNS_WORDLIST, RESOLVERS_LIST
from config.settings import (
    AMASS_TIMEOUT, AMASS_MAX_DNS_QUERIES, PUREDNS_RESOLVERS, PUREDNS_RATE_LIMIT,
    SUBFINDER_TIMEOUT, SUBFINDER_RATE_LIMIT, DNSX_RATE_LIMIT, FINDOMAIN_THREADS, CRTSH_TIMEOUT,
    KNOCKPY_TIMEOUT, KNOCKPY_THREADS, ALTERX_LIMIT
)
import requests
import urllib.request
import re
import time
import os
import shutil
from modules.github_recon import github_subdomains
from core.utils import get_tool_timeout, get_amass_timeout, get_api_timeout, is_valid_subdomain
from config.tools import (
    SUBFINDER, ASSETFINDER, FINDOMAIN, CHAOS, AMASS, 
    SUBSCRAPER, KNOCKPY, PUREDNS, DNSX, SHUFFLEDNS, ALTERX,
    TLSX, MASSDNS, is_tool_available
)
from core.runner import run_command

# =========================================================
# ⚙️ RESOLVER HELPER
# =========================================================
def ensure_resolvers(resolvers_file=PUREDNS_RESOLVERS, debug=False):
    """
    Ensures that a valid resolver list exists, downloading public resolvers if needed,
    and falling back to bundled high-availability resolvers.
    """
    if not os.path.exists(resolvers_file):
        try:
            print(f"[+] Downloading public resolvers to {resolvers_file}")
            os.makedirs(os.path.dirname(resolvers_file), exist_ok=True)
            urllib.request.urlretrieve("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt", resolvers_file)
        except Exception as e:
            if debug:
                print(f"[DEBUG] Failed to download resolvers: {e}")
            if RESOLVERS_LIST and os.path.exists(RESOLVERS_LIST):
                try:
                    shutil.copyfile(RESOLVERS_LIST, resolvers_file)
                    return resolvers_file
                except Exception:
                    return RESOLVERS_LIST
            return None
    return resolvers_file

# =========================================================
# 🔍 TOOL WRAPPERS
# =========================================================
def subfinder(domain, paths, base_latency=5, rate_limit=None):
    if not is_tool_available(SUBFINDER):
        return []
    req_timeout = max(5, min(15, base_latency * 2))
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    rl = rate_limit if rate_limit else SUBFINDER_RATE_LIMIT
    res = run_command([SUBFINDER, "-d", domain, "-timeout", str(req_timeout), "-max-time", "10", "-rl", str(rl), "-silent", "-all"], timeout=SUBFINDER_TIMEOUT + 60, cwd=raw_dir)
    save_txt(f"{raw_dir}/subfinder_raw.txt", res)
    return res


def assetfinder(domain, paths):
    if not is_tool_available(ASSETFINDER):
        return []
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    res = run_command([ASSETFINDER, "--subs-only", domain], cwd=raw_dir)
    save_txt(f"{raw_dir}/assetfinder_raw.txt", res)
    return res


def findomain(domain, paths, base_latency=5):
    if not is_tool_available(FINDOMAIN):
        return []
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    res = run_command([FINDOMAIN, "-t", domain, "-q"], cwd=raw_dir)
    save_txt(f"{raw_dir}/findomain_raw.txt", res)
    return res


def run_tlsx(domain, paths, base_latency=5):
    if not is_tool_available(TLSX):
        return []
    print("[+] Running tlsx (SAN Certificate Recon)")
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    timeout = get_tool_timeout(base_latency, "fast")
    cmd = [TLSX, "-u", domain, "-san", "-cn", "-silent", "-resp-only"]
    res_lines = run_command(cmd, timeout=timeout * 2, cwd=raw_dir)
    subs = [l.strip() for l in res_lines if is_valid_subdomain(l.strip(), domain)]
    save_txt(f"{raw_dir}/tlsx_raw.txt", subs)
    return subs


def chaos(domain, paths):
    """Run ProjectDiscovery Chaos to enumerate subdomains.
    Added debug_path to capture any tool errors so missing output can be diagnosed.
    """
    if not CHAOS_KEY or not is_tool_available(CHAOS):
        return []
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    debug_file = f"{paths['base']}/debug.txt"
    res = run_command([CHAOS, "-d", domain, "-silent", "-key", CHAOS_KEY], cwd=raw_dir, debug_path=debug_file)
    save_txt(f"{raw_dir}/chaos_raw.txt", res)
    return res


def _parse_amass_output(stdout_lines, output_file, domain):
    """Helper to collect and deduplicate valid subdomains from Amass output file and stdout."""
    subs = set()
    
    # 1. Read from -oA text file if generated
    txt_file = output_file if output_file.endswith(".txt") else f"{output_file}.txt"
    if os.path.exists(txt_file):
        try:
            with open(txt_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if parts:
                        sub = parts[0].strip().rstrip(".")
                        if is_valid_subdomain(sub, domain):
                            subs.add(sub)
        except Exception:
            pass
            
    # 2. Parse from stdout
    if stdout_lines:
        for line in stdout_lines:
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("[") or "No names were discovered" in line_clean:
                continue
            parts = line_clean.split()
            if parts:
                candidate = parts[0].strip().rstrip(".")
                if is_valid_subdomain(candidate, domain):
                    subs.add(candidate)
                    
    return sorted(list(subs))


def amass_passive(domain, paths, base_latency=5, debug=False):
    if not is_tool_available(AMASS):
        return []
    print("[+] Running Amass (Passive - Optimized)")
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    debug_file = f"{paths['base']}/debug.txt"
    timeout_mins = get_amass_timeout(base_latency, is_active=False)
    amass_dir = f"{raw_dir}/amass_db_passive"
    out_prefix = f"{raw_dir}/amass_passive"
    
    cmd_enum = [
        AMASS, "enum",
        "-passive",
        "-d", domain,
        "-timeout", str(timeout_mins),
        "-nocolor",
        "-oA", out_prefix,
        "-dir", amass_dir
    ]

    res = run_command(cmd_enum, timeout=(timeout_mins * 60) + 60, cwd=raw_dir, debug_path=debug_file)
    subs = _parse_amass_output(res, out_prefix, domain)
    save_txt(f"{raw_dir}/amass_passive_raw.txt", subs)
    return subs


def amass_active(domain, paths, base_latency=5, debug=False):
    if not is_tool_available(AMASS):
        return []
    print("[+] Running Amass (Active Brute-force - Optimized)")
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    debug_file = f"{paths['base']}/debug.txt"
    timeout_mins = get_amass_timeout(base_latency, is_active=True)
    amass_dir = f"{raw_dir}/amass_db_active"
    out_prefix = f"{raw_dir}/amass_active"
    
    cmd_enum = [
        AMASS, "enum",
        "-active",
        "-brute",
        "-norecursive",
        "-timeout", str(timeout_mins),
        "-d", domain,
        "-nocolor",
        "-oA", out_prefix,
        "-dir", amass_dir
    ]
    if os.path.exists(DNS_WORDLIST):
        cmd_enum.extend(["-w", DNS_WORDLIST])

    res = run_command(cmd_enum, timeout=timeout_mins * 60 + 60, cwd=raw_dir, debug_path=debug_file)
    subs = _parse_amass_output(res, out_prefix, domain)
    save_txt(f"{raw_dir}/amass_active_raw.txt", subs)
    return subs


def subscraper(domain, paths):
    if not is_tool_available(SUBSCRAPER):
        return []
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    res = run_command(["python3", SUBSCRAPER, "-d", domain, "-silent"], cwd=raw_dir)
    save_txt(f"{raw_dir}/subscraper_raw.txt", res)
    return res

def run_dnsx(domain, paths, base_latency=5, rate_limit=None):
    if not is_tool_available(DNSX):
        return []
    print("[+] Running dnsx (Active Brute-force)")
    dns_dir = paths.get('subdomains_dns', paths['subdomains'])
    timeout = get_tool_timeout(base_latency, "heavy")
    if not os.path.exists(DNS_WORDLIST):
        return []
    safe_timeout = timeout * 3
    rl = rate_limit if rate_limit else DNSX_RATE_LIMIT
    cmd = [
        DNSX, "-d", domain, "-w", DNS_WORDLIST, "-a", "-aaaa", "-cname", "-resp",
        "-cdn", "-retry", "2", "-rl", str(rl), "-t", "200", "-silent",
        "-auto-wildcard", "-wt", "5"
    ]
    
    # Use resolvers if available to speed up and avoid local rate limits
    if os.path.exists(PUREDNS_RESOLVERS):
        cmd.extend(["-r", PUREDNS_RESOLVERS])
        
    raw_res = run_command(cmd, timeout=safe_timeout, cwd=dns_dir)
    res = [l.strip().split()[0] for l in raw_res if l.strip() and is_valid_subdomain(l.strip().split()[0], domain)]
    save_txt(f"{dns_dir}/dnsx_raw.txt", res)
    return res


def run_shuffledns(domain, paths, base_latency=5, debug=False):
    if not is_tool_available(SHUFFLEDNS):
        return []
    print("[+] Running shuffleDNS (Active Resolution/Brute-force)")
    dns_dir = paths.get('subdomains_dns', paths['subdomains'])
    debug_file = f"{paths['base']}/debug.txt"
    timeout = get_tool_timeout(base_latency, "heavy")
    
    res_file = ensure_resolvers(PUREDNS_RESOLVERS, debug=debug)
    cmd = [SHUFFLEDNS, "-d", domain, "-mode", "bruteforce", "-silent", "-sw"]
    
    if is_tool_available(MASSDNS):
        cmd.extend(["-m", MASSDNS])
    if os.path.exists(DNS_WORDLIST):
        cmd.extend(["-w", DNS_WORDLIST])
    if res_file and os.path.exists(res_file):
        cmd.extend(["-r", res_file])
        
    res = run_command(cmd, timeout=timeout * 3, cwd=dns_dir, debug_path=debug_file)
    valid_subs = [l.strip() for l in res if l.strip() and is_valid_subdomain(l.strip(), domain)]
    save_txt(f"{dns_dir}/shuffledns_raw.txt", valid_subs)
    return valid_subs


def run_alterx(domain, paths, subs=None, debug=False, base_latency=5):
    print("[+] Running alterx (Smart Domain Permutation Engine)")
    dns_dir = paths.get('subdomains_dns', paths['subdomains'])
    
    sub_file = os.path.abspath(f"{dns_dir}/pre_alterx.txt")
    seed_subs = list(subs) if subs else [domain]
    if domain not in seed_subs:
        seed_subs.append(domain)
        
    save_txt(sub_file, seed_subs)
    
    cmd = [ALTERX, "-l", sub_file, "-enrich", "-silent", "-limit", str(ALTERX_LIMIT)]
    
    # 1. Generate candidate permutations
    try:
        timeout = get_tool_timeout(base_latency, "heavy")
        raw_perms = run_command(cmd, timeout=timeout * 2, cwd=dns_dir)
        if not raw_perms:
            return []
            
        cand_file = os.path.abspath(f"{dns_dir}/alterx_candidates.txt")
        save_txt(cand_file, raw_perms)
        print(f"[+] alterx generated {len(raw_perms)} permutation candidates. Verifying alive status...")

        # 2. Active DNS resolution to keep ONLY alive subdomains
        resolvers_file = ensure_resolvers(PUREDNS_RESOLVERS, debug=debug)
        out_file = os.path.abspath(f"{dns_dir}/alterx_alive.txt")
        if resolvers_file and os.path.exists(resolvers_file):
            resolve_cmd = [PUREDNS, "resolve", cand_file, "-r", resolvers_file, "-w", out_file, "-q", "-l", str(PUREDNS_RATE_LIMIT)]
            try:
                run_command(resolve_cmd, timeout=300, cwd=dns_dir)
                if os.path.exists(out_file):
                    with open(out_file, "r") as f:
                        alive_subs = [line.strip() for line in f if line.strip() and is_valid_subdomain(line.strip(), domain)]
                    print(f"[+] alterx validation: {len(alive_subs)} / {len(raw_perms)} subdomains are ALIVE")
                    save_txt(f"{dns_dir}/alterx_raw.txt", alive_subs)
                    return alive_subs
            except Exception as e:
                if debug:
                    print(f"[DEBUG] alterx resolution error: {e}")

        return []
    except Exception as e:
        if debug:
            print(f"[DEBUG] alterx execution error: {e}")
        return []
    finally:
        cand_file = os.path.abspath(f"{dns_dir}/alterx_candidates.txt")
        if os.path.exists(cand_file):
            try:
                os.remove(cand_file)
            except Exception:
                pass







def run_crtsh(domain, paths, base_latency=5, debug=False):
    print("[+] Running crt.sh")

    subs = set()
    # Specialized tight timeout for API calls
    timeout = get_api_timeout(base_latency)
    # Professional User-Agent to avoid crt.sh blocks
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
    }
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        # Increase timeout and add retry logic for crt.sh
        for attempt in range(2):
            try:
                r = requests.get(url, headers=headers, timeout=CRTSH_TIMEOUT)
                if r.status_code == 200:
                    break
                time.sleep(2)
            except:
                if attempt == 1: raise
                time.sleep(5)

        if r.status_code != 200:
            print(f"[!] crt.sh HTTP {r.status_code} for {domain}")
            return []

        # Log a snippet of the response to see if it's a block page
        if debug:
            print(f"[DEBUG] crt.sh response snippet: {r.text[:100]}")

        if not r.text.strip():
            raise Exception("Empty response")

        try:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub_clean = sub.strip().replace("*.", "")
                    if is_valid_subdomain(sub_clean, domain):
                        subs.add(sub_clean)
        except:
            # fallback if response is broken (common when large)
            if debug:
                print("[DEBUG] crt.sh returned non-JSON, using fallback parsing")

            for line in r.text.split("\n"):
                if domain in line:
                    # extract anything that looks like a subdomain
                    matches = re.findall(rf"(?:[a-zA-Z0-9_-]+\.)*{re.escape(domain)}", line)
                    for m in matches:
                        if is_valid_subdomain(m.strip(), domain):
                            subs.add(m.strip())

        print(f"[+] crtsh: {len(subs)}")
        raw_dir = paths.get('subdomains_raw', paths['subdomains'])
        save_txt(f"{raw_dir}/crtsh_raw.txt", list(subs))
        return list(subs)

    except Exception as e:
        if debug:
            print(f"[DEBUG] [crtsh error] {e}")
        return []



def run_knockpy(domain, paths, base_latency=5, debug=False):
    if not is_tool_available(KNOCKPY):
        return []
    print("[+] Running knockpy")

    output_file = f"{paths['subdomains']}/knockpy.json"

    try:
        timeout = max(KNOCKPY_TIMEOUT, get_tool_timeout(base_latency, "heavy"))  # Use setting as floor
        # ✅ CLEAN command (NO shell redirection)
        cmd = [
            KNOCKPY,
            "-d", domain,
            "--recon",
            "--json",
            "--timeout", str(timeout),
            "--threads", str(KNOCKPY_THREADS)
        ]

        # ✅ RUN WITH run_command (debug enabled) to capture any errors
        debug_file = f"{paths['base']}/debug.txt"
        res = run_command(cmd, timeout=timeout * 2, cwd=paths['subdomains'], debug_path=debug_file)
        
        # knockpy saves to a file by itself if it didn't crash, but we want to be sure
        if not os.path.exists(output_file) and res:
            save_txt(output_file, res)

        # ✅ WAIT (VERY IMPORTANT)
        time.sleep(3)

        # ✅ VALIDATE FILE
        if not os.path.exists(output_file):
            if debug:
                print("[DEBUG] knockpy file not created")
            return []

        if os.path.getsize(output_file) < 50:
            if debug:
                print("[DEBUG] knockpy file too small")
            return []

        # ✅ READ FILE
        with open(output_file, "r") as f:
            raw = f.read().strip()

        if not raw:
            return []

        # ✅ ROBUST JSON EXTRACTION
        start_chars = [raw.find("["), raw.find("{")]
        start_idx = min([i for i in start_chars if i != -1] or [0])
        
        end_chars = [raw.rfind("]"), raw.rfind("}")]
        end_idx = max([i for i in end_chars if i != -1] or [len(raw)])
        
        raw = raw[start_idx:end_idx + 1]

        # ✅ PARSE JSON
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        subs = set()

        # ✅ HANDLE BOTH LIST AND DICT (v9 behavior)
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    sub = entry.get("domain")
                    if sub and is_valid_subdomain(sub, domain):
                        subs.add(sub.strip())
        elif isinstance(data, dict):
            sub = data.get("domain")
            if sub and is_valid_subdomain(sub, domain):
                subs.add(sub.strip())

        print(f"[+] knockpy: {len(subs)}")
        return list(subs)

    except Exception as e:
        if debug:
            print(f"[DEBUG] knockpy error: {e}")
        return []
# =========================================================
# 🧬 DNS PERMUTATION & BRUTE FORCE
# =========================================================
import urllib.request
def brute_force_subdomains(subs, domain, paths, debug=False):
    print("[+] Generating DNS permutations (Advanced Mode)")
    
    words = [
        # --- Core & Common ---
        "api", "dev", "staging", "test", "v1", "v2", "admin", "dashboard", "portal", "internal", 
        "mail", "vpn", "cdn", "sso", "auth", "login", "register", "signup", "shop", "store", 
        "blog", "news", "support", "help", "docs", "devops", "k8s", "docker", "jenkins", "git", 
        "gitlab", "github", "jira", "confluence", "slack", "discord", "zoom", "teams", "meet",
        
        # --- Infrastructure & Cloud ---
        "cloud", "storage", "s3", "bucket", "assets", "static", "img", "media", "video", "stream", 
        "aws", "azure", "gcp", "do", "linode", "vultr", "heroku", "vercel", "netlify", "cloudflare", 
        "fastly", "akamai", "bastion", "jump", "ssh", "gateway", "lb", "proxy", "edge", "k8s",
        "kubernetes", "cluster", "node", "pod", "registry", "helm", "terraform", "ansible",
        
        # --- Environments ---
        "prod", "production", "uat", "qa", "demo", "sandbox", "beta", "alpha", "old", "new", 
        "legacy", "backup", "archive", "preprod", "nonprod", "stg", "stg1", "stg2", "dev1", "dev2",
        "local", "localhost", "site", "web", "www2", "www3", "pub", "public", "priv", "private",
        
        # --- Database & Tech ---
        "sql", "db", "database", "redis", "elastic", "mongo", "pg", "mysql", "vault", "vault-api", 
        "prometheus", "grafana", "kibana", "log", "logs", "monitor", "status", "health", "check", 
        "callback", "webhook", "secure", "ssm", "secret", "private", "corp", "office", "intra", 
        "intranet", "search", "index", "cache", "broker", "queue", "mq", "kafka", "rabbit",
        
        # --- Regional ---
        "us", "uk", "eu", "asia", "jp", "de", "fr", "ca", "au", "br", "in", "cn", "east", "west",
        "north", "south", "central", "dc", "region", "zone", "cluster1", "cluster2",
        
        # --- Departmental & Business ---
        "hr", "finance", "legal", "sales", "marketing", "pr", "rnd", "engineering", "ops", "tech",
        "corp", "enterprise", "partner", "affiliate", "customer", "client", "service", "billing", 
        "pay", "payment", "stripe", "paypal", "checkout", "cart", "order", "invoice", "hrportal",
        
        # --- Communication & Security ---
        "mailer", "sendgrid", "mailgun", "mfa", "imap", "pop3", "smtp", "owa", "autodiscover", 
        "sip", "voip", "mobile", "ios", "android", "m", "api-gateway", "microservice", "auth-api", 
        "user-api", "soc", "siem", "splunk", "okta", "duo", "sentinel", "crowdstrike", "qualys", 
        "nessus", "nexpose", "firewall", "vpn1", "vpn2", "fortigate", "cisco", "anyconnect"
    ]
    
    permutations = set()
    
    # 🧠 SMART PERMUTATION LOGIC (BOUNDED)
    seed_subs = list(subs)[:40]
    for sub in seed_subs:
        if sub.endswith("." + domain):
            prefix = sub[:-len(domain)-1]
        else:
            prefix = ""
        if not prefix or prefix == domain:
            continue
            
        for w in words:
            # Hyphenated (e.g., api-dev.target.com)
            permutations.add(f"{w}-{prefix}.{domain}")
            permutations.add(f"{prefix}-{w}.{domain}")
            
            # Nested (e.g., dev.api.target.com and api.dev.target.com)
            permutations.add(f"{w}.{sub}")
            permutations.add(f"{prefix}.{w}.{domain}")
            
            # Concatenated (e.g., apidev.target.com)
            permutations.add(f"{w}{prefix}.{domain}")
            permutations.add(f"{prefix}{w}.{domain}")
            
        # Numeric increments (e.g., api1, api-01)
        for i in range(1, 4):
            permutations.add(f"{prefix}{i}.{domain}")
            permutations.add(f"{prefix}-0{i}.{domain}")

    # Add base words to domain
    for w in words:
        permutations.add(f"{w}.{domain}")
        
    if not permutations:
        return []
        
    perm_file = os.path.abspath(f"{paths['subdomains']}/permutations.txt")
    with open(perm_file, "w") as f:
        for p in permutations:
            f.write(p + "\n")
            
    resolvers_file = ensure_resolvers(PUREDNS_RESOLVERS, debug=debug)
    if not resolvers_file or not os.path.exists(resolvers_file):
        return []
            
    out_file = os.path.abspath(f"{paths['subdomains']}/puredns.txt")
    # puredns resolve with silence, quiet mode, and strict rate limiting
    cmd = [PUREDNS, "resolve", perm_file, "-r", resolvers_file, "-w", out_file, "-q", "-l", str(PUREDNS_RATE_LIMIT)]
    
    try:
        # Give it a safe timeout, as millions of permutations could otherwise hang
        run_command(cmd, timeout=3600)
        if os.path.exists(out_file):
            with open(out_file, "r") as f:
                valid_subs = [line.strip() for line in f if line.strip() and is_valid_subdomain(line.strip(), domain)]
            print(f"[+] puredns found {len(valid_subs)} hidden subdomains via permutations")
            save_txt(f"{paths['subdomains']}/puredns_raw.txt", valid_subs)
            return valid_subs
    except Exception as e:
        if debug: print(f"[DEBUG] puredns error: {e}")
    finally:
        if os.path.exists(perm_file):
            try:
                os.remove(perm_file)
            except Exception:
                pass
        
    return []

def check_wildcard_domain(domain):
    """
    Actively checks if target domain has wildcard DNS by resolving random subdomains.
    Returns (has_wildcard: bool, wildcard_ips: set).
    """
    import socket
    import uuid
    wildcard_ips = set()
    hits = 0
    for _ in range(3):
        rand_host = f"wctest-{uuid.uuid4().hex[:8]}.{domain}"
        try:
            answers = socket.getaddrinfo(rand_host, None, socket.AF_INET)
            for a in answers:
                wildcard_ips.add(a[4][0])
            hits += 1
        except Exception:
            pass
    return (hits >= 2), wildcard_ips


def filter_wildcards(subs, domain, paths, debug=False):
    print("\n[+] Filtering wildcard records & resolving active subdomains (puredns)")
    if not subs:
        return []
        
    has_wildcard, wildcard_ips = check_wildcard_domain(domain)
    if has_wildcard:
        print(f"  [!] Alert: Wildcard DNS detected on {domain} (wildcard IPs: {', '.join(sorted(wildcard_ips))})")

    resolvers_file = ensure_resolvers(PUREDNS_RESOLVERS, debug=debug)
    input_file = os.path.abspath(f"{paths['subdomains']}/pre_filter.txt")
    out_file = os.path.abspath(f"{paths['subdomains']}/resolved_clean.txt")
    save_txt(input_file, subs)
    
    if resolvers_file and os.path.exists(resolvers_file) and is_tool_available(PUREDNS):
        cmd = [PUREDNS, "resolve", input_file, "-r", resolvers_file, "-w", out_file, "-q", "-l", str(PUREDNS_RATE_LIMIT)]
        try:
            run_command(cmd, timeout=3600)
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    valid = [line.strip() for line in f if line.strip() and is_valid_subdomain(line.strip(), domain)]
                print(f"[+] Wildcard filtering removed {len(subs) - len(valid)} dead/fake subdomains")
                return valid
        except Exception as e:
            if debug: print(f"[DEBUG] puredns wildcard filter error: {e}")

    # Fallback in case puredns is unavailable or failed
    if has_wildcard:
        print("[*] Running native fallback resolver to purge wildcard records...")
        import socket
        from concurrent.futures import ThreadPoolExecutor
        clean_valid = []

        def check_host(h):
            try:
                ans = socket.getaddrinfo(h, None, socket.AF_INET)
                ips = {a[4][0] for a in ans}
                # If host only resolves to wildcard IPs and is not apex/www, treat as wildcard noise
                if ips.issubset(wildcard_ips) and h not in [domain, f"www.{domain}"]:
                    return None
                return h
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=30) as pool:
            results = pool.map(check_host, subs)
            for r in results:
                if r and is_valid_subdomain(r, domain):
                    clean_valid.append(r)

        print(f"[+] Native fallback removed {len(subs) - len(clean_valid)} wildcard subdomains")
        save_txt(out_file, clean_valid)
        return clean_valid

    return subs


# =========================================================
# 🧹 CLEANING ENGINE
# =========================================================
def clean_subdomains(subs, domain):
    cleaned = set()
    
    # Strict FQDN regex
    fqdn_regex = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

    for sub in subs:
        sub = sub.strip().lower()

        if not sub:
            continue

        if sub.startswith("*."):
            sub = sub[2:]

        if "*" in sub:
            continue

        if not is_valid_subdomain(sub, domain):
            continue

        if "@" in sub:
            continue
            
        if not fqdn_regex.match(sub):
            continue

        cleaned.add(sub)

    return sorted(cleaned)


# =========================================================
# 🧠 MAIN ENUMERATION ENGINE
# =========================================================
def enumerate_subdomains(domain, paths, debug=False, base_latency=5, rate_limit=None):
    print(f"\n[+] Subdomain enumeration: {domain}")

    results = {}

    # ----------------------------
    # ⚡ FAST PASS (quick tools)
    # ----------------------------
    results["subfinder"] = subfinder(domain, paths, base_latency=base_latency, rate_limit=rate_limit)
    results["assetfinder"] = assetfinder(domain, paths)
    results["findomain"] = findomain(domain, paths, base_latency=base_latency)
    results["tlsx"] = run_tlsx(domain, paths, base_latency=base_latency)

    # ----------------------------
    # 🔎 EXTENDED PASS
    # ----------------------------
    results["chaos"] = chaos(domain, paths)
    results["amass_passive"] = amass_passive(domain, paths, base_latency=base_latency, debug=debug)
    results["crtsh"] = run_crtsh(domain, paths=paths, base_latency=base_latency)
    results["subscraper"] = subscraper(domain, paths)
    results["github"] = github_subdomains(domain, paths)

    # ----------------------------
    # 🧠 KNOCKPY
    # ----------------------------
    results["knockpy"] = run_knockpy(domain, paths, base_latency=base_latency, debug=debug)

    # ----------------------------
    # 💥 HEAVY ACTIVE PASS (Amass Active, dnsx, shuffleDNS)
    # ----------------------------
    # We run this after passive to ensure we hit hidden subdomains
    results["amass_active"] = amass_active(domain, paths, base_latency=base_latency, debug=debug)
    results["dnsx"] = run_dnsx(domain, paths, base_latency=base_latency, rate_limit=rate_limit)
    results["shuffledns"] = run_shuffledns(domain, paths, base_latency=base_latency, debug=debug)

    # ----------------------------
    # 📝 SAVE INDIVIDUAL TOOL RESULTS (SUBDOMAINS/RAW)
    # ----------------------------
    raw_dir = paths.get('subdomains_raw', paths['subdomains'])
    for tool, data in results.items():
        if data:
            save_txt(f"{raw_dir}/{tool}_raw.txt", data)

    # ----------------------------
    # 🔄 MERGE
    # ----------------------------
    all_subs = []
    for tool, data in results.items():
        print(f"[+] {tool}: {len(data)}")
        all_subs.extend(data)

    # ----------------------------
    # 🧹 CLEAN
    # ----------------------------
    final_subs = clean_subdomains(all_subs, domain)

    # ----------------------------
    # 🛡️ WILDCARD FILTERING
    # ----------------------------
    final_subs = filter_wildcards(final_subs, domain, paths, debug)

    # ----------------------------
    # 🧬 PERMUTATIONS & VERIFICATION (alterx & puredns)
    # ----------------------------
    alterx_alive_subs = run_alterx(domain, paths, subs=final_subs, debug=debug, base_latency=base_latency)
    if alterx_alive_subs:
        results["alterx"] = alterx_alive_subs
        active_dir = paths.get('subdomains_active', paths['subdomains'])
        save_txt(f"{active_dir}/alterx_alive.txt", alterx_alive_subs)
        final_subs = unique_list(final_subs + alterx_alive_subs)
        final_subs = clean_subdomains(final_subs, domain)

    hidden_subs = brute_force_subdomains(final_subs, domain, paths, debug)
    if hidden_subs:
        final_subs = unique_list(final_subs + hidden_subs)
        final_subs = clean_subdomains(final_subs, domain)

    # ----------------------------
    # 💾 SAVE
    # ----------------------------
    save_txt(f"{paths['subdomains']}/all.txt", final_subs)
    save_json(f"{paths['subdomains']}/all.json", final_subs)

    return final_subs
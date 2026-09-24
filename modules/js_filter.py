import re
from core.output import save_txt, save_json, unique_list
from core.scoring import keyword_score
from core.utils import is_valid_subdomain
from config.settings import EXCLUDED_EXTENSIONS
from config.keywords import KEYWORDS

# =========================================================
# ❌ BAD JS PATTERNS (GARBAGE / THIRD-PARTY VENDORS)
# =========================================================
BAD_JS_PATTERNS = [
    "google-analytics.com",
    "googletagmanager.com",
    "jquery.min.js",
    "jquery-ui.min.js",
    "bootstrap.min.js",
    "bootstrap.bundle.min.js",
    "fontawesome.js",
    "wp-embed.min.js",
    "wp-polyfill.min.js",
    "cloudflare.min.js",
    "recaptcha/api.js",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com", 
    "unpkg.com",
    "ajax.googleapis.com",
    "polyfill.io",
    "connect.facebook.net",
    "platform.twitter.com",
    "widget.intercom.io",
    "js.stripe.com",
    "js.braintreegateway.com",
    "snap.licdn.com",
    "static.hotjar.com",
    "cdn.segment.com",
    "cdn.optimizely.com",
    "cdn.amplitude.com",
    "rum.browser-intake-datadoghq.com",
    "cdn.cookielaw.org",
    "consent.cookiebot.com",
    "sentry.io",
    "browser.sentry-cdn.com",
    "js.hs-scripts.com",
    "js.hsforms.net",
    "bat.bing.com",
    "static.ads-twitter.com",
    "react.min.js",
    "react-dom.min.js",
    "angular.min.js",
    "vue.min.js",
    "vue.runtime.min.js",
    "lodash.min.js",
    "moment.min.js",
    "axios.min.js",
    "chart.min.js",
    "d3.min.js",
    "three.min.js",
    "gsap.min.js",
    "anime.min.js",
    "swiper.min.js",
    "owl.carousel.min.js",
    "slick.min.js",
    "select2.min.js",
    "datatables.min.js",
    "tinymce.min.js",
    "ckeditor.js",
    "popper.min.js",
]

# =========================================================
# 🛡️ RISK CATEGORIES
# =========================================================
RISK_KEYWORDS = {
    "HIGH": [
        ".env", "config", "setup", "admin", "debug", "sql", "password", "secret", "private", 
        "internal", "vpn", "root", "dev", "staging", "test", "local", "backup", "dump", 
        "schema", "database", "key", "token", "credential", "login", "auth", "session", 
        "cookie", "jwt", "apikey", "access_key", "secret_key", "id_rsa", "ssh", "passwd", "shadow",
        ".bak", ".db", ".log", ".yaml", ".yml", ".tar.gz", ".zip", ".tgz", ".pem", ".p12", ".pfx", 
        ".sqlite", ".sqlite3", ".sh", ".bash_history", ".conf"
    ],
    "MEDIUM": [
        "api", "v1", "v2", "v3", "v4", "graphql", "rest", "wp-json", "user", "upload", 
        "download", "manage", "account", "profile", "billing", "payment", "subscribe", 
        "webhook", "callback", "client", "service", "app", "mobile", "ios", "android",
        "search", "filter", "query", "order", "cart", "checkout", "shipping"
    ],
    "LOW": [
        "static", "assets", "img", "css", "js", "fonts", "image", "vendor", "lib", 
        "node_modules", "jquery", "bootstrap", "react", "vue", "angular", "ext", 
        "public", "common", "main", "bundle", "style", "theme"
    ]
}


# =========================================================
# 🧹 FILTER JS FILES (PRE-DOWNLOAD & ANALYSIS)
# =========================================================
def filter_js_files(js_files, domain=None, all_domains=None):
    """
    Filters JS file URLs removing vendor garbage, enforcing scope, and categorizing high value scripts.
    """
    clean = []
    high_value = []
    effective_domains = all_domains if all_domains else ([domain] if domain else [])

    for js in js_files:
        if not js:
            continue
        js_lower = js.lower().strip()

        # Remove known vendor garbage
        if any(bad in js_lower for bad in BAD_JS_PATTERNS):
            continue

        # If effective_domains is set, ensure external js belongs to in-scope domains
        if effective_domains and not js.startswith("/"):
            if not any(is_valid_subdomain(js, d) for d in effective_domains):
                continue

        # Classify high interest
        if keyword_score(js) >= 4:
            high_value.append(js)

        clean.append(js)

    return unique_list(clean), unique_list(high_value)


# =========================================================
# 🔗 RECONSTRUCT CORRUPTED URLS
# =========================================================
def reconstruct_corrupted_url(url, domain):
    if not url:
        return url
    url_lower = url.lower()
    
    if "xn_params.txt" in url_lower:
        idx = url_lower.find("xn_params.txt")
        rel_path = url[idx + len("xn_params.txt"):]
        if not rel_path.startswith("/"):
            rel_path = "/" + rel_path
        return f"https://{domain}{rel_path}"
        
    elif url_lower.startswith("http:///home/") or url_lower.startswith(":////home/"):
        if domain in url_lower:
            idx = url_lower.find(domain)
            rel_path = url[idx + len(domain):]
            if not rel_path.startswith("/"):
                rel_path = "/" + rel_path
            return f"https://{domain}{rel_path}"
            
    return url


# =========================================================
# 🔗 STRIP JUNK & TRACKING QUERY PARAMS
# =========================================================
def strip_junk_query_params(url):
    if not url:
        return url
    url = re.sub(r'[\?&]__cf_chl_[^&]+', '', url)
    url = re.sub(r'[\?&]utm_[^&]+', '', url)
    url = re.sub(r'[\?&]_ga[^&]+', '', url)
    url = re.sub(r'[\?&]fbclid=[^&]+', '', url)
    url = re.sub(r'[\?&]gclid=[^&]+', '', url)
    
    if '?' not in url and '&' in url:
        url = url.replace('&', '?', 1)
        
    url = re.sub(r'\?$', '', url)
    return url


# =========================================================
# 🔗 NORMALIZE AND CLEAN ENDPOINT
# =========================================================
def normalize_and_clean_endpoint(ep):
    if not ep:
        return ep
    
    ep = strip_junk_query_params(ep)
    
    while "/./" in ep:
        ep = ep.replace("/./", "/")
        
    if ep.startswith("https://"):
        ep = "https://" + ep[8:].replace("//", "/")
    elif ep.startswith("http://"):
        ep = "http://" + ep[7:].replace("//", "/")
        
    return ep


# =========================================================
# 🔗 FILTER ENDPOINTS
# =========================================================
def filter_endpoints(endpoints, domain, all_domains=None):
    clean = []
    local_prefixes = ["/home/", "/tmp/", "/var/", "/etc/", "/opt/", "/usr/", "/bin/", "/lib/", "/sys/", "/proc/", "/dev/", "/root/"]
    effective_domains = all_domains if all_domains else ([domain] if domain else [])

    junk_substrings = [
        "/undefined", "undefined.js", "/null/", "/null", "null.js", 
        "javascript:void", "javascript:false", "javascript:true",
        "shockwaveflash", "activexobject", "msxml2.xmlhttp"
    ]

    static_junk = [
        "/wp-content/themes/", "/wp-content/plugins/",
        "/wp-includes/", "/wp-admin/css/",
        "/node_modules/", "/bower_components/",
        "/vendor/", "/assets/fonts/",
        "/favicon", "/apple-touch-icon",
        "/__webpack_hmr", "/_next/static/",
        "/sockjs-node/", "/hot-update",
    ]

    for ep in endpoints:
        if not ep:
            continue
        ep_lower = ep.lower().strip()

        # remove garbage extensions
        if any(bad in ep_lower for bad in EXCLUDED_EXTENSIONS):
            continue

        # Exclude .js files from endpoints output
        if ep_lower.endswith(".js") or ".js?" in ep_lower:
            continue

        if any(junk in ep_lower for junk in junk_substrings):
            continue

        if any(sj in ep_lower for sj in static_junk):
            continue

        if "xn_params.txt" in ep_lower or ":////home/" in ep_lower or ":///home/" in ep_lower:
            ep = reconstruct_corrupted_url(ep, domain)
            
        ep = normalize_and_clean_endpoint(ep)
        ep_lower = ep.lower()

        in_scope = ep.startswith("/") or (any(is_valid_subdomain(ep, d) for d in effective_domains) if effective_domains else is_valid_subdomain(ep, domain))
        if in_scope:
            if ep.startswith("/") and any(ep_lower.startswith(pref) for pref in local_prefixes):
                continue
            if any(f"/{pref.strip('/')}/" in ep_lower for pref in local_prefixes):
                continue
            clean.append(ep)

    return unique_list(clean)


# =========================================================
# 🧠 RISK SCORING
# =========================================================
def categorize_risk(endpoints):
    risk_map = {"HIGH": [], "MEDIUM": [], "LOW": []}
    static_doc_extensions = ('.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ttf', '.eot')

    for ep in endpoints:
        ep_lower = ep.lower()
        categorized = False
        
        if ep_lower.endswith(static_doc_extensions):
            risk_map["LOW"].append(ep)
            continue

        for risk, keywords in RISK_KEYWORDS.items():
            if any(k in ep_lower for k in keywords):
                risk_map[risk].append(ep)
                categorized = True
                break
        
        if not categorized:
            risk_map["LOW"].append(ep)
            
    return risk_map


# =========================================================
# 🧠 MAIN FILTER FUNCTION
# =========================================================
def run_js_filter(domain, js_files, endpoints, paths, all_domains=None):
    print("\n[+] JS Filtering & Intelligence (Risk Analysis)\n")

    clean_js, high_js = filter_js_files(js_files, domain=domain, all_domains=all_domains)
    clean_endpoints = filter_endpoints(endpoints, domain, all_domains=all_domains)
    risk_analysis = categorize_risk(clean_endpoints)

    save_txt(f"{paths['js']}/js_filtered.txt", clean_js)
    save_txt(f"{paths['js']}/js_high_value.txt", high_js)
    save_txt(f"{paths['js']}/endpoints_filtered.txt", clean_endpoints)
    save_txt(f"{paths['js']}/endpoints_high_risk.txt", risk_analysis["HIGH"])
    save_txt(f"{paths['js']}/endpoints_medium_risk.txt", risk_analysis["MEDIUM"])
    save_json(f"{paths['js']}/risk_analysis.json", risk_analysis)

    high_interest = []
    api_endpoints = []
    param_endpoints = []
    api_patterns = [r'/api/', r'/v[0-9]+/', r'/graphql\b', r'/rest/', r'/wp-json/']

    for ep in clean_endpoints:
        ep_lower = ep.lower()
        if any(k in ep_lower for k in KEYWORDS):
            high_interest.append(ep)
        if any(re.search(pat, ep_lower) for pat in api_patterns):
            api_endpoints.append(ep)
        if "?" in ep:
            param_endpoints.append(ep)

    save_txt(f"{paths['js']}/endpoints_high_interest.txt", high_interest)
    save_txt(f"{paths['js']}/endpoints_api.txt", api_endpoints)
    save_txt(f"{paths['js']}/endpoints_params.txt", param_endpoints)

    report_file = f"{paths['js']}/endpoints_report.txt"
    with open(report_file, "w") as f:
        f.write(f"📊 ENDPOINTS INTELLIGENCE REPORT: {domain}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"🔗 Total Filtered Endpoints: {len(clean_endpoints)}\n")
        f.write(f"🔌 API / REST / GraphQL:    {len(api_endpoints)}\n")
        f.write(f"❓ Parameterized Endpoints:  {len(param_endpoints)}\n")
        f.write(f"⭐ High-Interest Endpoints:  {len(high_interest)}\n\n")
        
        f.write("🚨 RISK BREAKDOWN\n")
        f.write("-" * 30 + "\n")
        f.write(f"🔴 HIGH RISK:   {len(risk_analysis['HIGH'])}\n")
        f.write(f"🟡 MEDIUM RISK: {len(risk_analysis['MEDIUM'])}\n")
        f.write(f"🟢 LOW RISK:    {len(risk_analysis['LOW'])}\n\n")
        
        if risk_analysis["HIGH"]:
            f.write("🔥 HIGH RISK ENDPOINTS (TOP 30)\n")
            f.write("=" * 60 + "\n")
            for ep in risk_analysis["HIGH"][:30]:
                f.write(f"  • {ep}\n")
            f.write("\n")
            
        if api_endpoints:
            f.write("🔌 DISCOVERED API ROUTES (TOP 30)\n")
            f.write("=" * 60 + "\n")
            for ep in api_endpoints[:30]:
                f.write(f"  • {ep}\n")

    print("-" * 50)
    print(f"🛡️ JS RISK ANALYSIS: {domain}")
    print("-" * 50)
    print(f"🧹 Clean JS Files:     {len(clean_js)}")
    print(f"⭐ High-Value JS:      {len(high_js)}")
    print(f"🔗 Total Endpoints:    {len(clean_endpoints)}")
    print(f"🔌 API Endpoints:      {len(api_endpoints)}")
    print(f"❓ Parameterized:       {len(param_endpoints)}")
    print(f"🔴 HIGH RISK:          {len(risk_analysis['HIGH'])}")
    print(f"🟡 MEDIUM RISK:        {len(risk_analysis['MEDIUM'])}")
    print(f"🟢 LOW RISK:           {len(risk_analysis['LOW'])}")
    print("-" * 50)

    if risk_analysis["HIGH"]:
        print("\n🚨 CRITICAL ENDPOINTS (HIGH RISK):")
        for ep in risk_analysis["HIGH"][:10]:
            print(f"   [!] {ep}")
    print("-" * 50 + "\n")

    return clean_js, high_js, clean_endpoints, risk_analysis["HIGH"]
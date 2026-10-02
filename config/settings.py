# =========================================================
# ⚙️ GLOBAL TOOL SETTINGS - BALANCED PRODUCTION
# =========================================================

FRAMEWORK_VERSION = "3.2.1"

# --- Subdomain Enumeration ---
AMASS_TIMEOUT = 5            # 5 minutes (balanced production)
AMASS_MAX_DNS_QUERIES = 150  
PUREDNS_RESOLVERS = "/tmp/resolvers.txt"
PUREDNS_RATE_LIMIT = 200     # Limit to prevent home router NAT exhaustion/DoS
SUBFINDER_TIMEOUT = 300       # 5 minutes
SUBFINDER_RATE_LIMIT = 30     # Subfinder rate limit (req/s)
DNSX_RATE_LIMIT = 100         # Dnsx rate limit (req/s)
FINDOMAIN_THREADS = 25        
KNOCKPY_TIMEOUT = 120        
KNOCKPY_THREADS = 10          
CRTSH_TIMEOUT = 80           # 80 seconds
ALTERX_LIMIT = 50000         # Max permutation candidates for AlterX

# --- General & Global Rate Limiting ---
DEBUG_MODE = False           # Set to True for verbose terminal output
GLOBAL_RATE_LIMIT = 50       # Global default rate limit (requests/second)


# --- Passive Collection ---
GAU_THREADS = 10              

# --- HTTP Probing (httpx) ---
HTTPX_THREADS = 30            # Reduced for stability and avoiding IP bans
HTTPX_RATE_LIMIT = 50         # Rate limit in requests/second
HTTPX_TIMEOUT = 20            
HTTPX_RETRIES = 3             

# --- Port Scanning (Naabu) ---
NAABU_PORTS = "top-1000"       # Can be "top-100", "top-1000", or "80,443,8080"
NAABU_THREADS = 50           
NAABU_RATE_LIMIT = 1000       

# --- Crawling (Katana / Gospider) ---
KATANA_THREADS = 5           
KATANA_DEPTH = 6              
KATANA_RATE_LIMIT = 30
GOSPIDER_DEPTH = 6           
GOSPIDER_THREADS = 10         
HAKRAWLER_DEPTH = 6
HAKRAWLER_THREADS = 5

# --- JavaScript Analysis ---
JSLUICE_THREADS = 15          
JSLEAK_THREADS = 10
SOURCEMAPPER_ENABLED = True
SUBDOMAINIZER_TIMEOUT = 180
XNLINKFINDER_TIMEOUT = 300   # 5 minutes
XNLINKFINDER_DEPTH = 6        
GETJS_THREADS = 10
SUBJS_THREADS = 10
URLFINDER_THREADS = 10
DEEP_JS_SCAN = True           # Set to True for exhaustive regex scanning

# --- Screenshots ---
GOWITNESS_THREADS = 4         

# --- Vulnerability Scanning (Nuclei) ---
NUCLEI_TIMEOUT = 3500        # 30 minutes for a balanced scan
NUCLEI_CONCURRENCY = 12       # Reduced to prevent system overload
NUCLEI_RATE_LIMIT = 60        
NUCLEI_RETRIES = 10            

# --- Parameter Discovery & API Scanning ---
ARJUN_THREADS = 5            
X8_THREADS = 5               
KITERUNNER_RATE_LIMIT = 50
PARAMSPIDER_TIMEOUT = 300     # 5 minutes (increased for larger domains)
WAYMORE_TIMEOUT = 300

# --- Global Exclusions (Garbage Filtering) ---
# These are strictly ignored across the entire pipeline
EXCLUDED_EXTENSIONS = [
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", # Images
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".flv",           # Media
    ".woff", ".woff2", ".ttf", ".eot", ".otf",                # Fonts
    ".css", ".less", ".scss"                                  # Styles
]

# --- High Value Extensions (Discovery Only) ---

# -------------------------------------------------
# 📊 NOISE PARAMETERS & ENTROPY THRESHOLD
# -------------------------------------------------
# Common query parameters that are typically harmless or used for analytics.
# These are filtered out during parameter discovery to reduce noise.
NOISE_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "ref", "referrer", "sessionid", "sid", "token",
    "auth", "access_token", "_ga", "_gid", "_fbp", "_fbc",
    "_hs", "_hsenc", "_hstc", "_hssc", "_hssrc",
]

# Minimum Shannon entropy for a parameter value to be considered interesting.
# Lower entropy values are likely static or low-entropy placeholders.
ENTROPY_THRESHOLD = 3.5

# We want to FIND these, but NOT necessarily download/analyze them automatically
HIGH_VALUE_EXTENSIONS = [
    ".zip", ".tar", ".gz", ".7z", ".rar", ".iso",             # Archives
    ".sql", ".db", ".sqlite", ".bak", ".old", ".save",        # Database/Backups
    ".env", ".conf", ".config", ".ini", ".json", ".yaml",     # Configs
    ".exe", ".bin", ".dmg", ".apk", ".sh", ".py"              # Binaries/Scripts
]




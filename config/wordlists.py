import os

# =========================================================
# 📝 WORDLIST PATH RESOLUTION WITH SMART FALLBACK
# =========================================================

CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
BUNDLED_DNS = os.path.join(CONFIG_DIR, "wordlists", "subdomains_top5000.txt")

# Standard search paths for DNS wordlists
POSSIBLE_DNS_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/dirbuster/subdomains-top1mil-20000.txt",
    "/usr/share/wordlists/dirb/common.txt",
    BUNDLED_DNS
]

def resolve_dns_wordlist():
    """Finds the best available DNS wordlist on the system, falling back to bundled list."""
    for path in POSSIBLE_DNS_WORDLISTS:
        if path and os.path.exists(path) and os.path.getsize(path) > 0:
            return path
    return BUNDLED_DNS

DNS_WORDLIST = resolve_dns_wordlist()
DNS_WORDLIST_ACTIVE = DNS_WORDLIST

POSSIBLE_DIR_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt"
]

def resolve_dir_wordlist():
    for path in POSSIBLE_DIR_WORDLISTS:
        if os.path.exists(path):
            return path
    return "/usr/share/wordlists/dirb/common.txt"

DIR_WORDLIST = resolve_dir_wordlist()

BUNDLED_API = os.path.join(CONFIG_DIR, "wordlists", "api_routes.txt")
POSSIBLE_API_WORDLISTS = [
    BUNDLED_API,
    "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
]

def resolve_api_wordlist():
    for path in POSSIBLE_API_WORDLISTS:
        if path and os.path.exists(path) and os.path.getsize(path) > 0:
            return path
    return BUNDLED_API

API_WORDLIST = resolve_api_wordlist()

# =========================================================
# 🌐 DNS RESOLVERS RESOLUTION
# =========================================================
BUNDLED_RESOLVERS = os.path.join(CONFIG_DIR, "wordlists", "resolvers.txt")

POSSIBLE_RESOLVERS = [
    "/tmp/resolvers.txt",
    "/usr/share/seclists/Discovery/DNS/resolvers.txt",
    BUNDLED_RESOLVERS
]

def resolve_resolvers():
    """Finds the best available DNS resolvers list, falling back to bundled list."""
    for path in POSSIBLE_RESOLVERS:
        if path and os.path.exists(path) and os.path.getsize(path) > 0:
            return path
    return BUNDLED_RESOLVERS

RESOLVERS_LIST = resolve_resolvers()

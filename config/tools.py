import os
import shutil

# =========================================================
# ⚙️ TOOL PATH CONFIGURATION & DYNAMIC RESOLUTION
# =========================================================

HOME = os.path.expanduser("~")
EXTRA_PATHS = [
    f"{HOME}/go/bin",
    f"{HOME}/.local/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/opt/subscraper",
    "/opt/github-search",
    "/opt/SubDomainizer"
]

# Ensure extra binary directories are prepended to PATH for subprocess calls
current_path = os.environ.get("PATH", "")
path_parts = current_path.split(":")
for ep in reversed(EXTRA_PATHS):
    if os.path.exists(ep) and ep not in path_parts:
        path_parts.insert(0, ep)
os.environ["PATH"] = ":".join(path_parts)


def resolve_tool(name, fallback_paths=None):
    """
    Finds executable by name in PATH or explicit fallback paths.
    Returns the absolute path if found, or the best candidate path.
    """
    if fallback_paths:
        for p in fallback_paths:
            if p.endswith(".py") and os.path.exists(p):
                return p
            elif os.path.exists(p) and os.access(p, os.X_OK):
                return p

    found = shutil.which(name)
    if found:
        return found

    if fallback_paths and len(fallback_paths) > 0:
        return fallback_paths[0]
    return name


def is_tool_available(tool_cmd):
    """Check if tool can be found and executed."""
    if not tool_cmd:
        return False
    if tool_cmd.endswith(".py"):
        return os.path.exists(tool_cmd)
    if os.path.isabs(tool_cmd):
        return os.path.exists(tool_cmd) and os.access(tool_cmd, os.X_OK)
    return shutil.which(tool_cmd) is not None


# --- Subdomain Discovery ---
SUBFINDER = resolve_tool("subfinder", [f"{HOME}/go/bin/subfinder"])
ASSETFINDER = resolve_tool("assetfinder", [f"{HOME}/go/bin/assetfinder", "/usr/bin/assetfinder"])
FINDOMAIN = resolve_tool("findomain", [f"{HOME}/go/bin/findomain", "/usr/bin/findomain"])
CHAOS = resolve_tool("chaos", [f"{HOME}/go/bin/chaos"])
AMASS = resolve_tool("amass", ["/usr/lib/amass/amass", f"{HOME}/go/bin/amass", "/usr/bin/amass"])
SUBSCRAPER = resolve_tool("subscraper.py", ["/opt/subscraper/subscraper.py"])
KNOCKPY = resolve_tool("knockpy", [f"{HOME}/.local/bin/knockpy", "/usr/local/bin/knockpy"])
PUREDNS = resolve_tool("puredns", [f"{HOME}/go/bin/puredns"])
DNSX = resolve_tool("dnsx", [f"{HOME}/go/bin/dnsx"])
SHUFFLEDNS = resolve_tool("shuffledns", [f"{HOME}/go/bin/shuffledns"])
ALTERX = resolve_tool("alterx", [f"{HOME}/go/bin/alterx"])
MASSDNS = resolve_tool("massdns", [f"{HOME}/go/bin/massdns", "/usr/bin/massdns"])

# --- Modern Discovery Additions ---
TLSX = resolve_tool("tlsx", [f"{HOME}/go/bin/tlsx"])
SUBZY = resolve_tool("subzy", [f"{HOME}/go/bin/subzy"])

# --- URL & JS Collection ---
GAU = resolve_tool("gau", [f"{HOME}/go/bin/gau"])
WAYBACKURLS = resolve_tool("waybackurls", [f"{HOME}/go/bin/waybackurls"])
GETJS = resolve_tool("getJS", [f"{HOME}/go/bin/getJS"])
SUBJS = resolve_tool("subjs", [f"{HOME}/go/bin/subjs"])
KATANA = resolve_tool("katana", [f"{HOME}/go/bin/katana"])
GOSPIDER = resolve_tool("gospider", [f"{HOME}/go/bin/gospider"])
HAKRAWLER = resolve_tool("hakrawler", [f"{HOME}/go/bin/hakrawler"])
WAYMORE = resolve_tool("waymore", [f"{HOME}/.local/bin/waymore"])
URLFINDER = resolve_tool("urlfinder", [f"{HOME}/go/bin/urlfinder"])

# --- Analysis & Vulnerability ---
JSLUICE = resolve_tool("jsluice", [f"{HOME}/go/bin/jsluice"])
JSLEAK = resolve_tool("jsleak", [f"{HOME}/go/bin/jsleak"])
SOURCEMAPPER = resolve_tool("sourcemapper", [f"{HOME}/go/bin/sourcemapper"])
SUBDOMAINIZER = resolve_tool("SubDomainizer.py", ["/opt/SubDomainizer/SubDomainizer.py"])
SECRETFINDER = resolve_tool("SecretFinder.py", ["/opt/secretfinder/SecretFinder.py", "/opt/SecretFinder/SecretFinder.py"])
XNLINKFINDER = resolve_tool("xnLinkFinder", [f"{HOME}/.local/bin/xnLinkFinder"])
NUCLEI = resolve_tool("nuclei", [f"{HOME}/go/bin/nuclei", "/usr/bin/nuclei"])
GOWITNESS = resolve_tool("gowitness", [f"{HOME}/go/bin/gowitness"])
NOMORE403 = resolve_tool("nomore403", [f"{HOME}/go/bin/nomore403"])

# --- Parameter & API Discovery ---
PARAMSPIDER = resolve_tool("paramspider", ["/usr/local/bin/paramspider", "/usr/bin/paramspider"])
ARJUN = resolve_tool("arjun", ["/usr/bin/arjun", f"{HOME}/.local/bin/arjun"])
X8 = resolve_tool("x8", ["/usr/bin/x8"])
KR = resolve_tool("kr", [f"{HOME}/go/bin/kr", "/usr/local/bin/kr"])
UNFURL = resolve_tool("unfurl", [f"{HOME}/go/bin/unfurl"])
ANEW = resolve_tool("anew", [f"{HOME}/go/bin/anew"])
QSREPLACE = resolve_tool("qsreplace", [f"{HOME}/go/bin/qsreplace"])

# --- HTTP Probing ---
HTTPX = resolve_tool("httpx", [f"{HOME}/go/bin/httpx", "/usr/bin/httpx"])

# --- Port Scanning ---
NAABU = resolve_tool("naabu", [f"{HOME}/go/bin/naabu", "/usr/bin/naabu"])

# --- WAF Detection ---
WAFW00F = resolve_tool("wafw00f", ["/usr/bin/wafw00f"])

# --- GitHub Recon ---
GITHUB_SUBDOMAINS = resolve_tool("github-subdomains.py", ["/opt/github-search/github-subdomains.py"])
GITHUB_ENDPOINTS = resolve_tool("github-endpoints.py", ["/opt/github-search/github-endpoints.py"])
GITHUB_SECRETS = resolve_tool("github-secrets.py", ["/opt/github-search/github-secrets.py"])

# =========================================================
# 📋 CATEGORIZED TOOL DEFINITIONS
# =========================================================

# Essential Core Tools (At least HTTPX and a subdomain discovery tool must exist)
CORE_TOOLS = {
    "httpx": HTTPX,
    "subfinder": SUBFINDER
}

# Optional Modules (Framework runs without them and warns gracefully)
OPTIONAL_TOOLS = {
    "assetfinder": ASSETFINDER,
    "findomain": FINDOMAIN,
    "chaos": CHAOS,
    "amass": AMASS,
    "subscraper": SUBSCRAPER,
    "knockpy": KNOCKPY,
    "puredns": PUREDNS,
    "massdns": MASSDNS,
    "dnsx": DNSX,
    "shuffledns": SHUFFLEDNS,
    "alterx": ALTERX,
    "tlsx": TLSX,
    "subzy": SUBZY,
    "gau": GAU,
    "waybackurls": WAYBACKURLS,
    "getJS": GETJS,
    "subjs": SUBJS,
    "katana": KATANA,
    "gospider": GOSPIDER,
    "hakrawler": HAKRAWLER,
    "waymore": WAYMORE,
    "urlfinder": URLFINDER,
    "jsluice": JSLUICE,
    "jsleak": JSLEAK,
    "sourcemapper": SOURCEMAPPER,
    "subdomainizer": SUBDOMAINIZER,
    "secretfinder": SECRETFINDER,
    "xnlinkfinder": XNLINKFINDER,
    "nuclei": NUCLEI,
    "gowitness": GOWITNESS,
    "nomore403": NOMORE403,
    "paramspider": PARAMSPIDER,
    "arjun": ARJUN,
    "x8": X8,
    "kr": KR,
    "unfurl": UNFURL,
    "anew": ANEW,
    "qsreplace": QSREPLACE,
    "naabu": NAABU,
    "wafw00f": WAFW00F,
    "github_subdomains": GITHUB_SUBDOMAINS,
    "github_endpoints": GITHUB_ENDPOINTS,
    "github_secrets": GITHUB_SECRETS
}

ALL_TOOLS = {**CORE_TOOLS, **OPTIONAL_TOOLS}
REQUIRED_TOOLS = list(CORE_TOOLS.values())

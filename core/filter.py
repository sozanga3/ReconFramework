import re
from urllib.parse import urlparse, parse_qsl
from core.utils import is_valid_subdomain, reconstruct_url, is_valid_url

BAD_THIRD_PARTY_DOMAINS = [
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "youtube.com",
    "vimeo.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "sentry.io",
    "browser.sentry-cdn.com",
    "cloudflare.com",
    "cloudfront.net",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "trafficmanager.net",
    "github.io",
    "wpengine.com",
    "fastly.net",
    "edgesuite.net",
    "appspot.com",
    "herokuapp.com",
    "pantheonsite.io"
]

def filter_urls(urls, domain):
    clean = []
    for u in urls:
        if not u:
            continue
        # Reconstruct into full URL format
        valid_u = reconstruct_url(u, default_domain=domain)
        if not valid_u or not is_valid_url(valid_u):
            continue
        if not is_valid_subdomain(valid_u, domain):
            continue
        host = _url_host(valid_u)
        if not any(bad in host for bad in BAD_THIRD_PARTY_DOMAINS):
            clean.append(valid_u)
    return list(set(clean))


def _url_host(url):
    """Extract the hostname from a URL or a bare hostname string."""
    if not url:
        return ""
    u = url.strip()
    if "://" in u:
        try:
            host = urlparse(u).netloc or ""
            # Strip credentials if any
            if "@" in host:
                host = host.split("@")[-1]
            # Strip port if present
            return host.split(":")[0].lower()
        except Exception:
            pass
    # Bare hostname / subdomain (no scheme)
    return u.split("/")[0].split(":")[0].split("?")[0].lower()


def filter_urls_multi_domain(urls, domains):
    """Return only URLs whose host belongs to one of the supplied domains
    (exact match or any subdomain level), reconstructed into valid URL format.

    Args:
        urls (list[str]): Raw URL / hostname strings to filter.
        domains (list[str]): Authoritative domains to keep (e.g. ['example.com', 'target.org']).

    Returns:
        list[str]: De-duplicated list of in-scope, well-formed URLs preserving insertion order.
    """
    if not urls:
        return []

    # Normalise domain list once
    norm_domains = [d.strip().lower().lstrip(".") for d in domains if d and d.strip()] if domains else []
    default_target = norm_domains[0] if norm_domains else None

    seen = set()
    result = []
    for u in urls:
        if not u:
            continue
        # Reconstruct any partial URL or relative path into full valid URL
        valid_u = reconstruct_url(u, default_domain=default_target)
        if not valid_u or not is_valid_url(valid_u):
            continue

        host = _url_host(valid_u)
        if not host:
            continue
        if any(bad in host for bad in BAD_THIRD_PARTY_DOMAINS):
            continue
            
        if not norm_domains or any(is_valid_subdomain(host, d) for d in norm_domains):
            if valid_u not in seen:
                seen.add(valid_u)
                result.append(valid_u)
    return result


# =========================================================
# 🚀 SMART URL PATTERN CLUSTERING (ANTI-WAF & DEDUP)
# =========================================================
NUM_PATTERN = re.compile(r"^\d+$")
UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{16,64}$")


def normalize_path_pattern(path):
    """
    Normalizes variable path segments (numbers, UUIDs, hex hashes)
    into tokens ({num}, {uuid}, {hash}) to allow structural clustering.
    Preserves file extensions like .json, .php, .html, etc.
    """
    if not path:
        return "/"
    segments = path.split("/")
    norm = []
    for seg in segments:
        if not seg:
            norm.append("")
            continue
        if "." in seg:
            name, ext = seg.rsplit(".", 1)
            if NUM_PATTERN.match(name):
                name = "{num}"
            elif UUID_PATTERN.match(name):
                name = "{uuid}"
            elif HASH_PATTERN.match(name):
                name = "{hash}"
            norm.append(f"{name}.{ext}")
        else:
            if NUM_PATTERN.match(seg):
                norm.append("{num}")
            elif UUID_PATTERN.match(seg):
                norm.append("{uuid}")
            elif HASH_PATTERN.match(seg):
                norm.append("{hash}")
            else:
                norm.append(seg)
    return "/".join(norm)


def collapse_url_patterns(urls, max_per_pattern=3):
    """
    Collapses repetitive URLs that share the same structural pattern
    (scheme + host + normalized path + query parameter keys) down to
    a maximum number of representative samples (default: 3).

    Greatly accelerates downstream active fuzzing and parameter discovery
    while eliminating WAF IP ban triggers caused by crawler pagination loops.
    """
    if not urls:
        return []

    pattern_counts = {}
    collapsed = []
    seen = set()

    for u in urls:
        if not u or u in seen:
            continue
        seen.add(u)
        try:
            parsed = urlparse(u)
            netloc = parsed.netloc.lower()
            norm_path = normalize_path_pattern(parsed.path)
            param_keys = tuple(sorted(set(k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True))))

            pattern_key = (netloc, norm_path, param_keys)
            count = pattern_counts.get(pattern_key, 0)
            if count < max_per_pattern:
                collapsed.append(u)
                pattern_counts[pattern_key] = count + 1
        except Exception:
            collapsed.append(u)

    return collapsed
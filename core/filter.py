from core.utils import is_valid_subdomain
from urllib.parse import urlparse

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
    "cloudfront.net"
]

def filter_urls(urls, domain):
    clean = []
    for u in urls:
        if is_valid_subdomain(u, domain) and not any(bad in u for bad in BAD_THIRD_PARTY_DOMAINS):
            clean.append(u)
    return list(set(clean))


def _url_host(url):
    """Extract the hostname from a URL or a bare hostname string."""
    if not url:
        return ""
    u = url.strip()
    if "://" in u:
        try:
            host = urlparse(u).netloc or ""
            # Strip port if present
            return host.split(":")[0].lower()
        except Exception:
            pass
    # Bare hostname / subdomain (no scheme)
    return u.split("/")[0].split(":")[0].split("?")[0].lower()


def filter_urls_multi_domain(urls, domains):
    """Return only URLs whose host belongs to one of the supplied domains
    (exact match or any subdomain level).

    Args:
        urls (list[str]): Raw URL / hostname strings to filter.
        domains (list[str]): Authoritative domains to keep (e.g. ['example.com', 'target.org']).

    Returns:
        list[str]: De-duplicated list of in-scope URLs preserving insertion order.
    """
    if not domains:
        return list(urls)

    # Normalise domain list once
    norm_domains = [d.strip().lower().lstrip(".") for d in domains if d and d.strip()]
    if not norm_domains:
        return list(urls)

    seen = set()
    result = []
    for u in urls:
        if not u:
            continue
        host = _url_host(u)
        if not host:
            # Relative paths (/api/...) are always kept
            if u.startswith("/"):
                if u not in seen:
                    seen.add(u)
                    result.append(u)
            continue
        if any(is_valid_subdomain(host, d) for d in norm_domains):
            if u not in seen:
                seen.add(u)
                result.append(u)
    return result
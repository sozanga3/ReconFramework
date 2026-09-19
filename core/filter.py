from core.utils import is_valid_subdomain

BAD_THIRD_PARTY_DOMAINS = [
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "youtube.com",
    "vimeo.com",
    "facebook.com",
    "twitter.com"
]

def filter_urls(urls, domain):
    clean = []
    for u in urls:
        if is_valid_subdomain(u, domain) and not any(bad in u for bad in BAD_THIRD_PARTY_DOMAINS):
            clean.append(u)
    return list(set(clean))
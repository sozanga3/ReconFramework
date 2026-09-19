import re
from urllib.parse import urlparse
from config.settings import HIGH_VALUE_EXTENSIONS

# =========================================================
# 🎯 HIGH VALUE KEYWORDS (EXTENDED)
# =========================================================
from config.keywords import KEYWORDS


# =========================================================
# ⚙️ TECHNOLOGY RISK SCORE
# =========================================================
def tech_score(tech_list):
    score = 0

    if not tech_list:
        return 0

    for tech in tech_list:
        t = tech.lower()

        # outdated PHP
        if "php:5" in t or "php:7.0" in t or "php:7.1" in t:
            score += 3

        # ASP.NET / IIS
        if "asp.net" in t:
            score += 1
        if "iis" in t:
            score += 1

        # Apache old
        if "apache" in t and "2.2" in t:
            score += 2

        # CMS
        if "wordpress" in t:
            score += 2
        if "drupal" in t or "joomla" in t:
            score += 2

        # JS libs
        if "jquery:1" in t:
            score += 2

    return score


# =========================================================
# 🌐 BASE HTTP SCORE
# =========================================================
def base_score(status_code, content_length):
    score = 0

    if status_code == 200:
        score += 3
    elif status_code in [301, 302]:
        score += 1
    elif status_code == 403:
        score += 3  # VERY IMPORTANT (bypass target)
    elif status_code >= 500:
        score -= 2

    # content size
    if content_length > 20000:
        score += 2
    elif content_length > 5000:
        score += 1
    elif content_length == 0:
        score -= 1

    return score


# =========================================================
# 🔑 KEYWORD SCORE
# =========================================================
def keyword_score(value):
    score = 0

    value = value.lower()

    for keyword in KEYWORDS:
        if keyword in value:
            score += 3   # increased weight

    return score


# =========================================================
# 🔗 ENDPOINT SCORE
# =========================================================
def endpoint_score(url):
    score = 0

    depth = url.count("/")
    if depth > 5:
        score += 2

    if "?" in url:
        score += 2

    if "=" in url:
        score += 1

    return score


# =========================================================
# 📦 PARAM SCORE
# =========================================================
def param_score(params):
    score = 0

    if not params:
        return 0

    score += len(params) * 3

    for p in params:
        score += keyword_score(p)

    return score


# =========================================================
# 📄 CONTENT SCORE (TITLE)
# =========================================================
def content_score(title):
    score = 0

    if not title:
        return 0

    title = title.lower()

    if "login" in title:
        score += 4
    if "admin" in title:
        score += 4
    if "dashboard" in title:
        score += 3

    return score


# =========================================================
# ⚠️ PENALTY SCORE
# =========================================================
def penalty_score(url):
    score = 0

    # Penalize specific external domains
    bad_domains = [
        "fonts.googleapis.com",
        "youtube.com",
        "vimeo.com",
        "facebook.com",
        "twitter.com"
    ]

    for domain in bad_domains:
        if domain in url:
            score += 5
            
    # Penalize static file extensions (matches at end of string or before query params)
    static_exts = r"\.(css|png|jpg|jpeg|svg|gif|ico|woff|woff2|ttf|eot)(\?.*)?$"
    if re.search(static_exts, url, re.IGNORECASE):
        score += 5
        
    # Penalize CDN subdomains, but NOT the letters "cdn" inside a path
    if "://cdn." in url or ".cdn." in url:
        score += 5

    return score


# =========================================================
# 📄 EXTENSION SCORE
# =========================================================
def extension_score(url):
    score = 0
    url_lower = url.lower()

    for ext in HIGH_VALUE_EXTENSIONS:
        if url_lower.endswith(ext) or f"{ext}?" in url_lower:
            score += 10  # Massive bonus for discovery
            break

    return score


# =========================================================
# 🚀 FINAL TARGET SCORING (MAIN ENGINE)
# =========================================================
def score_target(target):
    score = 0

    url = target.get("url", "")
    
    try:
        parsed = urlparse(url)
        path_to_score = parsed.path
        if parsed.query:
            path_to_score += "?" + parsed.query
    except:
        path_to_score = url

    score += base_score(
        target.get("status_code", 0),
        target.get("length", 0)
    )

    score += tech_score(target.get("tech", []))

    score += content_score(target.get("title", ""))

    # Score only the path/query to avoid domain name false positives (e.g. test.com)
    score += keyword_score(path_to_score)

    score += endpoint_score(url)

    score += param_score(target.get("params", []))

    # 🔥 API bonus (important)
    if "/api" in url:
        score += 4

    # 💎 High Value Extension bonus
    score += extension_score(url)

    # ❌ penalties
    score -= penalty_score(url)

    return score


# =========================================================
# 🧠 SORT + RANK TARGETS
# =========================================================
def rank_targets(targets):
    for t in targets:
        t["score"] = score_target(t)

    return sorted(targets, key=lambda x: x["score"], reverse=True)


# =========================================================
# 🌐 HTTPX COMPATIBILITY LAYER
# =========================================================
def score_http_target(record):
    """
    Adapter for httpx → converts to scoring format
    """

    target = {
        "url": record.get("url", ""),
        "status_code": record.get("status_code", 0),
        "title": record.get("title", ""),
        "tech": record.get("tech", []),
        "length": record.get("length", 0),
        "params": []
    }

    return score_target(target)


# =========================================================
# 🎯 JS SCORING
# =========================================================
def score_js(js_url, endpoints_count=0, secrets=0):
    score = 0

    score += keyword_score(js_url)

    score += endpoints_count * 2

    score += secrets * 5

    return score


# =========================================================
# 🔍 PARAM DISCOVERY SCORE
# =========================================================
def score_params(url, params):
    score = 0

    score += len(params) * 3

    for p in params:
        score += keyword_score(p)

    return score

def entropy_score(value: str) -> float:
    """Calculate Shannon entropy of a string.
    Returns a float representing the entropy; higher means more randomness.
    """
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    import math
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
# url_features.py
# Basic URL feature extraction for phishing detection

import re
import math
from urllib.parse import urlparse, parse_qs

SUSPECT_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "payment", "billing", "card", "verify-account"
]

def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for v in freq.values():
        p = v / n
        ent -= p * math.log2(p)
    return ent

def _contains_ipv4(host: str) -> bool:
    """Return True if host looks like an IPv4 address."""
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))

def parse_url(url: str) -> dict:
    """Normalize and parse a URL, ensure scheme exists for parsing."""
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urlparse(url)
    return {
        "normalized": url,
        "parsed": parsed,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "host": parsed.hostname or "",
        "scheme": parsed.scheme or ""
    }

def extract_features(url: str) -> dict:
    """Return a dictionary of basic URL features used for detection."""
    p = parse_url(url)
    host = p["host"]
    path = p["path"]
    query = p["query"]

    # basic metrics
    url_length = len(p["normalized"])
    path_length = len(path)
    param_count = len(parse_qs(query))
    tld = ""
    suspicious_tld = False
    if host and "." in host:
        tld = host.split(".")[-1].lower()
        if tld in ("zip", "xyz", "top", "gq", "tk", "ml"):
            suspicious_tld = True

    # suspicious elements
    has_at = "@" in p["normalized"]
    has_double_slash = "//" in p["normalized"].split("://")[-1]
    has_ip = _contains_ipv4(host)

    # keywords
    url_lower = p["normalized"].lower()
    keywords_found = [kw for kw in SUSPECT_KEYWORDS if kw in url_lower]
    suspect_keyword_count = len(keywords_found)

    # entropy
    host_entropy = _entropy(host)
    path_entropy = _entropy(path)

    dot_count_in_host = host.count(".")
    special_char_count = sum(1 for ch in p["normalized"] if not ch.isalnum() and ch not in (":", "/", ".", "?", "&", "=", "-", "_"))

    features = {
        "url": p["normalized"],
        "scheme": p["scheme"],
        "host": host,
        "tld": tld,
        "suspicious_tld": suspicious_tld,
        "has_ip": has_ip,
        "url_length": url_length,
        "path_length": path_length,
        "param_count": param_count,
        "has_at": has_at,
        "has_double_slash": has_double_slash,
        "suspect_keyword_count": suspect_keyword_count,
        "keywords_found": keywords_found,
        "host_entropy": round(host_entropy, 4),
        "path_entropy": round(path_entropy, 4),
        "dot_count_in_host": dot_count_in_host,
        "special_char_count": special_char_count
    }

    return features

"""Domain analysis helpers for phishing detection."""

from __future__ import annotations

from typing import Dict, List
import socket
from urllib.parse import urlparse

from config import get_settings


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def _split_labels(host: str) -> List[str]:
    return [label for label in host.split(".") if label]


def analyze_domain(url: str) -> Dict:
    """Return domain-related signals and DNS resolution details."""
    settings = get_settings()
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    labels = _split_labels(host)

    registrable_guess = ""
    if len(labels) >= 2:
        registrable_guess = ".".join(labels[-2:])

    digit_count = sum(ch.isdigit() for ch in host)
    alpha_count = sum(ch.isalpha() for ch in host)
    digit_ratio = round(digit_count / max(len(host), 1), 3)

    resolved_ips: List[str] = []
    dns_resolves = False
    if host:
        try:
            socket.setdefaulttimeout(settings.dns_timeout)
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = info[4][0]
                if ip not in resolved_ips:
                    resolved_ips.append(ip)
            dns_resolves = bool(resolved_ips)
        except OSError:
            dns_resolves = False

    return {
        "host": host,
        "registrable_domain_guess": registrable_guess,
        "subdomain_count": max(len(labels) - 2, 0),
        "domain_length": len(host),
        "has_hyphen": "-" in host,
        "is_punycode": "xn--" in host,
        "digit_ratio": digit_ratio,
        "digit_count": digit_count,
        "alpha_count": alpha_count,
        "dns_resolves": dns_resolves,
        "resolved_ips": resolved_ips,
        "resolved_ip_count": len(resolved_ips),
    }

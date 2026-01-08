"""TLS certificate checks for HTTPS hosts."""

from __future__ import annotations

from typing import Dict
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime, timezone

from config import get_settings


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        timestamp = ssl.cert_time_to_seconds(value)
    except ValueError:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def check_tls(url: str) -> Dict:
    """Attempt a TLS handshake and extract basic certificate signals."""
    settings = get_settings()
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""

    result = {
        "tls_supported": False,
        "tls_version": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_days_remaining": None,
        "cert_is_self_signed": None,
    }

    if not host:
        return result

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=settings.tls_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                result["tls_supported"] = True
                result["tls_version"] = tls_sock.version()
                cert = tls_sock.getpeercert()
    except (OSError, ssl.SSLError):
        return result

    subject = dict(item[0] for item in cert.get("subject", [])) if cert else {}
    issuer = dict(item[0] for item in cert.get("issuer", [])) if cert else {}

    not_after = _parse_cert_time(cert.get("notAfter") if cert else None)
    days_remaining = None
    if not_after:
        now = datetime.now(timezone.utc)
        delta = not_after - now
        days_remaining = max(delta.days, 0)

    result.update(
        {
            "cert_subject": subject or None,
            "cert_issuer": issuer or None,
            "cert_days_remaining": days_remaining,
            "cert_is_self_signed": bool(subject) and subject == issuer,
        }
    )
    return result

"""Configuration for the phishing detection tool."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    request_timeout: float = 6.0
    tls_timeout: float = 5.0
    dns_timeout: float = 4.0
    user_agent: str = "PhishDetector/1.0 (+https://example.com)"


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def get_settings() -> Settings:
    """Load settings from environment variables with safe defaults."""
    return Settings(
        request_timeout=_env_float("PHISH_REQUEST_TIMEOUT", Settings.request_timeout),
        tls_timeout=_env_float("PHISH_TLS_TIMEOUT", Settings.tls_timeout),
        dns_timeout=_env_float("PHISH_DNS_TIMEOUT", Settings.dns_timeout),
        user_agent=os.getenv("PHISH_USER_AGENT", Settings.user_agent),
    )

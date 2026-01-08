"""Programmatic API entrypoint for the phishing detection tool."""

from __future__ import annotations

from typing import Dict

from url_features import extract_features
from html_parser import analyze_html_for_forms
from heuristic_scorer import score_features
from domain_info import analyze_domain
from tls_check import check_tls
from ml_scorer import score_with_model


def analyze_url(url: str) -> Dict:
    """Run the full analysis pipeline and return a structured response."""
    features = extract_features(url)
    features.update(analyze_domain(features["url"]))
    features.update(check_tls(features["url"]))
    features.update(analyze_html_for_forms(features["url"]))

    heuristic = score_features(features)
    ml = score_with_model(features)

    return {
        "url": features.get("url"),
        "features": features,
        "heuristic": heuristic,
        "ml": ml,
    }

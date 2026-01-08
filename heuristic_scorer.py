# heuristic_scorer.py
# Rule-based scorer converting URL features (+HTML signals) into a risk verdict

from typing import Dict, List

CATEGORIES = ["credential_theft", "card_theft", "info_gathering", "malware"]
BRAND_KEYWORDS = {"paypal", "google", "microsoft", "bank", "visa", "mastercard", "apple", "facebook", "instagram"}

def _add_reason(reasons: List[str], reason: str):
    if reason not in reasons:
        reasons.append(reason)

def score_features(features: Dict) -> Dict:
    """Improved scorer with brand-impersonation and HTML-form signals."""
    score = 0.0
    reasons: List[str] = []
    cat_scores = {c: 0.0 for c in CATEGORIES}

    # locals
    url = features.get("url", "").lower()
    host = features.get("host", "").lower()
    tld = features.get("tld", "")
    url_length = features.get("url_length", 0)
    param_count = features.get("param_count", 0)
    special_char_count = features.get("special_char_count", 0)
    suspicious_tld = features.get("suspicious_tld", False)
    has_ip = features.get("has_ip", False)
    keywords = features.get("keywords_found", [])
    host_entropy = features.get("host_entropy", 0.0)
    path_entropy = features.get("path_entropy", 0.0)
    has_double_slash = features.get("has_double_slash", False)
    redirect_count = features.get("redirect_count", 0)
    external_form_action = features.get("external_form_action", False)
    external_domain_count = features.get("external_domain_count", 0)
    external_script_count = features.get("external_script_count", 0)
    iframe_count = features.get("iframe_count", 0)
    meta_refresh = features.get("meta_refresh", False)
    suspicious_js = features.get("suspicious_js_keywords", [])
    word_count = features.get("word_count", 0)

    # base signals
    if suspicious_tld:
        score += 0.22
        _add_reason(reasons, "Suspicious top-level domain")
    if has_ip:
        score += 0.30
        _add_reason(reasons, "URL uses an IP address instead of domain")
    if url_length > 80:
        score += 0.12
        _add_reason(reasons, "Unusually long URL")
    if special_char_count > 5:
        score += 0.10
        _add_reason(reasons, "Many special characters in URL")
    if host_entropy and host_entropy > 3.2:
        score += 0.09
        _add_reason(reasons, "High entropy in host (looks random/auto-generated)")
    if path_entropy and path_entropy > 4.0:
        score += 0.06
        _add_reason(reasons, "High entropy in path (suspicious)")

    # HTML form signals (if provided)
    if features.get("has_password_input"):
        score += 0.35
        cat_scores["credential_theft"] += 1.2
        _add_reason(reasons, "Page contains password input (login form detected)")
    if features.get("has_card_inputs"):
        score += 0.45
        cat_scores["card_theft"] += 1.4
        _add_reason(reasons, "Page contains card-related input fields")
    if external_form_action:
        score += 0.25
        _add_reason(reasons, "Form submits to a different domain")
        cat_scores["credential_theft"] += 0.8

    # keyword signals
    kw = set(k.lower() for k in keywords)
    if kw & {"login", "secure", "verify", "account"}:
        score += 0.30
        _add_reason(reasons, f"Suspicious keywords in URL: {', '.join(sorted(kw & {'login','secure','verify','account'}))}")
        cat_scores["credential_theft"] += 1.0
    if kw & {"card", "billing", "payment"}:
        score += 0.30
        _add_reason(reasons, f"Payment/card-related keywords: {', '.join(sorted(kw & {'card','billing','payment'}))}")
        cat_scores["card_theft"] += 1.0
    if kw & {"survey", "free", "claim"}:
        score += 0.08
        _add_reason(reasons, "Promotional/offer keywords (possible info harvesting)")
        cat_scores["info_gathering"] += 0.6
    if kw & {"download", "setup"} or url.endswith((".exe", ".zip", ".scr", ".msi")):
        score += 0.45
        _add_reason(reasons, "URL links to downloadable executable or archive")
        cat_scores["malware"] += 1.2

    # brand impersonation
    for brand in BRAND_KEYWORDS:
        if brand in host:
            # naive impersonation check: brand in host but not exact brand.tld
            if not host.startswith(brand + "."):
                score += 0.40
                _add_reason(reasons, f"Host contains brand name '{brand}' (possible impersonation)")
                cat_scores["credential_theft"] += 1.0
                break

    # structure signals
    if param_count >= 5:
        score += 0.06
        _add_reason(reasons, "Many query parameters in URL")
    if has_double_slash:
        score += 0.05
        _add_reason(reasons, "Unusual double-slash in path")
    if redirect_count >= 3:
        score += 0.10
        _add_reason(reasons, "Multiple redirects before reaching content")
    if meta_refresh:
        score += 0.12
        _add_reason(reasons, "Meta refresh redirect detected")
    if iframe_count >= 2:
        score += 0.10
        _add_reason(reasons, "Page contains multiple iframes")
    if external_domain_count >= 5:
        score += 0.08
        _add_reason(reasons, "Page loads content from many external domains")
    if external_script_count >= 3:
        score += 0.08
        _add_reason(reasons, "Page loads several external scripts")
    if suspicious_js:
        score += 0.18
        _add_reason(reasons, "Suspicious JavaScript patterns detected")
        cat_scores["malware"] += 0.6
    if word_count and word_count < 80 and features.get("has_login_form"):
        score += 0.06
        _add_reason(reasons, "Sparse page text with login form")

    # suspicious TLD boosts
    if tld in ("zip", "xyz", "top", "gq", "tk", "ml"):
        cat_scores["credential_theft"] += 0.20
        cat_scores["malware"] += 0.12

    # joint indicators
    if cat_scores["credential_theft"] > 0 and cat_scores["card_theft"] > 0:
        _add_reason(reasons, "Indicators for both credential and card theft")
        score += 0.10

    # clamp base score
    score = max(0.0, min(score, 1.0))

    # normalize categories
    max_possible = 2.0
    scaled = {c: round(max(0.0, min(v / max_possible, 1.0)), 3) for c, v in cat_scores.items()}
    predicted = [c for c, v in scaled.items() if v >= 0.5]

    if not predicted and score >= 0.65:
        predicted = ["credential_theft"]
        _add_reason(reasons, "High overall risk without clear category: fallback to credential_theft")

    final_score = score * 0.65 + (max(scaled.values()) if scaled else 0.0) * 0.35
    final_score = round(max(0.0, min(final_score, 1.0)), 3)

    if final_score >= 0.7:
        risk = "high"
    elif final_score >= 0.4:
        risk = "medium"
    else:
        risk = "low"

    return {
        "risk": risk,
        "score": final_score,
        "predicted_categories": predicted,
        "reasons": reasons
    }

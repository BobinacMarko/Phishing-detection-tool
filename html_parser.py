from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from config import get_settings


SUSPICIOUS_JS_KEYWORDS = (
    "eval(",
    "atob(",
    "document.write(",
    "unescape(",
    "fromCharCode",
)


def _host(url: str) -> str:
    return urlparse(url).hostname or ""


def _is_external(base_host: str, url: str) -> bool:
    target_host = _host(url)
    return bool(target_host) and target_host.lower() != base_host.lower()


def _count_external_domains(base_host: str, urls: List[str]) -> int:
    domains = {_host(u).lower() for u in urls if _host(u)}
    return len({d for d in domains if d != base_host.lower()})


def analyze_html_for_forms(url: str) -> Dict:
    """
    Returns a dict with keys:
      - has_login_form (bool)
      - has_password_input (bool)
      - has_card_inputs (bool)
      - detected_fields (list)
    """
    settings = get_settings()
    result = {
        "has_login_form": False,
        "has_password_input": False,
        "has_card_inputs": False,
        "detected_fields": [],
        "form_count": 0,
        "password_input_count": 0,
        "hidden_input_count": 0,
        "external_form_action": False,
        "page_title": None,
        "word_count": 0,
        "iframe_count": 0,
        "script_tag_count": 0,
        "external_script_count": 0,
        "external_link_count": 0,
        "external_domain_count": 0,
        "meta_refresh": False,
        "redirect_count": 0,
        "final_url": None,
        "status_code": None,
        "suspicious_js_keywords": [],
        "html_fetch_error": None,
    }

    try:
        headers = {"User-Agent": settings.user_agent}
        r = requests.get(
            url,
            timeout=settings.request_timeout,
            headers=headers,
            allow_redirects=True,
        )

        result["status_code"] = r.status_code
        result["final_url"] = r.url
        result["redirect_count"] = len(r.history)

        if r.status_code >= 400:
            return result

        soup = BeautifulSoup(r.text, "html.parser")
        base_host = _host(r.url)

        forms = soup.find_all("form")
        result["form_count"] = len(forms)

        result["iframe_count"] = len(soup.find_all("iframe"))

        scripts = soup.find_all("script")
        result["script_tag_count"] = len(scripts)

        title = soup.find("title")
        if title and title.text:
            result["page_title"] = title.text.strip()

        anchor_tags = soup.find_all("a", href=True)
        external_links: List[str] = []
        for a in anchor_tags:
            href = urljoin(r.url, a.get("href", ""))
            if href and _is_external(base_host, href):
                external_links.append(href)

        result["external_link_count"] = len(external_links)
        result["external_domain_count"] = _count_external_domains(base_host, external_links)

        for script in scripts:
            src = script.get("src")
            if src:
                full_src = urljoin(r.url, src)
                if _is_external(base_host, full_src):
                    result["external_script_count"] += 1
            else:
                content = script.text or ""
                for keyword in SUSPICIOUS_JS_KEYWORDS:
                    if keyword in content and keyword not in result["suspicious_js_keywords"]:
                        result["suspicious_js_keywords"].append(keyword)

        meta_refresh = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
        result["meta_refresh"] = meta_refresh is not None

        text = soup.get_text(separator=" ", strip=True)
        if text:
            result["word_count"] = len(text.split())

        for form in forms:
            action = form.get("action") or ""
            if action:
                action_url = urljoin(r.url, action)
                if _is_external(base_host, action_url):
                    result["external_form_action"] = True

            inputs = form.find_all("input")
            names = [inp.get("name", "").lower() for inp in inputs if inp.get("name")]
            types = [inp.get("type", "").lower() for inp in inputs if inp.get("type")]

            # password
            if "password" in types or any("password" in n for n in names):
                result["has_password_input"] = True
                result["has_login_form"] = True
                result["password_input_count"] += sum(1 for t in types if t == "password")

            result["hidden_input_count"] += sum(1 for t in types if t == "hidden")

            # card fields heuristics
            card_like = {
                "card", "cardnumber", "card_number", "cc-number", "cc_number",
                "ccnumber", "cvv", "cvc", "expiry", "exp",
            }
            if (
                any(any(cl in n for cl in card_like) for n in names)
                or (any(t in ("tel", "number") for t in types) and any("card" in n for n in names))
            ):
                result["has_card_inputs"] = True

            result["detected_fields"].extend(names)

        # deduplicate
        result["detected_fields"] = list(dict.fromkeys(result["detected_fields"]))

    except Exception:
        result["html_fetch_error"] = "request_failed"

    return result

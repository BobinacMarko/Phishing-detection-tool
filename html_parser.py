# html_parser.py
import requests
from bs4 import BeautifulSoup
from typing import Dict

REQUEST_TIMEOUT = 6  # seconds

def analyze_html_for_forms(url: str) -> Dict:
    """
    Returns a dict with keys:
      - has_login_form (bool)
      - has_password_input (bool)
      - has_card_inputs (bool)
      - detected_fields (list)
    """
    result = {
        "has_login_form": False,
        "has_password_input": False,
        "has_card_inputs": False,
        "detected_fields": []
    }
    try:
        headers = {"User-Agent": "PhishDetector/1.0 (+https://example.com)"}
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True)
        if r.status_code >= 400:
            return result
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            names = [inp.get("name","").lower() for inp in inputs if inp.get("name")]
            types = [inp.get("type","").lower() for inp in inputs if inp.get("type")]
            # password
            if "password" in types or any("password" in n for n in names):
                result["has_password_input"] = True
                result["has_login_form"] = True
            # card fields heuristics
            card_like = {"card", "cardnumber", "card_number", "cc-number", "cc_number", "ccnumber", "cvv", "cvc", "expiry", "exp"}
            if any(any(cl in n for cl in card_like) for n in names) or any(t in ("tel","number") for t in types) and any("card" in n for n in names):
                result["has_card_inputs"] = True
            result["detected_fields"].extend(names)
        # deduplicate
        result["detected_fields"] = list(dict.fromkeys(result["detected_fields"]))
    except Exception:
        # network errors, timeouts, parsing errors ignored: return conservative empty result
        pass
    return result

# main.py
import json
from url_features import extract_features
from html_parser import analyze_html_for_forms
from heuristic_scorer import score_features

def print_json(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))

def main_loop():
    print("Phishing Detection Tool - heuristic demo\n")
    while True:
        try:
            url = input("Enter URL to analyze (press Enter to exit): ").strip()
            if url == "":
                break
            features = extract_features(url)
            # safely analyze HTML (may be slow, but ok for demo)
            form_info = analyze_html_for_forms(features["url"])
            features.update(form_info)

            verdict = score_features(features)
            output = {
                "request_id": None,
                "url": features.get("url"),
                "features": features,
                "result": verdict
            }
            print_json(output)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main_loop()

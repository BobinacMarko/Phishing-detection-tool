"""Quick manual runner for the phishing detector pipeline."""

from api.api import analyze_url


if __name__ == "__main__":
    sample_urls = [
        "https://example.com/login",
        "http://paypal.com.secure-account-update.xyz/login",
    ]

    for url in sample_urls:
        result = analyze_url(url)
        print("=" * 80)
        print(result["url"])
        print(result["heuristic"])

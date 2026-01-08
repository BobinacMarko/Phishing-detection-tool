"""Optional ML scoring for phishing detection."""

from __future__ import annotations

from typing import Dict
from pathlib import Path


def score_with_model(features: Dict, model_path: str = "models/model.joblib", vectorizer_path: str = "models/vectorizer.pkl") -> Dict:
    """Attempt to score with a serialized model if available."""
    model_file = Path(model_path)
    vectorizer_file = Path(vectorizer_path)

    if not model_file.exists() or not vectorizer_file.exists():
        return {
            "available": False,
            "reason": "Model artifacts not found",
        }

    if model_file.stat().st_size == 0 or vectorizer_file.stat().st_size == 0:
        return {
            "available": False,
            "reason": "Model artifacts are empty",
        }

    try:
        import joblib
    except ImportError:
        return {
            "available": False,
            "reason": "joblib is not installed",
        }

    model = joblib.load(model_file)
    vectorizer = joblib.load(vectorizer_file)

    text = features.get("url", "")
    vector = vectorizer.transform([text])
    score = float(model.predict_proba(vector)[0][1])

    return {
        "available": True,
        "score": round(score, 4),
        "label": "phishing" if score >= 0.5 else "legitimate",
    }

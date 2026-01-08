"""Batch collection utility for the phishing detection pipeline."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional

from api.api import analyze_url


def _normalize_input_format(path: Path, explicit: Optional[str]) -> str:
    if explicit:
        return explicit.lower()
    suffix = path.suffix.lower()
    if suffix in {".txt", ".list"}:
        return "txt"
    if suffix == ".jsonl":
        return "jsonl"
    return "csv"


def _normalize_output_format(path: Path, explicit: Optional[str]) -> str:
    if explicit:
        return explicit.lower()
    if path.suffix.lower() == ".csv":
        return "csv"
    return "jsonl"


def _read_txt(path: Path) -> Iterator[Dict]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            yield {"url": url}


def _read_csv(path: Path) -> Iterator[Dict]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if not row:
                continue
            url = (row.get("url") or row.get("URL") or "").strip()
            if not url:
                continue
            entry = {"url": url}
            label = row.get("label")
            if label is not None and str(label).strip() != "":
                entry["label"] = label
            yield entry


def _read_jsonl(path: Path) -> Iterator[Dict]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            if raw.startswith("#"):
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(data, str):
                data = {"url": data}
            if not isinstance(data, dict):
                continue
            url = str(data.get("url", "")).strip()
            if not url:
                continue
            entry = {"url": url}
            if "label" in data:
                entry["label"] = data["label"]
            yield entry


def _iter_inputs(path: Path, input_format: str) -> Iterator[Dict]:
    if input_format == "txt":
        return _read_txt(path)
    if input_format == "jsonl":
        return _read_jsonl(path)
    return _read_csv(path)


def _summarize_result(result: Dict, label: Optional[str]) -> Dict:
    heuristic = result.get("heuristic", {}) or {}
    ml = result.get("ml", {}) or {}
    summary = {
        "url": result.get("url"),
        "label": label,
        "heuristic_risk": heuristic.get("risk"),
        "heuristic_score": heuristic.get("score"),
        "heuristic_predicted_categories": heuristic.get("predicted_categories"),
        "heuristic_reasons": heuristic.get("reasons"),
        "ml_available": ml.get("available"),
        "ml_score": ml.get("score"),
        "ml_label": ml.get("label"),
        "features": result.get("features", {}),
    }
    return summary


def _write_jsonl(rows: Iterable[Dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False))
            handle.write("\n")


def _write_csv(rows: Iterable[Dict], path: Path) -> None:
    rows = list(rows)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            row = dict(row)
            if "features" in row:
                row["features"] = json.dumps(row["features"], ensure_ascii=False)
            if "heuristic_predicted_categories" in row:
                row["heuristic_predicted_categories"] = json.dumps(
                    row["heuristic_predicted_categories"], ensure_ascii=False
                )
            if "heuristic_reasons" in row:
                row["heuristic_reasons"] = json.dumps(row["heuristic_reasons"], ensure_ascii=False)
            writer.writerow(row)


def run_collect(input_path: Path, output_path: Path, input_format: str, output_format: str) -> None:
    outputs = []
    for entry in _iter_inputs(input_path, input_format):
        url = entry.get("url")
        label = entry.get("label")
        if not url:
            continue
        result = analyze_url(url)
        outputs.append(_summarize_result(result, label))

    if output_format == "csv":
        _write_csv(outputs, output_path)
    else:
        _write_jsonl(outputs, output_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect phishing analysis results for a list of URLs.")
    parser.add_argument("input", help="Path to input list (.txt, .csv, .jsonl)")
    parser.add_argument("output", help="Path to output file (.jsonl or .csv)")
    parser.add_argument(
        "--input-format",
        choices=["txt", "csv", "jsonl"],
        help="Override input format detection",
    )
    parser.add_argument(
        "--output-format",
        choices=["jsonl", "csv"],
        help="Override output format detection",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    input_format = _normalize_input_format(input_path, args.input_format)
    output_format = _normalize_output_format(output_path, args.output_format)

    run_collect(input_path, output_path, input_format, output_format)


if __name__ == "__main__":
    main()

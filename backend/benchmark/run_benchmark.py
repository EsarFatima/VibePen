"""VibePen benchmark: scan known vulnerable apps and compare with a list of real flaws.

Run from the backend folder:
    python benchmark/run_benchmark.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # so we can import detector.*

from detector.static_analyzer import analyze_directory  # noqa: E402


def finding_key(finding):
    """Turn a finding into (file path, rule name)."""
    path = finding["location"].split(" (Line")[0].replace("\\", "/")
    return path, finding["type"]


def compare(findings, real_flaws):
    """Compare scanner findings with the list of real flaws (matched by file + rule)."""
    found = {finding_key(f) for f in findings if "error" not in f}
    real = {(item["file"], item["rule"]) for item in real_flaws}

    true_pos = found & real          # reported and really a flaw
    false_pos = found - real         # reported but not in our real list
    missed = real - found            # real flaw the scanner did not report

    precision = len(true_pos) / len(found) if found else 0.0
    recall = len(true_pos) / len(real) if real else 0.0
    return {
        "reported": len(found),
        "real_flaws": len(real),
        "true_positives": len(true_pos),
        "false_positives": sorted(false_pos),
        "missed": sorted(missed),
        "precision": round(precision, 2),
        "recall": round(recall, 2),
    }


def main():
    with open(os.path.join(HERE, "expected.json"), encoding="utf-8") as f:
        targets = json.load(f)

    results = {}
    for name, info in targets.items():
        folder = info["folder"]
        if not os.path.isdir(folder):
            print(f"[!] Folder not found for {name}: {folder}")
            continue
        print(f"\n=== {name} ===")
        findings = analyze_directory(folder)
        result = compare(findings, info["real_flaws"])
        results[name] = result
        print(f"Reported findings : {result['reported']}")
        print(f"Real flaws listed : {result['real_flaws']}")
        print(f"Found (true pos.) : {result['true_positives']}")
        print(f"Precision         : {result['precision']}")
        print(f"Recall            : {result['recall']}")
        for path, rule in result["false_positives"]:
            print(f"  FALSE POSITIVE: {rule}  {path}")
        for path, rule in result["missed"]:
            print(f"  MISSED:         {rule}  {path}")

    out_path = os.path.join(HERE, "benchmark_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
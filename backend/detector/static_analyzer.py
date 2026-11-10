import subprocess
import json
import os
import re
import shutil


def get_evidence(match):
    """Read the matching line straight from the file (Semgrep hides it when not logged in)."""
    try:
        with open(match["path"], encoding="utf-8", errors="ignore") as f:
            line = f.read().splitlines()[match["start"]["line"] - 1].strip()
    except Exception:
        return "No code snippet available."

    def hide(m):
        text = m.group(0)
        inner = text[1:-1]
        if len(inner) > 6:
            return text[0] + inner[:4] + "****" + text[-1]
        return text

    # Hide most of any long text inside quotes, so we never show a full secret
    line = re.sub(r'"[^"]*"|\'[^\']*\'', hide, line)
    return line[:200]


def short_path(path, base_dir):
    """Show src/app.js instead of C:\\Users\\...\\temp\\src\\app.js"""
    try:
        return os.path.relpath(path, base_dir)
    except ValueError:
        return path


def analyze_directory(target_directory: str):
    """
    Scans a project directory using custom Semgrep rules.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    rule_path = os.path.join(current_dir, "rules.yaml")

    formatted_findings = []

    if not os.path.exists(rule_path):
        return [{"error": f"Configuration file missing at {rule_path}"}]

    print(f"[*] VibePen Engine running static analysis on: {target_directory}")

    if shutil.which("semgrep") is None:
        return [{"error": "Semgrep is not installed. Run: python -m pip install semgrep"}]

    command = ["semgrep", "scan", f"--config={rule_path}", target_directory, "--json"]

    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=False)

        if result.stdout.strip():
            scan_data = json.loads(result.stdout)
            raw_results = scan_data.get("results", [])

            for match in raw_results:
                extra = match.get("extra", {})
                line_number = match.get("start", {}).get("line")
                # Semgrep adds a folder prefix like "detector." - keep only the rule name
                rule_id = match.get("check_id", "vulnerability_detected").split(".")[-1]

                formatted_findings.append({
                    "type": rule_id,
                    "title": rule_id,
                    "evidence": get_evidence(match),
                    "location": f"{short_path(match.get('path'), target_directory)} (Line {line_number})",
                    "severity": extra.get("severity", "ERROR"),
                    "message": extra.get("message", ""),
                    "description": extra.get("message", "")
                })

        return formatted_findings

    except json.JSONDecodeError:
        return [{"error": "Failed to parse backend scanning JSON matrix."}]
    except Exception as e:
        return [{"error": f"Scanner runtime error: {str(e)}"}]


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    print("[*] Running local module self-test...")
    print(analyze_directory(current_dir))
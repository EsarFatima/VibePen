import json
from datetime import datetime, timezone
from pathlib import Path


HISTORY_FILE = Path(__file__).with_name("scan_history.json")
MAX_ENTRIES_PER_TARGET = 20


def _target_key(target: str) -> str:
    return target.rstrip("/")


def _read_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def record_scan(report: dict) -> dict:
    target = _target_key(report["target"])
    entry = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": report["risk_score"],
        "total_findings": report["total_findings"],
        "severity_counts": report.get("severity_counts", {}),
    }
    history = _read_history()
    entry["target"] = target
    history.append(entry)
    target_history = [item for item in history if item.get("target") == target]
    other_history = [item for item in history if item.get("target") != target]
    target_history = sorted(target_history, key=lambda item: item.get("scanned_at", ""), reverse=True)
    HISTORY_FILE.write_text(
        json.dumps(other_history + target_history[:MAX_ENTRIES_PER_TARGET], indent=2),
        encoding="utf-8",
    )
    return entry


def get_scan_history(target: str, limit: int = 10) -> list[dict]:
    target = _target_key(target)
    entries = [item for item in _read_history() if item.get("target") == target]
    return sorted(entries, key=lambda item: item.get("scanned_at", ""), reverse=True)[:limit]
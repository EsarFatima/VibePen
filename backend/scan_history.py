import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


HISTORY_FILE = Path(__file__).with_name("scan_history.json")
def _target_key(target: str) -> str:
    return target.rstrip("/")


def _read_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        changed = False
        for item in history:
            if not item.get("id"):
                item["id"] = uuid.uuid5(uuid.NAMESPACE_URL, f"vibepen:{item.get('target', '')}:{item.get('scanned_at', '')}").hex
                changed = True
            if not item.get("target_type"):
                item["target_type"] = "ZIP" if item.get("target", "").lower().endswith(".zip") else "URL"
                changed = True
        if changed:
            HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
        return history
    except (OSError, json.JSONDecodeError):
        return []


def record_scan(report: dict) -> dict:
    target = _target_key(report["target"])
    entry = {
        "id": report.get("id", uuid.uuid4().hex),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target_type": report.get("scan_type", report.get("target_type", "URL")),
        "risk_score": report["risk_score"],
        "total_findings": report["total_findings"],
        "severity_counts": report.get("severity_counts", {}),
        "report": report,
    }
    history = _read_history()
    entry["target"] = target
    history.append(entry)
    target_history = [item for item in history if item.get("target") == target]
    other_history = [item for item in history if item.get("target") != target]
    target_history = sorted(target_history, key=lambda item: item.get("scanned_at", ""), reverse=True)
    HISTORY_FILE.write_text(json.dumps(other_history + target_history, indent=2), encoding="utf-8")
    return entry


def get_scan_history(target: str, limit: int = 10) -> list[dict]:
    target = _target_key(target)
    entries = [item for item in _read_history() if item.get("target") == target]
    return sorted(entries, key=lambda item: item.get("scanned_at", ""), reverse=True)[:limit]


def get_all_scan_history() -> list[dict]:
    return sorted(_read_history(), key=lambda item: item.get("scanned_at", ""), reverse=True)


def get_scan(scan_id: str) -> dict | None:
    return next((item for item in _read_history() if item.get("id") == scan_id), None)


def delete_scan(scan_id: str) -> bool:
    history = _read_history()
    remaining = [item for item in history if item.get("id") != scan_id]
    if len(remaining) == len(history):
        return False
    HISTORY_FILE.write_text(json.dumps(remaining, indent=2), encoding="utf-8")
    return True
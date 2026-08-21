import requests
import time


def check_rate_limit(session: requests.Session, url: str, attempts: int = 15, delay: float = 0.1) -> list[dict]:
    findings = []
    got_throttled = False
    for _ in range(attempts):
        try:
            resp = session.get(url, timeout=5)
            if resp.status_code == 429:
                got_throttled = True
                break
        except requests.RequestException:
            pass
        time.sleep(delay)

    if not got_throttled:
        findings.append({
            "type": "missing_rate_limit",
            "evidence": f"No throttling observed after {attempts} rapid requests to {url}",
            "location": url
        })
    return findings
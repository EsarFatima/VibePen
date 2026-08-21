import requests


def check_unauthenticated_access(base_url: str, protected_paths: list[str]) -> list[dict]:
    findings = []
    for path in protected_paths:
        url = f"{base_url}{path}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 and "login.php" not in resp.url:
                findings.append({
                    "type": "missing_auth",
                    "evidence": f"Unauthenticated request to {url} returned 200 OK",
                    "location": url
                })
        except requests.RequestException as e:
            findings.append({"error": f"request failed: {e}"})
    return findings
import requests


def check_wildcard_cors(session: requests.Session, url: str) -> list[dict]:
    findings = []
    try:
        resp = session.get(url, timeout=5)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append({
                "type": "wildcard_cors",
                "evidence": f"Access-Control-Allow-Origin: * on {url}",
                "location": url
            })
    except requests.RequestException as e:
        findings.append({"error": f"request failed: {e}"})
    return findings


def check_cors_credentials_misconfig(session: requests.Session, url: str) -> list[dict]:
    findings = []
    try:
        resp = session.get(url, timeout=5)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        aac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and aac.lower() == "true":
            findings.append({
                "type": "wildcard_cors",
                "evidence": f"Dangerous combo: wildcard origin + credentials=true on {url}",
                "location": url
            })
    except requests.RequestException as e:
        findings.append({"error": f"request failed: {e}"})
    return findings
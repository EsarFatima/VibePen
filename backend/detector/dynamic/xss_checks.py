import requests
import uuid


def check_reflected_xss(session: requests.Session, url: str, param: str) -> list[dict]:
    """
    Sends a unique marker in <angle brackets>. If it comes back
    un-escaped, the app is vulnerable to reflected XSS.
    """
    findings = []
    marker = f"xsstest{uuid.uuid4().hex[:8]}"
    payload = f"<{marker}>"
    try:
        resp = session.get(url, params={param: payload}, timeout=5)
        if payload in resp.text:
            findings.append({
                "type": "xss_risk",
                "evidence": f"Unescaped input reflected back for param '{param}'",
                "location": url
            })
    except requests.RequestException as e:
        findings.append({"error": f"request failed: {e}"})
    return findings


def check_stored_xss(session: requests.Session, submit_url: str, view_url: str, field: str) -> list[dict]:
    """
    Submits a marker to a form (e.g. guestbook/comment field), then
    checks a separate page where it would be displayed. Confirms
    stored XSS, not just reflected.
    """
    findings = []
    marker = f"storedxss{uuid.uuid4().hex[:8]}"
    payload = f"<{marker}>"
    try:
        session.post(submit_url, data={field: payload}, timeout=5)
        view_resp = session.get(view_url, timeout=5)
        if payload in view_resp.text:
            findings.append({
                "type": "xss_risk",
                "evidence": f"Stored, unescaped input found on {view_url} after submitting via '{field}'",
                "location": view_url
            })
    except requests.RequestException as e:
        findings.append({"error": f"request failed: {e}"})
    return findings


if __name__ == "__main__":
    from detector.dynamic.auth_session import login_dvwa
    session = login_dvwa()
    reflected_url = "http://localhost:8080/vulnerabilities/xss_r/"
    print("Reflected:", check_reflected_xss(session, reflected_url, "name"))

    # DVWA's stored XSS page uses fields "txtName" and "mtxMessage"
    stored_url = "http://localhost:8080/vulnerabilities/xss_s/"
    print("Stored:", check_stored_xss(session, stored_url, stored_url, "mtxMessage"))
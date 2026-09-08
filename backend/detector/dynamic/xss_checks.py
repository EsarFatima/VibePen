
import requests
import re
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


def check_stored_xss(session: requests.Session, page_url: str, name_field: str, message_field: str) -> list[dict]:
    findings = []
    marker = f"storedxss{uuid.uuid4().hex[:8]}"
    payload = f"<{marker}>"

    try:
        page = session.get(page_url, timeout=5)
        
        # Try to find CSRF token if it exists (some forms have it, some don't)
        match = re.search(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", page.text)
        csrf_token = match.group(1) if match else None

        # Build POST data; include CSRF token only if found
        post_data = {
            name_field: "tester",
            message_field: payload,
            "btnSign": "Sign Guestbook",
        }
        if csrf_token:
            post_data["user_token"] = csrf_token

        session.post(page_url, data=post_data, timeout=5)

        view_resp = session.get(page_url, timeout=5)
        if payload in view_resp.text:
            findings.append({
                "type": "xss_risk",
                "evidence": f"Stored, unescaped input found on {page_url} after submitting via '{message_field}'",
                "location": page_url
            })
    except requests.RequestException as e:
        findings.append({"error": f"request failed: {e}"})
    return findings

if __name__ == "__main__":
    from detector.dynamic.auth_session import login_dvwa
    session = login_dvwa("http://localhost:8080", username="admin", password="password")

    reflected_url = "http://localhost:8080/vulnerabilities/xss_r/"
    print("Reflected:", check_reflected_xss(session, reflected_url, "name"))

    stored_url = "http://localhost:8080/vulnerabilities/xss_s/"
    print("Stored:", check_stored_xss(session, stored_url, "txtName", "mtxMessage"))

    
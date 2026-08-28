
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
        print("=== PAGE STATUS ===", page.status_code)
        print("=== FINAL URL ===", page.url)
        print("=== FIRST 500 CHARS ===")
        print(page.text[:500])

        idx = page.text.find("user_token")
        if idx == -1:
            print("=== 'user_token' STRING NOT FOUND ANYWHERE ON PAGE ===")
        else:
            print("=== SNIPPET AROUND user_token ===")
            print(page.text[max(0, idx-100):idx+150])

        match = re.search(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", page.text)
        if not match:
            findings.append({"error": "Could not find CSRF token on stored XSS page"})
            return findings
        csrf_token = match.group(1)

        session.post(page_url, data={
            name_field: "tester",
            message_field: payload,
            "btnSign": "Sign Guestbook",
            "user_token": csrf_token,
        }, timeout=5)

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
    session = login_dvwa("http://localhost:8080", username="admin", password="iamesar")

    reflected_url = "http://localhost:8080/vulnerabilities/xss_r/"
    print("Reflected:", check_reflected_xss(session, reflected_url, "name"))

    stored_url = "http://localhost:8080/vulnerabilities/xss_s/"
    print("Stored:", check_stored_xss(session, stored_url, "txtName", "mtxMessage"))

    

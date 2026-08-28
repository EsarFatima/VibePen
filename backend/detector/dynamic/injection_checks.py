import requests


def check_sql_injection_error_based(session: requests.Session, url: str, param: str, extra_params: dict = None) -> list[dict]:
    """
    Sends a single quote. If a DB error message leaks back, that's a
    strong, low-effort signal of SQL injection.
    """
    findings = []
    params = {param: "'"}
    if extra_params:
        params.update(extra_params)
    try:
        resp = session.get(url, params=params, timeout=5)
        error_signs = ["sql syntax", "mysql_fetch", "you have an error in your sql", "warning: mysql"]
        if any(sign in resp.text.lower() for sign in error_signs):
            findings.append({
                "type": "sql_injection_pattern",
                "evidence": f"SQL error message leaked when sending ' to param '{param}'",
                "location": url
            })
    except requests.RequestException as e:
        findings.append({"error": f"request failed: {e}"})
    return findings


def check_sql_injection_boolean(session: requests.Session, url: str, param: str, extra_params: dict = None) -> list[dict]:
    """
    Compares response to a TRUE condition vs a FALSE condition.
    A meaningful length difference suggests unsanitized SQL.
    """
    findings = []
    true_params = {param: "' OR '1'='1"}
    false_params = {param: "' OR '1'='2"}
    if extra_params:
        true_params.update(extra_params)
        false_params.update(extra_params)
    try:
        true_resp = session.get(url, params=true_params, timeout=5)
        false_resp = session.get(url, params=false_params, timeout=5)

        len_diff = abs(len(true_resp.text) - len(false_resp.text))
        if len_diff > 50:
            findings.append({
                "type": "sql_injection_pattern",
                "evidence": f"Response length differs by {len_diff} chars between TRUE/FALSE SQLi payloads on '{param}'",
                "location": url
            })
    except requests.RequestException as e:
        findings.append({"error": f"request failed: {e}"})
    return findings


if __name__ == "__main__":
    from detector.dynamic.auth_session import login_dvwa, set_dvwa_security
    session = login_dvwa()
    set_dvwa_security(session, "http://localhost:8080", "impossible")
    print("Session security cookie:", session.cookies.get("security"))
    url = "http://localhost:8080/vulnerabilities/sqli/"
    extra = {"Submit": "Submit"}
    print("Error-based:", check_sql_injection_error_based(session, url, "id", extra))
    print("Boolean-based:", check_sql_injection_boolean(session, url, "id", extra))
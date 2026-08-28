from detector.dynamic.auth_session import login_dvwa, verify_session_valid, set_dvwa_security, get_dvwa_security_level
from detector.dynamic.injection_checks import check_sql_injection_error_based, check_sql_injection_boolean
from detector.dynamic.xss_checks import check_reflected_xss, check_stored_xss


def run_injection_checks(base_url: str = "http://localhost:8080", security_level: str = "low") -> list[dict]:
    session = login_dvwa(base_url, username="admin", password="iamesar")
    set_dvwa_security(session, base_url, security_level)

    actual_level = get_dvwa_security_level(session, base_url)
    print(f"Running checks at DVWA security level: {actual_level}")

    findings = []
    sqli_extra = {"Submit": "Submit"}
    findings += check_sql_injection_error_based(session, f"{base_url}/vulnerabilities/sqli/", "id", sqli_extra)
    findings += check_sql_injection_boolean(session, f"{base_url}/vulnerabilities/sqli/", "id", sqli_extra)
    findings += check_reflected_xss(session, f"{base_url}/vulnerabilities/xss_r/", "name")
    findings += check_stored_xss(session, f"{base_url}/vulnerabilities/xss_s/", f"{base_url}/vulnerabilities/xss_s/", "mtxMessage")
    return findings


if __name__ == "__main__":
    print("Starting injection checks...")
    try:
        results = run_injection_checks(security_level="impossible")
        print(f"Total findings: {len(results)}")
        for f in results:
            print(f)
    except Exception:
        import traceback
        traceback.print_exc()
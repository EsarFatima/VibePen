import os

import requests

from detector.dynamic.auth_bypass_checks import check_unauthenticated_access
from detector.dynamic.auth_session import login_dvwa, set_dvwa_security
from detector.dynamic.cors_checks import check_cors_credentials_misconfig, check_wildcard_cors
from detector.dynamic.error_handling_checks import check_verbose_error_handling
from detector.dynamic.injection_checks import check_sql_injection_boolean, check_sql_injection_error_based
from detector.dynamic.rate_limit_checks import check_rate_limit
from detector.dynamic.xss_checks import check_reflected_xss, check_stored_xss


def run_dvwa_checks(
    base_url: str = "http://localhost:8080",
    username: str | None = None,
    password: str | None = None,
    security_level: str = "low",
) -> tuple[list[dict], dict | None]:
    base_url = base_url.rstrip("/")
    public_session = requests.Session()
    findings = []
    findings += check_wildcard_cors(public_session, f"{base_url}/index.php")
    findings += check_cors_credentials_misconfig(public_session, f"{base_url}/index.php")
    findings += check_unauthenticated_access(base_url, [
        "/vulnerabilities/sqli/",
        "/vulnerabilities/xss_r/",
        "/security.php",
    ])

    if not username and not password:
        return findings, None
    if not username or not password:
        raise ValueError("DVWA username and password must be provided together")

    session = login_dvwa(base_url, username, password)
    set_dvwa_security(session, base_url, security_level)
    findings += check_rate_limit(session, f"{base_url}/login.php", attempts=10)
    sqli_url = f"{base_url}/vulnerabilities/sqli/"
    findings += check_sql_injection_error_based(session, sqli_url, "id", {"Submit": "Submit"})
    findings += check_sql_injection_boolean(session, sqli_url, "id", {"Submit": "Submit"})
    findings += check_reflected_xss(session, f"{base_url}/vulnerabilities/xss_r/", "name")
    findings += check_stored_xss(session, f"{base_url}/vulnerabilities/xss_s/", "txtName", "mtxMessage")
    findings += check_verbose_error_handling(session, sqli_url, "id", {"Submit": "Submit"})
    return findings, {"username": username, "authenticated": True, "security_level": security_level}
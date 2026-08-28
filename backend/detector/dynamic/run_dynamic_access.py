from detector.dynamic.auth_session import login_dvwa
from detector.dynamic.cors_checks import check_wildcard_cors, check_cors_credentials_misconfig
from detector.dynamic.auth_bypass_checks import check_unauthenticated_access
from detector.dynamic.rate_limit_checks import check_rate_limit


def run_access_checks(base_url: str = "http://localhost:8080", username: str | None = None, password: str | None = None) -> list[dict]:
    session = login_dvwa(base_url, username, password)

    findings = []
    findings += check_wildcard_cors(session, f"{base_url}/index.php")
    findings += check_cors_credentials_misconfig(session, f"{base_url}/index.php")
    findings += check_unauthenticated_access(base_url, [
        "/vulnerabilities/sqli/",
        "/vulnerabilities/xss_r/",
        "/security.php",
    ])
    findings += check_rate_limit(session, f"{base_url}/login.php", attempts=10)
    return findings


if __name__ == "__main__":
    print("Starting access checks...")
    try:
        results = run_access_checks()
        print(f"Total findings: {len(results)}")
        for f in results:
            print(f)
    except Exception as e:
        import traceback
        print("ERROR occurred:")
        traceback.print_exc()
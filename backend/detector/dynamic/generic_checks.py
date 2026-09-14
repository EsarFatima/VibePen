from urllib.parse import urlparse

import requests


def run_generic_checks(base_url: str) -> list[dict]:
    findings = []
    try:
        response = requests.get(base_url.rstrip("/"), timeout=5, allow_redirects=True)
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]

    final_url = response.url
    if urlparse(final_url).scheme != "https":
        findings.append({
            "type": "insecure_transport",
            "evidence": f"The website is reachable over {urlparse(final_url).scheme.upper()} instead of HTTPS",
            "location": final_url,
        })

    required_headers = {
        "Content-Security-Policy": "limits what browser content can run",
        "Referrer-Policy": "limits URL information shared with other sites",
        "Permissions-Policy": "limits access to browser capabilities",
    }
    missing = [name for name in required_headers if not response.headers.get(name)]
    if missing:
        details = ", ".join(f"{name} ({required_headers[name]})" for name in missing)
        findings.append({
            "type": "missing_security_headers",
            "evidence": f"The website response did not include: {details}",
            "location": final_url,
        })
    return findings
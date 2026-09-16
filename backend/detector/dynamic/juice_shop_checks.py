import uuid

import requests


def login_juice_shop(
    session: requests.Session,
    base_url: str,
    email: str,
    password: str,
) -> None:
    response = session.post(
        f"{base_url.rstrip('/')}/rest/user/login",
        json={"email": email, "password": password},
        timeout=5,
    )
    response.raise_for_status()
    token = response.json().get("authentication", {}).get("token")
    if not token:
        raise RuntimeError("Juice Shop login response did not contain an authentication token")
    session.headers.update({"Authorization": f"Bearer {token}"})


def verify_juice_shop_account(session: requests.Session, base_url: str, email: str) -> dict:
    response = session.get(f"{base_url.rstrip('/')}/rest/user/whoami", timeout=5)
    response.raise_for_status()
    body = response.json()
    user = body.get("user", body)
    return {
        "email": user.get("email") or email,
        "role": user.get("role") or "authenticated account",
        "id": user.get("id"),
    }


def check_juice_shop_authenticated_user_area(session: requests.Session, base_url: str) -> list[dict]:
    url = f"{base_url.rstrip('/')}/rest/user/data"
    try:
        response = session.get(url, timeout=5)
        if response.status_code in {401, 403}:
            return [{
                "type": "missing_auth",
                "evidence": f"A signed-in account was denied access to its own user area (HTTP {response.status_code})",
                "location": url,
            }]
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]
    return []


def check_juice_shop_cross_account_basket(
    other_session: requests.Session,
    base_url: str,
    basket_id: int,
) -> list[dict]:
    url = f"{base_url.rstrip('/')}/rest/basket/{basket_id}"
    try:
        response = other_session.get(url, timeout=5)
        if response.status_code == 200:
            return [{
                "type": "broken_access_control",
                "evidence": f"A second signed-in account received basket {basket_id} without ownership verification",
                "location": url,
            }]
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]
    return []


def check_juice_shop_anonymous_basket_access(session: requests.Session, base_url: str) -> list[dict]:
    url = f"{base_url.rstrip('/')}/rest/basket/1"
    try:
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            return [{
                "type": "missing_auth",
                "evidence": "An unauthenticated request received a successful response from a user basket endpoint",
                "location": url,
            }]
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]
    return []


def check_juice_shop_anonymous_admin_access(session: requests.Session, base_url: str) -> list[dict]:
    url = f"{base_url.rstrip('/')}/rest/admin/application-configuration"
    try:
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            return [{
                "type": "missing_auth",
                "evidence": "An unauthenticated request received administrative application configuration",
                "location": url,
            }]
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]
    return []


def check_juice_shop_cors(session: requests.Session, base_url: str) -> list[dict]:
    url = f"{base_url.rstrip('/')}/rest/products/search?q=apple"
    try:
        response = session.get(url, headers={"Origin": "https://scanner.invalid"}, timeout=5)
        origin = response.headers.get("Access-Control-Allow-Origin", "")
        credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower()
        if origin == "*":
            evidence = f"Access-Control-Allow-Origin: * on {url}"
            if credentials == "true":
                evidence += " with Access-Control-Allow-Credentials: true"
            return [{
                "type": "wildcard_cors",
                "evidence": evidence,
                "location": url,
            }]
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]
    return []


def check_juice_shop_security_headers(session: requests.Session, base_url: str) -> list[dict]:
    url = base_url.rstrip("/")
    required_headers = {
        "Content-Security-Policy": "limits what browser content can run",
        "Referrer-Policy": "limits URL information shared with other sites",
        "Permissions-Policy": "limits access to browser capabilities",
    }
    try:
        response = session.get(url, timeout=5)
        missing = [name for name in required_headers if not response.headers.get(name)]
        if missing:
            details = ", ".join(f"{name} ({required_headers[name]})" for name in missing)
            return [{
                "type": "missing_security_headers",
                "evidence": f"The website response did not include: {details}",
                "location": url,
            }]
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]
    return []


def check_juice_shop_search_errors(session: requests.Session, base_url: str) -> list[dict]:
    url = f"{base_url.rstrip('/')}/rest/products/search"
    findings = []
    for payload in ["'", "' OR '1'='1", "<script>alert(1)</script>"]:
        try:
            response = session.get(url, params={"q": payload}, timeout=5)
            body = response.text.lower()
            technical_markers = [
                "sql syntax",
                "sequelize",
                "stack trace",
                "uncaught exception",
                "internal server error",
            ]
            marker = next((item for item in technical_markers if item in body), None)
            if marker:
                findings.append({
                    "type": "verbose_error_handling",
                    "evidence": f"Search response exposed technical detail '{marker}' for malformed input",
                    "location": response.url,
                    "payload_used": payload,
                })
        except requests.RequestException as error:
            findings.append({"error": f"request failed: {error}"})
    return findings


def check_juice_shop_endpoint_errors(session: requests.Session, base_url: str) -> list[dict]:
    findings = []
    for path in ["/rest/order-history", "/rest/user/data"]:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            response = session.get(url, timeout=5)
            body = response.text.lower()
            technical_markers = ["stack", "typeerror", "unexpected path", "illegal activity"]
            marker = next((item for item in technical_markers if item in body), None)
            if response.status_code >= 500 and marker:
                findings.append({
                    "type": "verbose_error_handling",
                    "evidence": f"An unauthenticated request to {path} returned HTTP {response.status_code} with technical error detail '{marker}'",
                    "location": response.url,
                })
        except requests.RequestException as error:
            findings.append({"error": f"request failed: {error}"})
    return findings


def check_juice_shop_reflected_input(session: requests.Session, base_url: str) -> list[dict]:
    url = f"{base_url.rstrip('/')}/rest/products/search"
    marker = f"vibepen-{uuid.uuid4().hex}"
    try:
        response = session.get(url, params={"q": marker}, timeout=5)
        if marker in response.text:
            return [{
                "type": "xss_risk",
                "evidence": "A unique search marker was reflected in the API response",
                "location": response.url,
                "payload_used": marker,
            }]
    except requests.RequestException as error:
        return [{"error": f"request failed: {error}"}]
    return []
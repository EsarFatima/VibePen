from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class TargetProfile:
    kind: str
    label: str
    supported: bool
    message: str


def detect_target(base_url: str) -> TargetProfile:
    base_url = base_url.rstrip("/")
    session = requests.Session()
    try:
        response = session.get(
            f"{base_url}/rest/products/search",
            params={"q": "apple"},
            timeout=5,
        )
        if response.status_code == 200:
            body = response.json()
            if body.get("status") == "success" and isinstance(body.get("data"), list):
                return TargetProfile("juice_shop", "OWASP Juice Shop", True, "")
    except (requests.RequestException, ValueError):
        pass

    try:
        response = session.get(f"{base_url}/login.php", timeout=5)
        if "DVWA" in response.text or "Damn Vulnerable Web Application" in response.text:
            return TargetProfile(
                "dvwa",
                "Damn Vulnerable Web Application",
                True,
                "DVWA checks are running. Sign-in is needed for the deeper injection and XSS checks.",
            )
    except requests.RequestException:
        pass

    return TargetProfile(
        "generic",
        "Generic website checks",
        True,
        "This website was not recognized, so only general safety checks were run.",
    )
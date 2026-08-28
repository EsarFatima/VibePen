import requests
import re
from getpass import getpass

def set_dvwa_security(session: requests.Session, base_url: str, level: str = "low") -> None:
    if level not in {"low", "medium", "high", "impossible"}:
        raise ValueError("DVWA security level must be low, medium, high, or impossible")

    security_page = session.get(f"{base_url}/security.php", timeout=5)
    if "security.php" not in security_page.url:
        raise RuntimeError("DVWA session is not authenticated; cannot set security level")

    match = re.search(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", security_page.text)
    if not match:
        raise Exception("Could not find CSRF token on DVWA security page")
    csrf_token = match.group(1)

    session.post(f"{base_url}/security.php", data={
        "security": level,
        "seclev_submit": "Submit",
        "user_token": csrf_token,
    }, timeout=5)
    if session.cookies.get("security") != level:
        raise RuntimeError(f"DVWA did not apply requested security level: {level}")

def get_dvwa_security_level(session: requests.Session, base_url: str = "http://localhost:8080") -> str:
    security_page = session.get(f"{base_url}/security.php", timeout=5)
    if "security.php" not in security_page.url:
        raise RuntimeError("DVWA session is not authenticated; cannot read security level")

    match = re.search(
        r'<option\s+value=["\'](low|medium|high|impossible)["\'][^>]*selected',
        security_page.text,
        re.IGNORECASE,
    )
    if not match:
        raise RuntimeError("Could not read the selected DVWA security level")
    return match.group(1).lower()

def login_dvwa(base_url: str = "http://localhost:8080", username: str | None = None, password: str | None = None) -> requests.Session:
    """
    DVWA requires a CSRF token grabbed from the login page before
    POSTing credentials. Returns an authenticated session.
    """
    username = username or input("DVWA username: ").strip()
    password = password if password is not None else getpass("DVWA password: ")
    if not username or not password:
        raise ValueError("DVWA username and password are required")

    session = requests.Session()

    login_page = session.get(f"{base_url}/login.php", timeout=5)
    match = re.search(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", login_page.text)
    if not match:
        raise Exception("Could not find CSRF token on DVWA login page — is DVWA running and DB set up?")
    csrf_token = match.group(1)

    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": csrf_token,
    }
    session.post(f"{base_url}/login.php", data=payload, timeout=5)

    if not verify_session_valid(session, base_url):
        raise RuntimeError("DVWA login failed; no vulnerability checks were run")

    return session



def verify_session_valid(session: requests.Session, base_url: str = "http://localhost:8080") -> bool:
    """
    Confirms the session can access DVWA's authenticated home page.
    """
    resp = session.get(f"{base_url}/index.php", timeout=5)
    return "login.php" not in resp.url and "Welcome" in resp.text


if __name__ == "__main__":
    session = login_dvwa(
        "http://localhost:8080",
    )
    is_valid = verify_session_valid(session)
    print(f"Login successful: {is_valid}")
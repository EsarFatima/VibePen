import requests
import re


def login_dvwa(base_url: str = "http://localhost:8080", username: str = "admin", password: str = "password") -> requests.Session:
    """
    DVWA requires a CSRF token grabbed from the login page before
    POSTing credentials. Returns an authenticated session.
    """
    session = requests.Session()

    login_page = session.get(f"{base_url}/login.php")
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
    session.post(f"{base_url}/login.php", data=payload)

    return session


def verify_session_valid(session: requests.Session, base_url: str = "http://localhost:8080") -> bool:
    """
    Confirms the session can access DVWA's authenticated home page.
    """
    resp = session.get(f"{base_url}/index.php")
    return "login.php" not in resp.url and "Welcome" in resp.text


if __name__ == "__main__":
    session = login_dvwa()
    is_valid = verify_session_valid(session)
    print(f"Login successful: {is_valid}")
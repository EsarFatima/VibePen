"""Domain ownership verification (SRS objective O6).

A live scan may only start for a domain the user has proven they control.
Two methods are supported:
  dns  - a TXT record at _vibepen-verify.<domain>
  file - a text file at https://<domain>/.well-known/vibepen-verify.txt
Local sandbox targets (localhost, 127.0.0.1) are trusted automatically.
"""
import ipaddress
import json
import re
import secrets
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests

STORE = Path(__file__).with_name("verified_domains.json")
VALID_DAYS = 30
SANDBOX_HOSTS = {"localhost", "127.0.0.1", "::1"}
TXT_LABEL = "_vibepen-verify"
FILE_PATH = "/.well-known/vibepen-verify.txt"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    if "//" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0].rstrip(".")
    if not DOMAIN_RE.match(value):
        raise ValueError("Enter a valid domain, such as example.com.")
    return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load() -> dict:
    try:
        return json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    STORE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _with_instructions(record: dict) -> dict:
    value = f"vibepen-verification={record['token']}"
    return {
        **record,
        "txt_name": f"{TXT_LABEL}.{record['domain']}",
        "txt_value": value,
        "file_url": f"https://{record['domain']}{FILE_PATH}",
        "file_content": value,
    }


def _expired(record: dict) -> bool:
    expires = record.get("expires_at")
    return bool(expires) and datetime.fromisoformat(expires) <= _now()


def _status(record: dict) -> str:
    if record["status"] == "verified" and _expired(record):
        return "expired"
    return record["status"]


def issue_challenge(domain: str) -> dict:
    domain = normalize_domain(domain)
    data = _load()
    record = data.get(domain)
    if record is None or _status(record) in ("expired", "failed"):
        record = {"domain": domain, "token": secrets.token_hex(12), "status": "pending", "created_at": _now().isoformat()}
        data[domain] = record
        _save(data)
    return _with_instructions({**record, "status": _status(record)})


def list_domains() -> list[dict]:
    return [_with_instructions({**r, "status": _status(r)}) for r in _load().values()]


def remove_domain(domain: str) -> bool:
    domain = normalize_domain(domain)
    data = _load()
    if domain not in data:
        return False
    del data[domain]
    _save(data)
    return True


def _check_dns(domain: str, token: str) -> bool:
    expected = f"vibepen-verification={token}"
    try:
        answers = dns.resolver.resolve(f"{TXT_LABEL}.{domain}", "TXT", lifetime=5)
    except (dns.exception.DNSException, OSError):
        return False
    return any("".join(part.decode() for part in rdata.strings).strip() == expected for rdata in answers)


def _is_public_host(domain: str) -> bool:
    """Stops the verifier being used to probe private or internal addresses."""
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(domain, None)}
    except OSError:
        return False
    return bool(addresses) and not any(
        not ipaddress.ip_address(a).is_global for a in addresses
    )


def _check_file(domain: str, token: str) -> bool:
    expected = f"vibepen-verification={token}"
    if not _is_public_host(domain):
        return False
    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{domain}{FILE_PATH}", timeout=5, allow_redirects=False)
        except requests.RequestException:
            continue
        if response.status_code == 200 and response.text.strip() == expected:
            return True
    return False


def verify_domain(domain: str, method: str) -> dict:
    domain = normalize_domain(domain)
    if method not in ("dns", "file"):
        raise ValueError("Method must be 'dns' or 'file'.")
    data = _load()
    record = data.get(domain)
    if record is None:
        raise KeyError(domain)
    checker = _check_dns if method == "dns" else _check_file
    if checker(domain, record["token"]):
        record.update(status="verified", method=method, verified_at=_now().isoformat(),
                      expires_at=(_now() + timedelta(days=VALID_DAYS)).isoformat(), error=None)
    else:
        label = "TXT record" if method == "dns" else "verification file"
        record.update(status="failed", error=f"{label} not found yet. DNS changes can take a few minutes.")
    data[domain] = record
    _save(data)
    return _with_instructions({**record, "status": _status(record)})


def is_authorized(target: str) -> bool:
    """True if the target host is a sandbox host or belongs to a verified domain."""
    host = urlparse(target if "//" in target else f"//{target}").hostname
    if not host:
        return False
    host = host.lower().rstrip(".")
    if host in SANDBOX_HOSTS:
        return True
    for record in _load().values():
        if record["status"] != "verified" or _expired(record):
            continue
        domain = record["domain"]
        if host == domain:
            return True
        # A DNS record proves control of the whole zone; a file only proves one host.
        if record.get("method") == "dns" and host.endswith("." + domain):
            return True
    return False
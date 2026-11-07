"""Per-user domain ownership records, stored in the database.

The network checks live in verification.py. This module decides which user owns
which record, and whether a given user may scan a given target.
"""
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import verification as v
from db import Domain, utcnow

_CHECKERS = {"dns": "_check_dns", "file": "_check_file", "meta": "_check_meta"}
_FAILURE_LABEL = {
    "dns": "TXT record",
    "file": "verification file",
    "meta": "Meta tag in the homepage <head>",
}
_FAILURE_HINT = {
    "dns": "DNS changes can take a few minutes.",
    "file": "DNS changes can take a few minutes.",
    "meta": "It must be in the HTML your server sends, not added by JavaScript.",
}


def _iso(value):
    # Stored as naive UTC. The trailing Z tells the browser it is UTC, not local time.
    return value.isoformat() + "Z" if value else None


def _effective_status(record: Domain) -> str:
    if record.status == "verified" and record.expires_at and record.expires_at <= utcnow():
        return "expired"
    return record.status


def serialize(record: Domain) -> dict:
    value = f"vibepen-verification={record.token}"
    return {
        "domain": record.domain,
        "token": record.token,
        "status": _effective_status(record),
        "method": record.method,
        "verified_at": _iso(record.verified_at),
        "expires_at": _iso(record.expires_at),
        "created_at": _iso(record.created_at),
        "error": record.error,
        "txt_name": f"{v.TXT_LABEL}.{record.domain}",
        "txt_value": value,
        "file_url": f"https://{record.domain}{v.FILE_PATH}",
        "file_content": value,
        "meta_tag": f'<meta name="{v.META_NAME}" content="{record.token}">',
    }


def _get(session: Session, user_id: int, domain: str):
    return session.query(Domain).filter_by(user_id=user_id, domain=domain).first()


def issue_challenge(session: Session, user_id: int, domain: str) -> dict:
    domain = v.normalize_domain(domain)
    record = _get(session, user_id, domain)
    if record is None:
        record = Domain(user_id=user_id, domain=domain, token=secrets.token_hex(12), status="pending")
        session.add(record)
        try:
            session.commit()
        except IntegrityError:  # double submit: another request created it first
            session.rollback()
            record = _get(session, user_id, domain)
    elif _effective_status(record) in ("expired", "failed"):
        record.token = secrets.token_hex(12)
        record.status = "pending"
        record.method = record.verified_at = record.expires_at = record.error = None
        session.commit()
    return serialize(record)


def list_domains(session: Session, user_id: int) -> list[dict]:
    rows = session.query(Domain).filter_by(user_id=user_id).order_by(Domain.created_at, Domain.id).all()
    return [serialize(row) for row in rows]


def remove_domain(session: Session, user_id: int, domain: str) -> bool:
    domain = v.normalize_domain(domain)
    deleted = session.query(Domain).filter_by(user_id=user_id, domain=domain).delete()
    session.commit()
    return deleted > 0


def verify_domain(session: Session, user_id: int, domain: str, method: str) -> dict:
    domain = v.normalize_domain(domain)
    if method not in _CHECKERS:
        raise ValueError("Method must be 'dns', 'file' or 'meta'.")
    record = _get(session, user_id, domain)
    if record is None:
        raise KeyError(domain)
    checker = getattr(v, _CHECKERS[method])
    if checker(domain, record.token):
        now = utcnow()
        record.status = "verified"
        record.method = method
        record.verified_at = now
        record.expires_at = now + timedelta(days=v.VALID_DAYS)
        record.error = None
    else:
        record.status = "failed"
        record.error = f"{_FAILURE_LABEL[method]} not found yet. {_FAILURE_HINT[method]}"
    session.commit()
    return serialize(record)


def is_authorized(session: Session, user_id, target: str) -> bool:
    """True for sandbox hosts, or when this user has verified the target's domain."""
    try:
        host = urlparse(target if "//" in target else f"//{target}").hostname
    except ValueError:
        return False
    if not host:
        return False
    host = host.lower().rstrip(".")
    if host in v.SANDBOX_HOSTS:
        return True
    if user_id is None:
        return False
    rows = session.query(Domain).filter(
        Domain.user_id == user_id, Domain.status == "verified", Domain.expires_at > utcnow()
    ).all()
    for record in rows:
        if host == record.domain:
            return True
        # A DNS record proves control of the whole zone; a file or meta tag proves one host.
        if record.method == "dns" and host.endswith("." + record.domain):
            return True
    return False
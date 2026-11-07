"""Tests for per-user domain records. Run: python -m pytest test_domain_service.py -q"""
import datetime as dt

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db as database
import domain_service as ds
import verification as v

USER_A, USER_B = 1, 2


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    database.Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, autoflush=False)()
    s.add_all([
        database.User(id=USER_A, email="a@test.com", password_hash="x"),
        database.User(id=USER_B, email="b@test.com", password_hash="x"),
    ])
    s.commit()
    yield s
    s.close()
    engine.dispose()


def verified(session, user, domain, method, monkeypatch):
    monkeypatch.setattr(v, "_check_" + method, lambda d, t: True)
    ds.issue_challenge(session, user, domain)
    return ds.verify_domain(session, user, domain, method)


def test_issue_creates_pending_record_with_instructions(session):
    record = ds.issue_challenge(session, USER_A, "example.com")
    assert record["status"] == "pending"
    assert record["method"] is None
    assert len(record["token"]) == 24
    assert record["txt_name"] == "_vibepen-verify.example.com"
    assert record["token"] in record["meta_tag"]


def test_issue_is_idempotent_for_same_user(session):
    first = ds.issue_challenge(session, USER_A, "example.com")
    second = ds.issue_challenge(session, USER_A, "example.com")
    assert first["token"] == second["token"]
    assert len(ds.list_domains(session, USER_A)) == 1


def test_two_users_get_separate_records_for_same_domain(session):
    a = ds.issue_challenge(session, USER_A, "example.com")
    b = ds.issue_challenge(session, USER_B, "example.com")
    assert a["token"] != b["token"]
    assert session.query(database.Domain).count() == 2


def test_other_users_cannot_see_verify_or_remove(session):
    ds.issue_challenge(session, USER_A, "example.com")
    assert ds.list_domains(session, USER_B) == []
    with pytest.raises(KeyError):
        ds.verify_domain(session, USER_B, "example.com", "dns")
    assert ds.remove_domain(session, USER_B, "example.com") is False
    assert len(ds.list_domains(session, USER_A)) == 1


def test_verify_success_stores_expiry_and_method(session, monkeypatch):
    result = verified(session, USER_A, "example.com", "meta", monkeypatch)
    assert result["status"] == "verified"
    assert result["method"] == "meta"
    assert result["verified_at"].endswith("Z") and result["expires_at"].endswith("Z")
    row = session.query(database.Domain).one()
    assert row.expires_at - row.verified_at == dt.timedelta(days=v.VALID_DAYS)


def test_verify_failure_records_error(session, monkeypatch):
    ds.issue_challenge(session, USER_A, "example.com")
    monkeypatch.setattr(v, "_check_dns", lambda d, t: False)
    result = ds.verify_domain(session, USER_A, "example.com", "dns")
    assert result["status"] == "failed"
    assert "TXT record" in result["error"]


def test_unknown_method_rejected(session):
    ds.issue_challenge(session, USER_A, "example.com")
    with pytest.raises(ValueError):
        ds.verify_domain(session, USER_A, "example.com", "carrier-pigeon")


def test_invalid_domain_rejected(session):
    with pytest.raises(ValueError):
        ds.issue_challenge(session, USER_A, "not a domain")


def test_sandbox_hosts_allowed_for_everyone(session):
    for user in (None, USER_A):
        assert ds.is_authorized(session, user, "http://localhost:3000") is True
        assert ds.is_authorized(session, user, "http://127.0.0.1:8080") is True


def test_verified_domain_authorizes_only_its_owner(session, monkeypatch):
    verified(session, USER_A, "example.com", "dns", monkeypatch)
    assert ds.is_authorized(session, USER_A, "https://example.com/path") is True
    assert ds.is_authorized(session, USER_B, "https://example.com") is False
    assert ds.is_authorized(session, None, "https://example.com") is False


def test_subdomain_rules_depend_on_method(session, monkeypatch):
    verified(session, USER_A, "dns-site.com", "dns", monkeypatch)
    verified(session, USER_A, "file-site.com", "file", monkeypatch)
    assert ds.is_authorized(session, USER_A, "https://app.dns-site.com") is True
    assert ds.is_authorized(session, USER_A, "https://app.file-site.com") is False
    assert ds.is_authorized(session, USER_A, "https://file-site.com") is True


def test_expired_verification_is_not_authorized(session, monkeypatch):
    verified(session, USER_A, "example.com", "dns", monkeypatch)
    row = session.query(database.Domain).one()
    row.expires_at = database.utcnow() - dt.timedelta(days=1)
    session.commit()
    assert ds.list_domains(session, USER_A)[0]["status"] == "expired"
    assert ds.is_authorized(session, USER_A, "https://example.com") is False


def test_failed_domain_gets_fresh_token_when_added_again(session, monkeypatch):
    first = ds.issue_challenge(session, USER_A, "example.com")
    monkeypatch.setattr(v, "_check_dns", lambda d, t: False)
    ds.verify_domain(session, USER_A, "example.com", "dns")
    second = ds.issue_challenge(session, USER_A, "example.com")
    assert second["token"] != first["token"]
    assert second["status"] == "pending"
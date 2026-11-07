"""Tests for the meta-tag verification method.

Run with: python -m pytest test_verification_meta.py -q
"""
import pytest

import verification as v

TOKEN = "abc123def456abc123def456"


class FakeResponse:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.encoding = "utf-8"
        self._body = body.encode()

    def iter_content(self, chunk_size=65536):
        yield self._body

    def close(self):
        pass


def page(meta=f'<meta name="vibepen-verification" content="{TOKEN}">', body_extra=""):
    return f"<!doctype html><html><head><title>x</title>{meta}</head><body>{body_extra}</body></html>"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(v, "STORE", tmp_path / "verified.json")
    monkeypatch.setattr(v, "_is_public_host", lambda domain: True)


def serve(monkeypatch, routes):
    """routes maps URL -> FakeResponse. Any other URL behaves like a connection failure."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        assert kwargs.get("allow_redirects") is False
        if url not in routes:
            raise v.requests.ConnectionError("no route")
        return routes[url]

    monkeypatch.setattr(v.requests, "get", fake_get)
    return calls


def test_finds_tag_in_any_attribute_order_and_case(monkeypatch):
    html = page(f'<META CONTENT="{TOKEN}" NAME="Vibepen-Verification" />')
    serve(monkeypatch, {"https://example.com/": FakeResponse(body=html)})
    assert v._check_meta("example.com", TOKEN) is True


def test_wrong_token_fails(monkeypatch):
    serve(monkeypatch, {"https://example.com/": FakeResponse(body=page())})
    assert v._check_meta("example.com", "someothertoken") is False


def test_tag_inside_body_is_ignored(monkeypatch):
    html = page(meta="", body_extra=f'<meta name="vibepen-verification" content="{TOKEN}">')
    serve(monkeypatch, {"https://example.com/": FakeResponse(body=html)})
    assert v._check_meta("example.com", TOKEN) is False


def test_private_host_is_refused_without_any_request(monkeypatch):
    monkeypatch.setattr(v, "_is_public_host", lambda domain: False)
    calls = serve(monkeypatch, {"https://example.com/": FakeResponse(body=page())})
    assert v._check_meta("example.com", TOKEN) is False
    assert calls == []


def test_same_host_redirect_is_followed(monkeypatch):
    serve(monkeypatch, {
        "https://example.com/": FakeResponse(301, headers={"Location": "/home"}),
        "https://example.com/home": FakeResponse(body=page()),
    })
    assert v._check_meta("example.com", TOKEN) is True


def test_off_host_redirect_is_refused(monkeypatch):
    calls = serve(monkeypatch, {
        "https://example.com/": FakeResponse(302, headers={"Location": "https://evil.test/"}),
        "http://example.com/": FakeResponse(302, headers={"Location": "https://evil.test/"}),
        "https://evil.test/": FakeResponse(body=page()),
    })
    assert v._check_meta("example.com", TOKEN) is False
    assert "https://evil.test/" not in calls


def test_redirect_loop_gives_up(monkeypatch):
    serve(monkeypatch, {
        "https://example.com/": FakeResponse(302, headers={"Location": "https://example.com/"}),
        "http://example.com/": FakeResponse(302, headers={"Location": "http://example.com/"}),
    })
    assert v._check_meta("example.com", TOKEN) is False


def test_tag_beyond_size_limit_is_not_read(monkeypatch):
    html = "x" * (v.MAX_PAGE_BYTES + 10) + page()
    serve(monkeypatch, {"https://example.com/": FakeResponse(body=html)})
    assert v._check_meta("example.com", TOKEN) is False


def test_verify_domain_meta_success_and_scope(monkeypatch):
    token = v.issue_challenge("example.com")["token"]
    html = page(f'<meta name="vibepen-verification" content="{token}">')
    serve(monkeypatch, {"https://example.com/": FakeResponse(body=html)})
    result = v.verify_domain("example.com", "meta")
    assert result["status"] == "verified"
    assert result["method"] == "meta"
    assert result["expires_at"]
    assert v.is_authorized("https://example.com") is True
    # A meta tag proves one host only, unlike a DNS record which covers the whole zone.
    assert v.is_authorized("https://app.example.com") is False


def test_verify_domain_meta_failure_explains_javascript(monkeypatch):
    v.issue_challenge("example.com")
    serve(monkeypatch, {"https://example.com/": FakeResponse(body=page(meta=""))})
    result = v.verify_domain("example.com", "meta")
    assert result["status"] == "failed"
    assert "JavaScript" in result["error"]


def test_unknown_method_is_still_rejected():
    v.issue_challenge("example.com")
    with pytest.raises(ValueError):
        v.verify_domain("example.com", "carrier-pigeon")


def test_instructions_include_the_meta_tag():
    record = v.issue_challenge("example.com")
    assert record["meta_tag"] == f'<meta name="vibepen-verification" content="{record["token"]}">'

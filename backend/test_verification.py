"""Run from backend/:  python -m unittest test_verification -v"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import verification


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.object(verification, "STORE", Path(self.tmp.name) / "verified.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_normalize_accepts_urls_and_rejects_junk(self):
        self.assertEqual(verification.normalize_domain("https://Example.com/path"), "example.com")
        with self.assertRaises(ValueError):
            verification.normalize_domain("not a domain")

    def test_challenge_creates_token_and_instructions(self):
        record = verification.issue_challenge("example.com")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["txt_name"], "_vibepen-verify.example.com")
        self.assertTrue(record["txt_value"].endswith(record["token"]))

    def test_unverified_domain_is_blocked_sandbox_is_not(self):
        verification.issue_challenge("example.com")
        self.assertFalse(verification.is_authorized("https://example.com"))
        self.assertTrue(verification.is_authorized("http://localhost:3000"))
        self.assertTrue(verification.is_authorized("http://127.0.0.1:8080"))

    def test_dns_success_authorizes_domain_and_subdomains(self):
        verification.issue_challenge("example.com")
        with mock.patch.object(verification, "_check_dns", return_value=True):
            result = verification.verify_domain("example.com", "dns")
        self.assertEqual(result["status"], "verified")
        self.assertTrue(verification.is_authorized("https://example.com/login"))
        self.assertTrue(verification.is_authorized("https://app.example.com"))
        self.assertFalse(verification.is_authorized("https://evil-example.com"))
        self.assertFalse(verification.is_authorized("https://example.com.evil.net"))

    def test_file_method_does_not_cover_subdomains(self):
        verification.issue_challenge("example.com")
        with mock.patch.object(verification, "_check_file", return_value=True):
            verification.verify_domain("example.com", "file")
        self.assertTrue(verification.is_authorized("https://example.com"))
        self.assertFalse(verification.is_authorized("https://app.example.com"))

    def test_failed_check_stays_blocked(self):
        verification.issue_challenge("example.com")
        with mock.patch.object(verification, "_check_dns", return_value=False):
            result = verification.verify_domain("example.com", "dns")
        self.assertEqual(result["status"], "failed")
        self.assertFalse(verification.is_authorized("https://example.com"))

    def test_verification_expires_after_30_days(self):
        verification.issue_challenge("example.com")
        with mock.patch.object(verification, "_check_dns", return_value=True):
            verification.verify_domain("example.com", "dns")
        data = verification._load()
        data["example.com"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        verification._save(data)
        self.assertFalse(verification.is_authorized("https://example.com"))

    def test_file_check_refuses_private_addresses(self):
        with mock.patch.object(verification.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]):
            with mock.patch.object(verification.requests, "get") as get:
                self.assertFalse(verification._check_file("internal.example.com", "abc"))
                get.assert_not_called()

    def test_file_check_requires_exact_token(self):
        public = [(2, 1, 6, "", ("93.184.216.34", 0))]
        good = mock.Mock(status_code=200, text="vibepen-verification=abc\n")
        bad = mock.Mock(status_code=200, text="vibepen-verification=zzz")
        with mock.patch.object(verification.socket, "getaddrinfo", return_value=public):
            with mock.patch.object(verification.requests, "get", return_value=good):
                self.assertTrue(verification._check_file("example.com", "abc"))
            with mock.patch.object(verification.requests, "get", return_value=bad):
                self.assertFalse(verification._check_file("example.com", "abc"))


if __name__ == "__main__":
    unittest.main()
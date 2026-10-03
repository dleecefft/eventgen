from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.http_client import ResponseSnapshot
from app.certificate_inspector import CertificateChainResult, CertificateDetails
from app.web_app import (
    ALLOWED_HOSTS_ENV,
    PASSWORD_ENV,
    USERNAME_ENV,
    create_app,
    hostname_is_allowed,
    validate_target,
)


class WebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.username = secrets.token_urlsafe(12)
        self.password = secrets.token_urlsafe(24)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {
                USERNAME_ENV: self.username,
                PASSWORD_ENV: self.password,
                ALLOWED_HOSTS_ENV: "example.test,*.example.test",
                "EVENTGEN_SESSION_DIR": self.temp_dir.name,
                "EVENTGEN_SECURE_COOKIES": "false",
            },
            clear=False,
        )
        self.environment.start()
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp_dir.cleanup()

    def auth_headers(self) -> dict[str, str]:
        token = base64.b64encode(
            f"{self.username}:{self.password}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def csrf_token(self) -> str:
        response = self.client.get("/", headers=self.auth_headers())
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as browser_session:
            return str(browser_session["csrf_token"])

    def test_missing_credentials_fail_startup(self) -> None:
        with patch.dict(
            os.environ,
            {USERNAME_ENV: "", PASSWORD_ENV: "", ALLOWED_HOSTS_ENV: ""},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "Missing required"):
                create_app({"TESTING": True})

    def test_health_check_is_minimal_and_unauthenticated(self) -> None:
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_application_requires_basic_authentication(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 401)
        self.assertIn("Basic", response.headers["WWW-Authenticate"])

    def test_csrf_is_required_for_post(self) -> None:
        response = self.client.post(
            "/request",
            headers=self.auth_headers(),
            data={"url": "https://example.test/"},
        )

        self.assertEqual(response.status_code, 400)

    def test_hostname_patterns_are_exact_or_subdomain_only(self) -> None:
        patterns = ("example.test", "*.example.test")

        self.assertTrue(hostname_is_allowed("example.test", patterns))
        self.assertTrue(hostname_is_allowed("dev.example.test", patterns))
        self.assertFalse(hostname_is_allowed("notexample.test", patterns))

    @patch("app.web_app.socket.getaddrinfo")
    def test_target_validation_rejects_non_public_dns_answer(self, mock_dns) -> None:
        mock_dns.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]

        with self.assertRaisesRegex(ValueError, "non-public"):
            validate_target("https://example.test/", ("example.test",))

    @patch("app.web_app.socket.getaddrinfo")
    def test_target_validation_accepts_allowed_public_address(self, mock_dns) -> None:
        mock_dns.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
        ]

        result = validate_target("https://example.test/path", ("example.test",))

        self.assertEqual(result, "https://example.test/path")

    @patch("app.web_app.validate_target", return_value="https://example.test/start")
    @patch("app.web_app.send_once")
    def test_request_is_logged_and_downloadable(self, mock_send, _mock_validate) -> None:
        mock_send.return_value = ResponseSnapshot(
            request_url="https://example.test/start",
            validation_id="validation-123",
            user_agent="test-agent",
            status=200,
            reason="OK",
            headers=(("Content-Type", "text/plain"), ("Set-Cookie", "secret=value")),
            body=b"response evidence",
            body_truncated=False,
            tls_verified=True,
        )
        csrf = self.csrf_token()

        response = self.client.post(
            "/request",
            headers=self.auth_headers(),
            data={
                "csrf_token": csrf,
                "url": "https://example.test/start",
                "user_agent_index": "0",
                "verify_tls": "on",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"response evidence", response.data)

        download = self.client.get("/session-log.json", headers=self.auth_headers())
        report = json.loads(download.data)

        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers["Content-Disposition"])
        self.assertTrue(report["ephemeral_storage"])
        request_event = next(
            event for event in report["events"] if event["event_type"] == "request"
        )
        self.assertEqual(request_event["request"]["validation_id"], "validation-123")
        self.assertEqual(
            request_event["response"]["headers"][1]["value"], "[REDACTED]"
        )
        self.assertNotIn(self.password, download.get_data(as_text=True))

    @patch("app.web_app.get_public_egress_ip", return_value="203.0.113.42")
    def test_public_ip_is_added_to_session_log(self, _mock_ip) -> None:
        csrf = self.csrf_token()

        response = self.client.post(
            "/public-ip",
            headers=self.auth_headers(),
            data={
                "csrf_token": csrf,
                "user_agent_index": "0",
                "verify_tls": "on",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Public egress IP: 203.0.113.42", response.data)

    @patch("app.web_app.validate_target", return_value="https://example.test/")
    @patch("app.web_app.inspect_certificate_chain")
    def test_certificate_chain_is_displayed_and_logged(
        self,
        mock_inspect,
        _mock_validate,
    ) -> None:
        mock_inspect.return_value = CertificateChainResult(
            url="https://example.test/",
            hostname="example.test",
            port=443,
            tls_verified=True,
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificates=(
                CertificateDetails(
                    position=0,
                    role="leaf",
                    subject="CN=example.test",
                    issuer="CN=Test Intermediate",
                    serial_number="1234",
                    not_valid_before_utc="2026-01-01T00:00:00+00:00",
                    not_valid_after_utc="2027-01-01T00:00:00+00:00",
                    sha256_fingerprint="AA:BB:CC",
                    signature_hash="sha256",
                    public_key_type="RSAPublicKey",
                    dns_names=("example.test",),
                    ip_addresses=(),
                    is_ca=False,
                    self_issued=False,
                ),
            ),
        )
        csrf = self.csrf_token()

        response = self.client.post(
            "/certificate-chain",
            headers=self.auth_headers(),
            data={
                "csrf_token": csrf,
                "url": "https://example.test/",
                "verify_tls": "on",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CN=example.test", response.data)
        download = self.client.get("/session-log.json", headers=self.auth_headers())
        report = json.loads(download.data)
        chain_event = next(
            event
            for event in report["events"]
            if event["event_type"] == "certificate_chain_observed"
        )
        self.assertEqual(chain_event["certificate_chain"]["certificates"][0]["role"], "leaf")


if __name__ == "__main__":
    unittest.main()

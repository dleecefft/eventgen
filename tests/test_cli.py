from __future__ import annotations

import ssl
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from unittest.mock import patch

from event_generator_cli import (
    DEFAULT_USER_AGENT,
    USER_AGENT_OPTIONS,
    build_ssl_context,
    get_public_egress_ip,
    normalize_url,
    redirect_target,
    select_user_agent,
    send_once,
)


class FixtureHandler(BaseHTTPRequestHandler):
    requests_seen: list[str] = []
    user_agents_seen: list[str] = []

    def do_GET(self) -> None:
        type(self).requests_seen.append(self.path)
        type(self).user_agents_seen.append(self.headers.get("User-Agent", ""))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            self.wfile.write(b"redirect review")
            return
        if self.path == "/large":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"abcdefghij")
            return
        if self.path == "/ip":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ip":"203.0.113.42"}')
            return
        if self.path == "/bad-ip":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ip":"not-an-address"}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"final response")

    def log_message(self, format: str, *args: object) -> None:
        return


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        FixtureHandler.requests_seen.clear()
        FixtureHandler.user_agents_seen.clear()

    def test_user_agent_catalog_has_six_options_and_defaults_to_edge(self) -> None:
        self.assertEqual(len(USER_AGENT_OPTIONS), 6)
        self.assertIs(DEFAULT_USER_AGENT, USER_AGENT_OPTIONS[0])
        self.assertIn("Microsoft Edge", DEFAULT_USER_AGENT.name)

    def test_user_agent_catalog_includes_required_detection_markers(self) -> None:
        values = [option.value for option in USER_AGENT_OPTIONS]

        self.assertTrue(any("soc_testing" in value for value in values))
        self.assertIn("axios/1.7.9", values)
        self.assertTrue(any("PrismaAccessBrowser" in value for value in values))

    def test_user_agent_selector_rejects_negative_index(self) -> None:
        with (
            patch("builtins.input", side_effect=["-1", "2"]),
            redirect_stdout(StringIO()),
        ):
            selected = select_user_agent(DEFAULT_USER_AGENT)

        self.assertIs(selected, USER_AGENT_OPTIONS[2])

    def test_normalize_url_defaults_to_https_and_removes_fragment(self) -> None:
        self.assertEqual(
            normalize_url("example.com/path#browser-only"),
            "https://example.com/path",
        )

    def test_normalize_url_rejects_embedded_credentials(self) -> None:
        with self.assertRaisesRegex(ValueError, "Credentials"):
            normalize_url("https://name:secret@example.com/")

    def test_redirect_target_resolves_relative_location(self) -> None:
        self.assertEqual(
            redirect_target("https://example.com/start", "/next"),
            "https://example.com/next",
        )

    def test_send_once_does_not_follow_redirect(self) -> None:
        snapshot = send_once(f"{self.base_url}/redirect")

        self.assertEqual(snapshot.status, 302)
        self.assertEqual(snapshot.header("Location"), "/final")
        self.assertEqual(FixtureHandler.requests_seen, ["/redirect"])

    def test_send_once_limits_response_preview(self) -> None:
        snapshot = send_once(f"{self.base_url}/large", max_body_bytes=4)

        self.assertEqual(snapshot.body, b"abcd")
        self.assertTrue(snapshot.body_truncated)

    def test_send_once_uses_selected_user_agent(self) -> None:
        selected = "soc_testing/unit-test"

        snapshot = send_once(f"{self.base_url}/final", user_agent=selected)

        self.assertEqual(snapshot.user_agent, selected)
        self.assertEqual(FixtureHandler.user_agents_seen, [selected])

    def test_get_public_egress_ip_accepts_valid_address(self) -> None:
        address = get_public_egress_ip(endpoint=f"{self.base_url}/ip")

        self.assertEqual(address, "203.0.113.42")

    def test_get_public_egress_ip_rejects_invalid_address(self) -> None:
        with self.assertRaisesRegex(ConnectionError, "invalid address"):
            get_public_egress_ip(endpoint=f"{self.base_url}/bad-ip")

    def test_unverified_ssl_context_is_explicit(self) -> None:
        context = build_ssl_context(False)

        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main()

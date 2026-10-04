from __future__ import annotations

import unittest

from app.http_client import ResponseSnapshot
from app.waf_tester import (
    RateLimitError,
    WafRunManager,
    build_plan,
    inspect_template,
    load_payload_pack,
)


class MemoryLogStore:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def append(self, session_id: str, event: dict[str, object]) -> None:
        self.events.append((session_id, event))


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


class WafTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pack = load_payload_pack()

    def build(self, template: str, mode: str = "isolated"):
        return build_plan(
            owner_session_id="owner",
            url_template=template,
            substitution_mode=mode,
            rate_name="standard",
            user_agent_index=0,
            verify_tls=True,
            payload_pack=self.pack,
            target_validator=lambda url: url,
        )

    def test_payload_pack_is_versioned_and_has_six_reviewed_payloads(self) -> None:
        self.assertEqual(self.pack.version, "1.0.0")
        self.assertEqual(len(self.pack.payloads), 6)
        self.assertEqual(len(self.pack.digest_sha256), 64)

    def test_three_markers_are_located_in_path_and_query_values(self) -> None:
        template, positions = inspect_template(
            "https://example.test/[replaceme]?customer=[replaceme2]&city=[replaceme3]"
        )

        self.assertEqual(template.split("?")[0], "https://example.test/[replaceme]")
        self.assertEqual(positions[0].location, "path")
        self.assertEqual(positions[1].parameter_name, "customer")
        self.assertEqual(positions[2].parameter_name, "city")

    def test_invalid_marker_forms_are_rejected(self) -> None:
        cases = (
            ("https://example.test/search", "exactly once"),
            ("https://example.test/[replaceme2]", r"\[replaceme\] exactly once"),
            ("https://example.test/[replaceme]/[replaceme]", "exactly once"),
            ("https://example.test/[replaceme]?x=[replaceme3]", "requires"),
            ("https://example.test/[replaceme4]", "Unsupported"),
            ("https://[replaceme]/path", "invalid|hostname|scheme"),
            ("https://example.test/?[replaceme]=value", "parameter names"),
        )
        for template, message in cases:
            with self.subTest(template=template):
                with self.assertRaisesRegex(ValueError, message):
                    inspect_template(template)

    def test_isolated_mode_uses_one_active_marker_and_controls_the_other(self) -> None:
        plan = self.build(
            "https://example.test/search?customer=[replaceme]&city=[replaceme2]"
        )

        self.assertEqual(len(plan.requests), 1 + len(self.pack.payloads) * 2)
        self.assertEqual(plan.requests[0].active_markers, ())
        first_payload = plan.requests[1]
        values = dict(first_payload.marker_values)
        self.assertEqual(first_payload.active_markers, ("[replaceme]",))
        self.assertEqual(values["[replaceme]"], self.pack.payloads[0].logical_value)
        self.assertTrue(values["[replaceme2]"].startswith("soc_testing_control_"))

    def test_synchronized_mode_uses_same_payload_in_every_marker(self) -> None:
        plan = self.build(
            "https://example.test/search?customer=[replaceme]&city=[replaceme2]",
            mode="synchronized",
        )

        self.assertEqual(len(plan.requests), 1 + len(self.pack.payloads))
        first_payload = plan.requests[1]
        values = dict(first_payload.marker_values)
        self.assertEqual(first_payload.active_markers, ("[replaceme]", "[replaceme2]"))
        self.assertEqual(len(set(values.values())), 1)

    def test_payload_is_encoded_once_as_one_url_component(self) -> None:
        plan = self.build("https://example.test/search?q=[replaceme]")

        generated = plan.requests[1].url
        self.assertIn("%3Csoc_testing%3E", generated)
        self.assertNotIn("%253C", generated)


class WafRunManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.log = MemoryLogStore()
        self.clock = FakeClock()
        self.sent: list[str] = []
        self.sent_user_agents: list[str] = []

        def sender(url: str, **kwargs: object) -> ResponseSnapshot:
            self.sent.append(url)
            self.sent_user_agents.append(str(kwargs["user_agent"]))
            return ResponseSnapshot(
                request_url=url,
                validation_id=str(kwargs["validation_id"]),
                user_agent=str(kwargs["user_agent"]),
                status=200,
                reason="OK",
                headers=(("Date", "Sun, 04 Oct 2026 18:00:00 GMT"),),
                body=b"<active-markup-is-recorded-as-text>",
                body_truncated=False,
                tls_verified=True,
            )

        self.manager = WafRunManager(
            target_validator=lambda url: url,
            log_store=self.log,
            clock=self.clock,
            utc_clock=lambda: "2026-10-04T18:00:00Z",
            sender=sender,
        )
        plan = build_plan(
            owner_session_id="owner",
            url_template="https://example.test/search?q=[replaceme]",
            substitution_mode="synchronized",
            rate_name="fast",
            user_agent_index=0,
            verify_tls=True,
            payload_pack=self.manager.payload_pack,
            target_validator=lambda url: url,
        )
        self.manager.save_preview(plan)
        self.run = self.manager.create_run(plan.preview_id, "owner")

    def test_run_ownership_is_enforced(self) -> None:
        with self.assertRaises(KeyError):
            self.manager.get_run(self.run.run_id, "different-session")

    def test_server_rate_gate_rejects_request_before_five_seconds(self) -> None:
        self.manager.execute_next(self.run.run_id, "owner")
        self.clock.value += 4.999

        with self.assertRaises(RateLimitError):
            self.manager.execute_next(self.run.run_id, "owner")
        self.assertEqual(len(self.sent), 1)

        self.clock.value += 0.001
        self.manager.execute_next(self.run.run_id, "owner")
        self.assertEqual(len(self.sent), 2)

    def test_each_result_is_logged_immediately_with_clock_evidence(self) -> None:
        result = self.manager.execute_next(self.run.run_id, "owner")

        self.assertEqual(result["target_date_header"], "Sun, 04 Oct 2026 18:00:00 GMT")
        self.assertEqual(result["user_agent"], self.run.plan.user_agent)
        request_events = [event for _, event in self.log.events if event["event_type"] == "waf_request"]
        self.assertEqual(len(request_events), 1)
        self.assertEqual(
            request_events[0]["result"]["validation_id"],
            self.run.plan.requests[0].validation_id,
        )
        self.assertEqual(
            request_events[0]["result"]["user_agent"], self.run.plan.user_agent
        )

    def test_selected_user_agent_is_used_for_every_request_in_run(self) -> None:
        expected = self.run.plan.user_agent
        for index in range(len(self.run.plan.requests)):
            if index:
                self.clock.value += self.run.plan.interval_seconds
            self.manager.execute_next(self.run.run_id, "owner")

        self.assertEqual(
            self.sent_user_agents,
            [expected] * len(self.run.plan.requests),
        )
        request_events = [
            event for _, event in self.log.events if event["event_type"] == "waf_request"
        ]
        self.assertTrue(
            all(event["result"]["user_agent"] == expected for event in request_events)
        )

    def test_manual_step_leaves_run_paused(self) -> None:
        self.manager.execute_next(self.run.run_id, "owner")

        self.assertEqual(self.run.state, "paused")
        self.assertIsNone(self.manager.active_run_id)


if __name__ == "__main__":
    unittest.main()

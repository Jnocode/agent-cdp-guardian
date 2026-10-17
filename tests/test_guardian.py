"""
Unit tests for agent_cdp_guardian.core, TOCTOUGuard, and lifecycle
"""

import unittest
import time
from agent_cdp_guardian.core import CDPGuardian, GuardianConfig
from agent_cdp_guardian.toctou import TOCTOUGuard, PageState
from agent_cdp_guardian.exceptions import (
    HostMismatchError,
    IdentityDriftError,
    TOCTOUDriftError
)


class TestTOCTOUGuard(unittest.TestCase):

    def setUp(self):
        self.guard = TOCTOUGuard(max_allowed_drift_seconds=1.0, strict_dom_match=True)

    def test_consistent_state_allows_action(self):
        state1 = PageState.compute(
            url="https://github.com/settings",
            dom_content="<div>Form Content</div>",
            target_node_content="<button id='save'>Save</button>"
        )
        state2 = PageState.compute(
            url="https://github.com/settings",
            dom_content="<div>Form Content</div>",
            target_node_content="<button id='save'>Save</button>"
        )
        executed = []
        result = self.guard.guard_action(
            lambda: state2,
            state1,
            lambda x: executed.append(x) or "success",
            "clicked"
        )
        self.assertEqual(result, "success")
        self.assertEqual(executed, ["clicked"])

    def test_url_drift_triggers_fail_closed(self):
        state1 = PageState.compute("https://github.com/settings", "<div>A</div>")
        state2 = PageState.compute("https://github.com/logout", "<div>A</div>")

        with self.assertRaises(TOCTOUDriftError) as ctx:
            self.guard.guard_action(lambda: state2, state1, lambda: None)
        self.assertIn("URL mutated", str(ctx.exception))

    def test_target_node_mutation_triggers_fail_closed(self):
        state1 = PageState.compute(
            url="https://github.com",
            dom_content="<div>Root</div>",
            target_node_content="<button>Confirm Transfer $10</button>"
        )
        # Malicious or dynamic DOM change to a different action
        state2 = PageState.compute(
            url="https://github.com",
            dom_content="<div>Root</div>",
            target_node_content="<button>Transfer All Funds</button>"
        )

        with self.assertRaises(TOCTOUDriftError) as ctx:
            self.guard.guard_action(lambda: state2, state1, lambda: None, target_name="transfer_btn")
        self.assertIn("Target node 'transfer_btn' content/structure was altered", str(ctx.exception))

    def test_stale_observation_timeout(self):
        guard = TOCTOUGuard(max_allowed_drift_seconds=0.1)
        state1 = PageState.compute("https://github.com", "<div>Root</div>")
        time.sleep(0.15)
        state2 = PageState.compute("https://github.com", "<div>Root</div>")

        with self.assertRaises(TOCTOUDriftError) as ctx:
            guard.guard_action(lambda: state2, state1, lambda: None)
        self.assertIn("Stale state observation", str(ctx.exception))

    def test_target_node_disappearance_triggers_fail_closed(self):
        state1 = PageState(url="https://github.com", dom_hash="h1", target_node_hash="node123", timestamp=10.0)
        state2 = PageState(url="https://github.com", dom_hash="h1", target_node_hash=None, timestamp=10.05)
        with self.assertRaises(TOCTOUDriftError) as ctx:
            self.guard.assert_state_consistent(state1, state2, target_name="submit_btn")
        self.assertIn("disappeared", str(ctx.exception).lower())

    def test_negative_elapsed_triggers_fail_closed(self):
        state1 = PageState(url="https://github.com", dom_hash="h1", timestamp=2000.0)
        state2 = PageState(url="https://github.com", dom_hash="h1", timestamp=1000.0)
        with self.assertRaises(TOCTOUDriftError) as ctx:
            self.guard.assert_state_consistent(state1, state2)
        self.assertIn("invalid time interval", str(ctx.exception).lower())

    def test_nan_timestamp_triggers_fail_closed(self):
        state1 = PageState(url="https://github.com", dom_hash="h1", timestamp=float("nan"))
        state2 = PageState(url="https://github.com", dom_hash="h1", timestamp=1000.0)
        with self.assertRaises(TOCTOUDriftError) as ctx:
            self.guard.assert_state_consistent(state1, state2)
        self.assertIn("invalid time interval", str(ctx.exception).lower())



class TestCDPGuardianOrchestrator(unittest.TestCase):

    def setUp(self):
        self.config = GuardianConfig(
            allowed_hosts=["github.com", "gitlab.com"],
            expected_account="octocat",
            dom_header_selector="#user-badge",
            dom_header_pattern="octocat",
            enable_redaction=True
        )
        self.guardian = CDPGuardian(self.config)

    def test_filter_cdp_message_blocks_malicious_navigation(self):
        with self.assertRaises(HostMismatchError):
            self.guardian.filter_cdp_message(
                method="Page.navigate",
                params={"url": "https://evil-attacker-site.com/steal"}
            )

    def test_filter_cdp_message_allows_safe_navigation(self):
        params = {
            "url": "https://github.com/octocat/repo",
            "headers": {
                "Authorization": "Bearer 12345678901234567890",
            }
        }
        filtered = self.guardian.filter_cdp_message("Page.navigate", params)
        self.assertEqual(filtered["url"], "https://github.com/octocat/repo")
        self.assertEqual(filtered["headers"]["Authorization"], "Bearer 12345678901234567890")

    def test_guard_action_with_identity_verification(self):
        # Configure expected_account and dom_header_pattern
        state = PageState.compute(
            url="https://github.com/settings",
            dom_content="<div>Form Content</div>",
            target_node_content="<button id='save'>Save</button>",
            dom_header_text="Signed in as octocat"
        )
        called = []
        result = self.guardian.guard_action(
            get_current_state=lambda: state,
            initial_state=state,
            action_fn=lambda x: called.append(x) or "saved",
            x="ok"
        )
        self.assertEqual(result, "saved")
        self.assertEqual(called, ["ok"])

    def test_guard_action_detects_identity_drift_in_current_state(self):
        state1 = PageState.compute(
            url="https://github.com/settings",
            dom_content="<div>Form Content</div>",
            dom_header_text="Signed in as octocat"
        )
        state2 = PageState.compute(
            url="https://github.com/settings",
            dom_content="<div>Form Content</div>",
            dom_header_text="Signed in as attacker"
        )
        with self.assertRaises(IdentityDriftError):
            self.guardian.guard_action(
                get_current_state=lambda: state2,
                initial_state=state1,
                action_fn=lambda: None
            )

    def test_filter_cdp_message_does_not_corrupt_outgoing_tokens(self):
        cmd_params = {
            "targetId": "tab-123",
            "token": "session-auth-token-12345",
            "sessionId": "sub-session-999"
        }
        res = self.guardian.filter_cdp_message("Target.sendMessageToTarget", cmd_params)
        # Should NOT redact outgoing valid tokens
        self.assertEqual(res["token"], "session-auth-token-12345")
        self.assertEqual(res["targetId"], "tab-123")


    def test_sanitize_transcript(self):
        transcript = {
            "log": "Agent clicked login button",
            "secret_token": "sk-123456789012345678901234",
            "otp": "992182"
        }
        sanitized = self.guardian.sanitize_transcript(transcript)
        self.assertEqual(sanitized["secret_token"], "[REDACTED_SECRET_KEY_VALUE]")
        self.assertEqual(sanitized["otp"], "[REDACTED_SECRET_KEY_VALUE]")


if __name__ == "__main__":
    unittest.main()

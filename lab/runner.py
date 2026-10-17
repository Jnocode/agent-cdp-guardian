"""
Synthetic Regression Lab - Pure Python Runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Runs all scenario categories using synthetic snapshots (no browser required).
This suite runs in CI and verifies that invariants hold under synthetic state drift.
"""

import unittest
from agent_cdp_guardian import (
    CDPGuardian,
    GuardianConfig,
    PageState,
    IdentityDriftError,
    TOCTOUDriftError,
)
from lab.scenarios import (
    read_fixture,
    run_account_drift_positive,
    run_account_drift_negative,
    run_toctou_mutation_positive,
    run_toctou_mutation_negative_mutated,
    run_toctou_mutation_negative_removed,
    run_sensitive_otp_positive,
    run_sensitive_otp_negative,
)


class TestSyntheticRegressionLab(unittest.TestCase):
    """Verifies all safety scenarios in pure Python synthetic mode."""

    def setUp(self):
        self.config = GuardianConfig(
            allowed_hosts=["example.test", "localhost", "127.0.0.1"],
            expected_account="alice@example.test",
            dom_header_pattern="alice@example.test",
            enable_redaction=True,
            max_toctou_drift_seconds=3.0,
            fail_closed=True,
        )
        self.guardian = CDPGuardian(self.config)

    def test_scenario_1_account_drift_positive(self):
        html = read_fixture("account_drift.html")
        url = "http://example.test/settings"
        state = PageState.compute(
            url=url,
            dom_content=html,
            target_node_content="<button id='save-btn'>Save Preferences</button>",
            dom_header_text="alice@example.test"
        )
        action_called = False

        def action():
            nonlocal action_called
            action_called = True
            return {"status": "saved"}

        res = run_account_drift_positive(
            guardian=self.guardian,
            url=url,
            get_state_fn=lambda: state,
            action_fn=action
        )
        self.assertTrue(action_called, "Action should have executed for consistent account")
        self.assertEqual(res, {"status": "saved"})

    def test_scenario_1_account_drift_negative(self):
        html = read_fixture("account_drift.html")
        url = "http://example.test/settings"
        initial_state = PageState.compute(
            url=url,
            dom_content=html,
            target_node_content="<button id='save-btn'>Save Preferences</button>",
            dom_header_text="alice@example.test"
        )
        # Drifted state where user is now mallory
        drifted_state = PageState.compute(
            url=url,
            dom_content=html.replace("alice@example.test", "mallory@example.test"),
            target_node_content="<button id='save-btn'>Save Preferences</button>",
            dom_header_text="mallory@example.test"
        )
        action_called = False

        def action():
            nonlocal action_called
            action_called = True
            return {"status": "saved"}

        blocked, exc = run_account_drift_negative(
            guardian=self.guardian,
            url=url,
            get_initial_state_fn=lambda: initial_state,
            get_drifted_state_fn=lambda: drifted_state,
            action_fn=action
        )
        self.assertTrue(blocked, "Account drift must be blocked")
        self.assertFalse(action_called, "Action must NOT be called when account drifts")
        self.assertIsInstance(exc, IdentityDriftError)

    def test_scenario_2_toctou_mutation_positive(self):
        html = read_fixture("toctou_mutation.html")
        url = "http://example.test/transfer"
        state = PageState.compute(
            url=url,
            dom_content=html,
            target_node_content="<button id='action-btn' class='transfer-btn'>Confirm Transfer</button>",
            dom_header_text="alice@example.test"
        )
        action_called = False

        def action():
            nonlocal action_called
            action_called = True
            return {"status": "transferred"}

        res = run_toctou_mutation_positive(
            guardian=self.guardian,
            url=url,
            get_state_fn=lambda: state,
            action_fn=action
        )
        self.assertTrue(action_called)
        self.assertEqual(res, {"status": "transferred"})

    def test_scenario_2_toctou_mutation_negative_mutated(self):
        html = read_fixture("toctou_mutation.html")
        url = "http://example.test/transfer"
        initial_state = PageState.compute(
            url=url,
            dom_content=html,
            target_node_content="<button id='action-btn' class='transfer-btn'>Confirm Transfer</button>",
            dom_header_text="alice@example.test"
        )
        mutated_state = PageState.compute(
            url=url,
            dom_content=html,
            target_node_content="<button id='action-btn' class='transfer-btn'>Transfer All Assets to Unknown Recipient</button>",
            dom_header_text="alice@example.test"
        )
        action_called = False

        def action():
            nonlocal action_called
            action_called = True

        blocked, exc = run_toctou_mutation_negative_mutated(
            guardian=self.guardian,
            url=url,
            get_initial_state_fn=lambda: initial_state,
            get_mutated_state_fn=lambda: mutated_state,
            action_fn=action
        )
        self.assertTrue(blocked)
        self.assertFalse(action_called, "Action must NOT be called on mutated node")
        self.assertIsInstance(exc, TOCTOUDriftError)

    def test_scenario_2_toctou_mutation_negative_removed(self):
        html = read_fixture("toctou_mutation.html")
        url = "http://example.test/transfer"
        initial_state = PageState.compute(
            url=url,
            dom_content=html,
            target_node_content="<button id='action-btn' class='transfer-btn'>Confirm Transfer</button>",
            dom_header_text="alice@example.test"
        )
        removed_state = PageState.compute(
            url=url,
            dom_content=html,
            target_node_content=None,
            dom_header_text="alice@example.test"
        )
        action_called = False

        def action():
            nonlocal action_called
            action_called = True

        blocked, exc = run_toctou_mutation_negative_removed(
            guardian=self.guardian,
            url=url,
            get_initial_state_fn=lambda: initial_state,
            get_removed_state_fn=lambda: removed_state,
            action_fn=action
        )
        self.assertTrue(blocked)
        self.assertFalse(action_called, "Action must NOT be called on removed node")
        self.assertIsInstance(exc, TOCTOUDriftError)

    def test_scenario_3_sensitive_otp_positive(self):
        public_transcript = {
            "title": "Public Documentation",
            "message": "Welcome to agent-cdp-guardian safe browsing."
        }
        res = run_sensitive_otp_positive(self.guardian, public_transcript)
        self.assertEqual(res, public_transcript)

    def test_scenario_3_sensitive_otp_negative(self):
        sensitive_transcript = {
            "title": "MFA Challenge",
            "headers": {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummyPayload.syntheticSignature"
            },
            "body": "Your temporary verification code is: 481920 (valid for 5 minutes)"
        }
        sanitized = run_sensitive_otp_negative(self.guardian, sensitive_transcript)
        self.assertNotIn("481920", sanitized["body"])
        self.assertIn("[REDACTED_OTP_CODE]", sanitized["body"])
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", sanitized["headers"]["Authorization"])
        self.assertIn("[REDACTED_BEARER_TOKEN]", sanitized["headers"]["Authorization"])


if __name__ == "__main__":
    unittest.main()

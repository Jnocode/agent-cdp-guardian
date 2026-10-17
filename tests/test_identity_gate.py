"""
Unit tests for agent_cdp_guardian.identity_gate
"""

import unittest
from agent_cdp_guardian.identity_gate import IdentityGate, IdentityAnchor
from agent_cdp_guardian.exceptions import HostMismatchError, IdentityDriftError


class TestIdentityGate(unittest.TestCase):

    def setUp(self):
        self.anchor = IdentityAnchor(
            allowed_hosts=["github.com", "api.github.com"],
            expected_account="jnocode",
            dom_header_selector=".header-nav-current-user",
            dom_header_pattern="Signed in as jnocode"
        )
        self.gate = IdentityGate(self.anchor)

    def test_valid_host_and_dom_header(self):
        res = self.gate.verify(
            current_url="https://github.com/settings/tokens",
            dom_extracted_header="Signed in as jnocode (developer)"
        )
        self.assertTrue(res.valid)
        self.assertTrue(res.host_valid)
        self.assertTrue(res.dom_valid)
        self.assertEqual(res.current_host, "github.com")

    def test_subdomain_matching(self):
        res = self.gate.verify(
            current_url="https://api.github.com/user",
            dom_extracted_header="Signed in as jnocode"
        )
        self.assertTrue(res.valid)

    def test_disallowed_host_fails_closed(self):
        with self.assertRaises(HostMismatchError) as ctx:
            self.gate.verify(
                current_url="https://malicious-phishing.com/login",
                dom_extracted_header="Signed in as jnocode"
            )
        self.assertIn("Host mismatch", str(ctx.exception))

    def test_disallowed_host_non_fail_closed(self):
        res = self.gate.verify(
            current_url="https://evil.com",
            dom_extracted_header="Signed in as jnocode",
            fail_closed=False
        )
        self.assertFalse(res.valid)
        self.assertFalse(res.host_valid)
        self.assertIn("Host mismatch", res.reason)

    def test_dom_identity_drift_wrong_user_fails_closed(self):
        with self.assertRaises(IdentityDriftError) as ctx:
            self.gate.verify(
                current_url="https://github.com/settings",
                dom_extracted_header="Signed in as attacker99"
            )
        self.assertIn("Identity drift", str(ctx.exception))

    def test_dom_identity_header_missing_fails_closed(self):
        with self.assertRaises(IdentityDriftError) as ctx:
            self.gate.verify(
                current_url="https://github.com/settings",
                dom_extracted_header=None
            )
        self.assertIn("DOM identity header is missing", str(ctx.exception))

    def test_host_only_anchor_without_dom_requirement(self):
        simple_anchor = IdentityAnchor(allowed_hosts=["google.com"])
        simple_gate = IdentityGate(simple_anchor)
        res = simple_gate.verify("https://google.com/search?q=test")
        self.assertTrue(res.valid)
        self.assertTrue(res.dom_valid)


if __name__ == "__main__":
    unittest.main()

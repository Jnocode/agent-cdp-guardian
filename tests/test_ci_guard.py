"""
tests/test_ci_guard.py
~~~~~~~~~~~~~~~~~~~~~~
Ensures non-browser unit tests and synthetic lab tests are NEVER skipped in CI.
If any non-browser test is marked skipped or fails closed improperly, this guard raises an assertion.
"""

import unittest
import subprocess
import sys


class TestCIGuard(unittest.TestCase):
    """Enforces zero-skip policy on pure-Python tests."""

    def test_non_browser_suites_have_no_skips(self):
        # Run test suites in a clean isolated subprocess to prevent loader pollution
        cmd = [
            sys.executable,
            "-m",
            "unittest",
            "tests.test_guardian",
            "tests.test_identity_gate",
            "tests.test_redactor",
            "tests.test_tab_manager",
            "lab.runner",
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        combined = res.stdout + res.stderr
        self.assertEqual(res.returncode, 0, f"Core suite failed:\n{combined}")
        self.assertNotIn("skipped=", combined, "Zero tests should be skipped in core suite")
        self.assertIn("OK", combined)


if __name__ == "__main__":
    unittest.main()

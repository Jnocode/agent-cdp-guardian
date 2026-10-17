"""
Unit tests for agent_cdp_guardian.redactor
"""

import unittest
from agent_cdp_guardian.redactor import SecretRedactor


class TestSecretRedactor(unittest.TestCase):

    def setUp(self):
        self.redactor = SecretRedactor()

    def test_redact_otp_sms_code(self):
        sample = "Your verification code: 829104 is valid for 5 minutes."
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("829104", redacted)
        self.assertIn("[REDACTED_OTP_CODE]", redacted)

    def test_redact_bearer_token(self):
        sample = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.abcdefg123456789"
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("abcdefg123456789", redacted)
        self.assertIn("Bearer [REDACTED_BEARER_TOKEN]", redacted)

    def test_redact_jwt_standalone(self):
        sample = "Token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG5q6adc"
        redacted = self.redactor.redact_text(sample)
        self.assertIn("[REDACTED_JWT_TOKEN]", redacted)

    def test_redact_github_and_api_tokens(self):
        ghp = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        res = self.redactor.redact_text(f"Exported key: {ghp}")
        self.assertNotIn(ghp, res)
        self.assertIn("[REDACTED_API_TOKEN]", res)

    def test_redact_cookie_header(self):
        cookie = "Cookie: session_id=abc123xyz; secure; HttpOnly"
        res = self.redactor.redact_text(cookie)
        self.assertIn("[REDACTED_COOKIE_PAYLOAD]", res)
        self.assertNotIn("session_id=abc123xyz", res)

    def test_recursive_data_structure_redaction(self):
        payload = {
            "method": "Network.requestWillBeSent",
            "request": {
                "headers": {
                    "Authorization": "Bearer 1234567890abcdefghijklmn",
                    "User-Agent": "Mozilla/5.0",
                },
                "postData": "otp=492810&user=test"
            },
            "credentials": {
                "password": "SuperSecretPassword123!",
                "api_secret": "my-secret-key"
            }
        }
        cleaned = self.redactor.redact_data(payload)
        self.assertEqual(cleaned["credentials"]["password"], "[REDACTED_SECRET_KEY_VALUE]")
        self.assertEqual(cleaned["credentials"]["api_secret"], "[REDACTED_SECRET_KEY_VALUE]")
        self.assertIn("[REDACTED_OTP_CODE]", cleaned["request"]["postData"])
        self.assertIn("[REDACTED_BEARER_TOKEN]", cleaned["request"]["headers"]["Authorization"])
        self.assertEqual(cleaned["request"]["headers"]["User-Agent"], "Mozilla/5.0")


if __name__ == "__main__":
    unittest.main()

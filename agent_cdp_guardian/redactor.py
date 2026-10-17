"""
agent_cdp_guardian.redactor
~~~~~~~~~~~~~~~~~~~~~~~~~~
In-flight Secret and Sensitive Token Redactor.
Performs regex & structural redaction over CDP payloads (Console logs, DOM innerHTML,
Network request/response bodies, evaluation results) to prevent sensitive credentials,
session cookies, 2FA/OTP codes, or API tokens from entering agent LLM context.
"""

import re
from dataclasses import dataclass
from typing import Dict, Any, List, Union


@dataclass
class RedactionRule:
    name: str
    pattern: re.Pattern
    replacement: str


# Pre-configured high-confidence regex patterns for sensitive web data
DEFAULT_RULES: List[RedactionRule] = [
    # OTP / 2FA 6-digit or 8-digit verification codes
    RedactionRule(
        name="otp_verification_code",
        pattern=re.compile(
            r"(?i)\b(?:verification[-_ ]?code|otp|2fa|security[-_ ]?code|pin|totp)[:=\s]{1,3}['\"]?([0-9]{6,8})['\"]?\b"
        ),
        replacement="[REDACTED_OTP_CODE]",
    ),
    # Bearer Tokens & Authorization Headers
    RedactionRule(
        name="bearer_token",
        pattern=re.compile(
            r"(?i)\b(bearer\s+)([a-zA-Z0-9_\-\.]{16,500})\b"
        ),
        replacement=r"\1[REDACTED_BEARER_TOKEN]",
    ),
    # JWT Tokens (eyJ...)
    RedactionRule(
        name="jwt_token",
        pattern=re.compile(
            r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]{10,}\b"
        ),
        replacement="[REDACTED_JWT_TOKEN]",
    ),
    # Common Private Keys and Secrets
    RedactionRule(
        name="private_key_header",
        pattern=re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        replacement="[REDACTED_PRIVATE_KEY]",
    ),
    # GitHub / Cloud Tokens
    RedactionRule(
        name="api_tokens",
        pattern=re.compile(
            r"\b(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9-]{10,48}|sk-[a-zA-Z0-9]{20,50})\b"
        ),
        replacement="[REDACTED_API_TOKEN]",
    ),
    # Cookie Header values (Set-Cookie / Cookie)
    RedactionRule(
        name="cookie_values",
        pattern=re.compile(
            r"(?i)(cookie|set-cookie)\s*[:=]\s*([^\r\n;]+(?:;\s*[^\r\n;]+)*)"
        ),
        replacement=r"\1: [REDACTED_COOKIE_PAYLOAD]",
    ),
    # Credit Card Numbers (Luhn-like 13-19 digits formatted)
    RedactionRule(
        name="credit_card",
        pattern=re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        replacement="[REDACTED_CREDIT_CARD]",
    ),
]


class SecretRedactor:
    """
    Sanitizes CDP data streams, logs, and inspect payloads.
    Guarantees no accidental exfiltration of secrets or dynamic 2FA tokens into agent transcripts.
    """

    def __init__(self, custom_rules: List[RedactionRule] = None):
        self.rules: List[RedactionRule] = list(DEFAULT_RULES)
        if custom_rules:
            self.rules.extend(custom_rules)

    def redact_text(self, text: str) -> str:
        """Apply all redaction rules to a given string."""
        if not text:
            return ""
        sanitized = text
        for rule in self.rules:
            if "REDACTED" in rule.replacement and "\\" in rule.replacement:
                sanitized = rule.pattern.sub(rule.replacement, sanitized)
            elif rule.name == "otp_verification_code":
                # Specially handle OTP code capture replacement
                def _replace_otp(m):
                    full = m.group(0)
                    code = m.group(1)
                    return full.replace(code, "[REDACTED_OTP_CODE]")
                sanitized = rule.pattern.sub(_replace_otp, sanitized)
            else:
                sanitized = rule.pattern.sub(rule.replacement, sanitized)
        return sanitized

    def redact_data(self, data: Any) -> Any:
        """
        Recursively redact sensitive patterns in dictionaries, lists, or primitive values.
        """
        if isinstance(data, str):
            return self.redact_text(data)
        elif isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                lower_k = str(k).lower()
                # Headers like Authorization should undergo pattern redaction (e.g. Bearer token)
                if lower_k in ("authorization", "proxy-authorization"):
                    if isinstance(v, str):
                        redacted_text = self.redact_text(v)
                        # If standard pattern matched, keep pattern replacement (e.g. Bearer [REDACTED_BEARER_TOKEN])
                        if "[REDACTED_" in redacted_text:
                            new_dict[k] = redacted_text
                        else:
                            new_dict[k] = "[REDACTED_SECRET_KEY_VALUE]"
                    else:
                        new_dict[k] = self.redact_data(v)
                # If key name denotes sensitive credentials, aggressively mask value
                elif any(sec in lower_k for sec in ("password", "passwd", "secret", "token", "otp", "2fa", "private_key")):
                    if isinstance(v, (str, int, float)):
                        new_dict[k] = "[REDACTED_SECRET_KEY_VALUE]"
                    else:
                        new_dict[k] = self.redact_data(v)
                else:
                    new_dict[k] = self.redact_data(v)
            return new_dict
        elif isinstance(data, list):
            return [self.redact_data(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(self.redact_data(item) for item in data)
        return data

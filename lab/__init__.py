"""
Synthetic Security Regression Lab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Contains fixture templates and regression scenarios for:
  - Account drift (IdentityGate)
  - DOM node replacement/removal (TOCTOUGuard)
  - Sensitive OTP/token leakage (SecretRedactor)
"""

from .scenarios import (
    read_fixture,
    run_account_drift_positive,
    run_account_drift_negative,
    run_toctou_mutation_positive,
    run_toctou_mutation_negative_mutated,
    run_toctou_mutation_negative_removed,
    run_sensitive_otp_positive,
    run_sensitive_otp_negative,
)

__all__ = [
    "read_fixture",
    "run_account_drift_positive",
    "run_account_drift_negative",
    "run_toctou_mutation_positive",
    "run_toctou_mutation_negative_mutated",
    "run_toctou_mutation_negative_removed",
    "run_sensitive_otp_positive",
    "run_sensitive_otp_negative",
]

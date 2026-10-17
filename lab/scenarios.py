"""
Synthetic Security Regression Lab - Scenarios Definition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Defines reusable test scenarios for three primary invariant categories:
  1. Account Drift (Identity invariant)
  2. DOM Node Replacement / Removal (TOCTOU invariant)
  3. Sensitive OTP / Token Exposure (Redaction invariant)

Each scenario supports both:
  - Synthetic snapshot mode (pure Python, zero browser requirement)
  - Real browser CDP mode (extracts DOM via Runtime.evaluate over CDP WebSocket)
"""

import os
from typing import Dict, Any, Callable, Optional, Tuple
from agent_cdp_guardian import (
    CDPGuardian,
    GuardianConfig,
    PageState,
    IdentityDriftError,
    TOCTOUDriftError,
)

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def read_fixture(filename: str) -> str:
    path = os.path.join(FIXTURES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Scenario 1: Account Drift
# ---------------------------------------------------------------------------

def run_account_drift_positive(
    guardian: CDPGuardian,
    url: str,
    get_state_fn: Callable[[], PageState],
    action_fn: Callable[[], Any],
) -> Any:
    """
    Positive case: Identity remains alice@example.test.
    Action must be permitted and return successfully.
    """
    initial_state = get_state_fn()
    return guardian.guard_action(
        get_current_state=get_state_fn,
        initial_state=initial_state,
        action_fn=action_fn,
        target_name="save_preferences"
    )


def run_account_drift_negative(
    guardian: CDPGuardian,
    url: str,
    get_initial_state_fn: Callable[[], PageState],
    get_drifted_state_fn: Callable[[], PageState],
    action_fn: Callable[[], Any],
) -> Tuple[bool, Optional[Exception]]:
    """
    Negative case: Identity drifts to mallory@example.test.
    Action MUST be blocked and raise IdentityDriftError.
    Returns (blocked, exception).
    """
    initial_state = get_initial_state_fn()
    try:
        guardian.guard_action(
            get_current_state=get_drifted_state_fn,
            initial_state=initial_state,
            action_fn=action_fn,
            target_name="save_preferences"
        )
        return False, None
    except IdentityDriftError as e:
        return True, e


# ---------------------------------------------------------------------------
# Scenario 2: TOCTOU DOM Mutation / Removal
# ---------------------------------------------------------------------------

def run_toctou_mutation_positive(
    guardian: CDPGuardian,
    url: str,
    get_state_fn: Callable[[], PageState],
    action_fn: Callable[[], Any],
) -> Any:
    """
    Positive case: Button remains unchanged.
    Action must be permitted.
    """
    initial_state = get_state_fn()
    return guardian.guard_action(
        get_current_state=get_state_fn,
        initial_state=initial_state,
        action_fn=action_fn,
        target_name="confirm_transfer"
    )


def run_toctou_mutation_negative_mutated(
    guardian: CDPGuardian,
    url: str,
    get_initial_state_fn: Callable[[], PageState],
    get_mutated_state_fn: Callable[[], PageState],
    action_fn: Callable[[], Any],
) -> Tuple[bool, Optional[Exception]]:
    """
    Negative case A: Target button content changed.
    Action MUST be blocked with TOCTOUDriftError.
    """
    initial_state = get_initial_state_fn()
    try:
        guardian.guard_action(
            get_current_state=get_mutated_state_fn,
            initial_state=initial_state,
            action_fn=action_fn,
            target_name="confirm_transfer"
        )
        return False, None
    except TOCTOUDriftError as e:
        return True, e


def run_toctou_mutation_negative_removed(
    guardian: CDPGuardian,
    url: str,
    get_initial_state_fn: Callable[[], PageState],
    get_removed_state_fn: Callable[[], PageState],
    action_fn: Callable[[], Any],
) -> Tuple[bool, Optional[Exception]]:
    """
    Negative case B: Target button removed from DOM before execution.
    Action MUST be blocked with TOCTOUDriftError.
    """
    initial_state = get_initial_state_fn()
    try:
        guardian.guard_action(
            get_current_state=get_removed_state_fn,
            initial_state=initial_state,
            action_fn=action_fn,
            target_name="confirm_transfer"
        )
        return False, None
    except TOCTOUDriftError as e:
        return True, e


# ---------------------------------------------------------------------------
# Scenario 3: Sensitive OTP Page Sanitization
# ---------------------------------------------------------------------------

def run_sensitive_otp_positive(guardian: CDPGuardian, public_transcript: Dict[str, Any]) -> Dict[str, Any]:
    """
    Positive case: Non-sensitive transcript passes through without modification.
    """
    return guardian.sanitize_transcript(public_transcript)


def run_sensitive_otp_negative(guardian: CDPGuardian, sensitive_transcript: Dict[str, Any]) -> Dict[str, Any]:
    """
    Negative case: Transcript containing OTP and Bearer tokens MUST be redacted.
    Returns the sanitized transcript.
    """
    return guardian.sanitize_transcript(sensitive_transcript)

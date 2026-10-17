"""
agent-cdp-guardian
~~~~~~~~~~~~~~~~~~
A fail-closed, privacy-preserving Chrome DevTools Protocol (CDP) security
SDK and isolation invariant guard for autonomous AI coding agents.
"""

from .core import CDPGuardian, GuardianConfig
from .identity_gate import IdentityGate, IdentityAnchor, IdentityCheckResult
from .redactor import SecretRedactor, RedactionRule
from .toctou import TOCTOUGuard, PageState
from .tab_manager import TabManager, TabSession
from .exceptions import (
    GuardianError,
    SecurityViolationError,
    IdentityDriftError,
    HostMismatchError,
    NavigationDisallowedError,
    UnauthorizedActionError,
    TOCTOUDriftError,
    TabLifecycleError,
    RedactionError,
)

__version__ = "0.2.0"
__all__ = [
    "CDPGuardian",
    "GuardianConfig",
    "IdentityGate",
    "IdentityAnchor",
    "IdentityCheckResult",
    "SecretRedactor",
    "RedactionRule",
    "TOCTOUGuard",
    "PageState",
    "TabManager",
    "TabSession",
    "GuardianError",
    "SecurityViolationError",
    "IdentityDriftError",
    "HostMismatchError",
    "NavigationDisallowedError",
    "UnauthorizedActionError",
    "TOCTOUDriftError",
    "TabLifecycleError",
    "RedactionError",
]

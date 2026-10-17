"""
agent_cdp_guardian.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Hierarchical exception structure for fail-closed CDP protection.
"""

class GuardianError(Exception):
    """Base exception for all agent-cdp-guardian errors."""
    pass


class SecurityViolationError(GuardianError):
    """Raised when an operation violates active security boundaries."""
    pass


class IdentityDriftError(SecurityViolationError):
    """Raised when current browser identity attributes deviate from locked anchors."""
    pass


class HostMismatchError(IdentityDriftError):
    """Raised when browser navigates to an unexpected or disallowed host domain."""
    pass


class NavigationDisallowedError(SecurityViolationError):
    """Raised when agent attempts navigation outside strict allowlist boundaries."""
    pass


class UnauthorizedActionError(SecurityViolationError):
    """Raised when an agent attempts an action that violates configured security rules."""
    pass


class TOCTOUDriftError(SecurityViolationError):
    """
    Time-of-Check to Time-of-Use drift error.
    Raised when page state/DOM checksum shifts between inspection and action execution.
    """
    pass


class TabLifecycleError(GuardianError):
    """Raised when dedicated tab allocation, isolation, or disposal fails."""
    pass


class RedactionError(GuardianError):
    """Raised when in-flight sanitization or parsing encounters unrecoverable failure."""
    pass

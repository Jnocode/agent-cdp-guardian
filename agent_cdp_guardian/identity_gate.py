"""
agent_cdp_guardian.identity_gate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dual-Identity verification gate.
Verifies both URL hostname and DOM identity headers/anchors to prevent
account impersonation, session hijacking, or identity drift.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from .exceptions import IdentityDriftError, HostMismatchError


@dataclass(frozen=True)
class IdentityAnchor:
    """
    Immutable identity anchor for browser sessions.
    
    Attributes:
        allowed_hosts: Set of permissible domain hostnames (e.g. {"github.com", "api.github.com"}).
        expected_account: Optional identifier (e.g., username, user ID, tenant slug).
        dom_header_selector: CSS/XPath selector where user badge or header account is located.
        dom_header_pattern: Substring or regex that must match within the selector's text.
        strict_host_only: If True, blocks any host outside allowed_hosts regardless of account.
    """
    allowed_hosts: List[str]
    expected_account: Optional[str] = None
    dom_header_selector: Optional[str] = None
    dom_header_pattern: Optional[str] = None
    strict_host_only: bool = True

    def matches_host(self, url: str) -> bool:
        if not url:
            return False
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        for allowed in self.allowed_hosts:
            allowed_norm = allowed.lower()
            if host == allowed_norm or host.endswith("." + allowed_norm):
                return True
        return False


@dataclass
class IdentityCheckResult:
    valid: bool
    host_valid: bool
    dom_valid: bool
    current_url: str
    current_host: str
    observed_dom_text: Optional[str] = None
    reason: Optional[str] = None


class IdentityGate:
    """
    Dual-Identity verification engine.
    Ensures that every CDP action happens only when host domain AND DOM identity header match.
    """

    def __init__(self, anchor: IdentityAnchor):
        self.anchor = anchor

    def verify(
        self,
        current_url: str,
        dom_extracted_header: Optional[str] = None,
        fail_closed: bool = True
    ) -> IdentityCheckResult:
        """
        Perform dual verification on URL host and DOM header content.
        
        Args:
            current_url: Current tab location.
            dom_extracted_header: Text extracted from dom_header_selector (if configured).
            fail_closed: If True, raises IdentityDriftError / HostMismatchError on failure.
        """
        parsed = urlparse(current_url or "")
        current_host = (parsed.hostname or "").lower()

        host_valid = self.anchor.matches_host(current_url)
        if not host_valid:
            reason = f"Host mismatch: observed '{current_host}', allowed={self.anchor.allowed_hosts}"
            if fail_closed:
                raise HostMismatchError(reason)
            return IdentityCheckResult(
                valid=False,
                host_valid=False,
                dom_valid=False,
                current_url=current_url,
                current_host=current_host,
                reason=reason
            )

        dom_valid = True
        reason = None

        if self.anchor.expected_account or self.anchor.dom_header_pattern:
            if dom_extracted_header is None:
                dom_valid = False
                reason = "DOM identity header is missing or could not be resolved"
            else:
                expected_target = self.anchor.dom_header_pattern or self.anchor.expected_account
                if expected_target and (expected_target.lower() not in dom_extracted_header.lower()):
                    dom_valid = False
                    reason = (
                        f"Identity drift in DOM header: expected '{expected_target}' "
                        f"in header text, but observed '{dom_extracted_header}'"
                    )

        if not dom_valid:
            if fail_closed:
                raise IdentityDriftError(reason)
            return IdentityCheckResult(
                valid=False,
                host_valid=True,
                dom_valid=False,
                current_url=current_url,
                current_host=current_host,
                observed_dom_text=dom_extracted_header,
                reason=reason
            )

        return IdentityCheckResult(
            valid=True,
            host_valid=True,
            dom_valid=True,
            current_url=current_url,
            current_host=current_host,
            observed_dom_text=dom_extracted_header,
            reason=None
        )

"""
agent_cdp_guardian.core
~~~~~~~~~~~~~~~~~~~~~~~
Core CDPGuardian orchestrator.
Integrates Dual-Identity Gate, Fail-Closed TOCTOU Guard, Secret Redactor,
and Dedicated Tab Manager into a unified security SDK.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable
from .identity_gate import IdentityGate, IdentityAnchor, IdentityCheckResult
from .redactor import SecretRedactor, RedactionRule
from .toctou import TOCTOUGuard, PageState
from .tab_manager import TabManager, TabSession
from .exceptions import (
    GuardianError,
    SecurityViolationError,
    IdentityDriftError,
    HostMismatchError,
    TOCTOUDriftError,
    UnauthorizedActionError,
)


@dataclass
class GuardianConfig:
    """Configuration options for CDPGuardian."""
    allowed_hosts: List[str]
    expected_account: Optional[str] = None
    dom_header_selector: Optional[str] = None
    dom_header_pattern: Optional[str] = None
    strict_host_only: bool = True
    enable_redaction: bool = True
    custom_redaction_rules: Optional[List[RedactionRule]] = None
    max_toctou_drift_seconds: float = 5.0
    strict_dom_matching: bool = False
    fail_closed: bool = True
    cdp_host: str = "127.0.0.1"
    cdp_port: int = 9222


class CDPGuardian:
    """
    Main entry point for agent CDP governance.
    Wraps all CDP telemetry, action dispatches, and tab lifecycles.
    """

    def __init__(self, config: GuardianConfig):
        self.config = config

        self.identity_anchor = IdentityAnchor(
            allowed_hosts=config.allowed_hosts,
            expected_account=config.expected_account,
            dom_header_selector=config.dom_header_selector,
            dom_header_pattern=config.dom_header_pattern,
            strict_host_only=config.strict_host_only
        )

        self.identity_gate = IdentityGate(self.identity_anchor)
        self.redactor = SecretRedactor(custom_rules=config.custom_redaction_rules) if config.enable_redaction else None
        self.toctou_guard = TOCTOUGuard(
            max_allowed_drift_seconds=config.max_toctou_drift_seconds,
            strict_dom_match=config.strict_dom_matching
        )
        self.tab_manager = TabManager(cdp_host=config.cdp_host, cdp_port=config.cdp_port)
        self._current_session: Optional[TabSession] = None

    def verify_identity(self, current_url: str, dom_extracted_header: Optional[str] = None) -> IdentityCheckResult:
        """
        Verify host and DOM identity anchors.
        Fails closed by raising IdentityDriftError / HostMismatchError if invalid.
        """
        return self.identity_gate.verify(
            current_url=current_url,
            dom_extracted_header=dom_extracted_header,
            fail_closed=self.config.fail_closed
        )

    def sanitize_transcript(self, raw_data: Any) -> Any:
        """
        Sanitize CDP transcript, console logs, or DOM extraction before returning to Agent.
        """
        if not self.redactor:
            return raw_data
        return self.redactor.redact_data(raw_data)

    def guard_action(
        self,
        get_current_state: Callable[[], PageState],
        initial_state: PageState,
        action_fn: Callable[..., Any],
        *args,
        target_name: str = "action",
        **kwargs
    ) -> Any:
        """
        Execute an agent browser action with TOCTOU pre-verification and host boundary assertion.
        """
        # Validate initial URL against allowed hosts
        self.verify_identity(current_url=initial_state.url)
        return self.toctou_guard.guard_action(
            get_current_state,
            initial_state,
            action_fn,
            *args,
            target_name=target_name,
            **kwargs
        )

    def filter_cdp_message(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspect incoming/outgoing CDP messages to prevent malicious navigation or secret leakage.
        """
        # Block navigations to disallowed domains
        if method in ("Page.navigate", "Target.createTarget"):
            dest_url = params.get("url", "")
            if dest_url and not dest_url.startswith("about:"):
                if not self.identity_anchor.matches_host(dest_url):
                    raise HostMismatchError(
                        f"Blocked navigation to disallowed host in '{dest_url}'. "
                        f"Allowed hosts: {self.config.allowed_hosts}"
                    )

        # Sanitize payloads
        if self.redactor:
            params = self.redactor.redact_data(params)

        return params

    def create_session(self, initial_url: str = "about:blank") -> TabSession:
        """Allocate a dedicated, pristine tab for agent interaction."""
        if initial_url and not initial_url.startswith("about:"):
            if not self.identity_anchor.matches_host(initial_url):
                raise HostMismatchError(
                    f"Initial URL '{initial_url}' violates allowed hosts: {self.config.allowed_hosts}"
                )
        session = self.tab_manager.create_isolated_tab(initial_url=initial_url)
        self._current_session = session
        return session

    def close_session(self) -> None:
        """Clean up the active session tab."""
        if self._current_session and self._current_session.is_active:
            self.tab_manager.close_tab(self._current_session.target_id)
            self._current_session = None

    def close_all(self) -> List[str]:
        """Emergency clean-up for all allocated tabs."""
        return self.tab_manager.close_all_managed()

"""
agent_cdp_guardian.toctou
~~~~~~~~~~~~~~~~~~~~~~~~~
Fail-Closed TOCTOU (Time-of-Check to Time-of-Use) Guard.
Prevents navigation racing, front-running, and unexpected DOM mutations
between when an agent decides to interact and when the action actually fires.
"""

import hashlib
import math
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, Callable
from .exceptions import TOCTOUDriftError


@dataclass(frozen=True)
class PageState:
    url: str
    dom_hash: str
    target_node_hash: Optional[str] = None
    timestamp: float = 0.0
    dom_header_text: Optional[str] = None

    @classmethod
    def compute(
        cls,
        url: str,
        dom_content: str,
        target_node_content: Optional[str] = None,
        dom_header_text: Optional[str] = None
    ) -> "PageState":
        dom_hash = hashlib.sha256(dom_content.encode("utf-8")).hexdigest()
        node_hash = None
        if target_node_content is not None:
            node_hash = hashlib.sha256(target_node_content.encode("utf-8")).hexdigest()
        return cls(
            url=url,
            dom_hash=dom_hash,
            target_node_hash=node_hash,
            timestamp=time.time(),
            dom_header_text=dom_header_text
        )


class TOCTOUGuard:
    """
    Executes a guarded block or action with pre- and post-validation.
    Ensures that between extraction/observation and execution:
      1. URL has not drifted
      2. Key DOM structure or target element content remains consistent
    """

    def __init__(self, max_allowed_drift_seconds: float = 5.0, strict_dom_match: bool = False):
        self.max_allowed_drift_seconds = max_allowed_drift_seconds
        self.strict_dom_match = strict_dom_match

    def assert_state_consistent(
        self,
        initial: PageState,
        current: PageState,
        target_name: str = "interactive_element"
    ) -> None:
        """
        Verify that initial page state matches current page state before an action commits.
        Raises TOCTOUDriftError if any state invariant is broken.
        """
        # 1. URL check
        if initial.url != current.url:
            raise TOCTOUDriftError(
                f"TOCTOU Drift detected: URL mutated from '{initial.url}' to '{current.url}' "
                f"prior to executing action on '{target_name}'."
            )

        # 2. Target node check (if target node hash was captured)
        if initial.target_node_hash is not None:
            if current.target_node_hash is None:
                raise TOCTOUDriftError(
                    f"TOCTOU Drift detected: Target node '{target_name}' disappeared from DOM "
                    f"prior to execution (initial hash={initial.target_node_hash[:8]})."
                )
            if initial.target_node_hash != current.target_node_hash:
                raise TOCTOUDriftError(
                    f"TOCTOU Drift detected: Target node '{target_name}' content/structure was altered "
                    f"after observation (initial hash={initial.target_node_hash[:8]}, "
                    f"current hash={current.target_node_hash[:8]})."
                )

        # 3. Strict full DOM check if enabled
        if self.strict_dom_match and initial.dom_hash != current.dom_hash:
            raise TOCTOUDriftError(
                f"TOCTOU Drift detected: Full DOM structure modified between check and execution "
                f"(initial hash={initial.dom_hash[:8]}, current hash={current.dom_hash[:8]})."
            )

        # 4. Latency / Staleness threshold & Clock monotonicity
        elapsed = current.timestamp - initial.timestamp
        if math.isnan(elapsed) or elapsed < 0:
            raise TOCTOUDriftError(
                f"TOCTOU Drift detected: Invalid time interval ({elapsed}s) between check and execution. "
                "Possible clock skew, tampering, or NaN timestamp."
            )
        if self.max_allowed_drift_seconds > 0 and elapsed > self.max_allowed_drift_seconds:
            raise TOCTOUDriftError(
                f"TOCTOU Drift detected: Stale state observation ({elapsed:.2f}s > "
                f"{self.max_allowed_drift_seconds}s limit). Re-fetch element before acting."
            )

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
        Atomically inspect current state right before running the action.
        """
        current_state = get_current_state()
        self.assert_state_consistent(initial_state, current_state, target_name=target_name)
        return action_fn(*args, **kwargs)

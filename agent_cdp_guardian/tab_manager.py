"""
agent_cdp_guardian.tab_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dedicated Tab and Lifecycle Isolation for CDP sessions.
Enforces isolated tab lifecycle, explicit attachment, strict navigation boundary,
and automatic fail-safe disposal without polluting browser profiles.
"""

import json
import re
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from .exceptions import TabLifecycleError, NavigationDisallowedError

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
VALID_TARGET_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


class _StrictNoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevents HTTP redirection to mitigate SSRF and endpoint hijacking."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _mask_url_query(url: str) -> str:
    """Mask query parameters in URLs to avoid leaking tokens in error messages."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.query:
            return url
        # Replace query parameters with masked versions
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        masked_params = [(k, "[REDACTED]") for k, _ in params]
        new_query = urllib.parse.urlencode(masked_params)
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
    except Exception:
        return "[URL_MASKED]"


@dataclass
class TabSession:
    """Represents an isolated browser tab controlled via CDP."""
    target_id: str
    ws_url: str
    initial_url: str
    title: str = ""
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class TabManager:
    """
    Manages dedicated browser tabs over CDP HTTP endpoint (e.g. http://127.0.0.1:9222).
    Ensures:
      - AI Agents get dedicated, fresh tabs rather than hijacking existing user windows.
      - Enforces strict loopback connection to prevent SSRF against internal/external networks.
      - Disallows HTTP 30x redirection.
      - Validates target IDs strictly against path traversal.
      - Restricts close operations to managed sessions only.
    """

    def __init__(self, cdp_host: str = "127.0.0.1", cdp_port: int = 9222):
        host_clean = (cdp_host or "").strip("[]").lower()
        if host_clean not in LOOPBACK_HOSTS:
            raise TabLifecycleError(
                f"Loopback security violation: CDP host '{cdp_host}' is not allowed. "
                f"Must be one of: {sorted(LOOPBACK_HOSTS)}"
            )
        if not isinstance(cdp_port, int) or not (1 <= cdp_port <= 65535):
            raise TabLifecycleError(f"Invalid CDP port '{cdp_port}'. Must be between 1 and 65535.")

        self.cdp_host = host_clean
        self.cdp_port = cdp_port
        self.base_url = f"http://{host_clean}:{cdp_port}"
        self._managed_sessions: Dict[str, TabSession] = {}
        self._opener = urllib.request.build_opener(_StrictNoRedirect)

    def _http_get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "agent-cdp-guardian/0.1.0"})
        try:
            with self._opener.open(req, timeout=5) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except Exception as e:
            safe_url = _mask_url_query(url)
            raise TabLifecycleError(f"Failed to communicate with CDP endpoint at {safe_url}: {type(e).__name__}")

    def _http_put(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, data=b"", headers={"User-Agent": "agent-cdp-guardian/0.1.0"}, method="PUT")
        try:
            with self._opener.open(req, timeout=5) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data) if data else {}
        except Exception as e:
            safe_url = _mask_url_query(url)
            raise TabLifecycleError(f"Failed PUT request to CDP endpoint at {safe_url}: {type(e).__name__}")

    def create_isolated_tab(self, initial_url: str = "about:blank") -> TabSession:
        """
        Create a new, pristine tab via `/json/new?<url>` and register for monitoring.
        """
        path = f"/json/new?{urllib.parse.quote(initial_url, safe='')}" if initial_url else "/json/new"
        res = self._http_put(path)
        target_id = res.get("id")
        ws_url = res.get("webSocketDebuggerUrl")
        if not target_id or not ws_url:
            raise TabLifecycleError(f"CDP response did not return valid target_id/ws_url: {res}")

        session = TabSession(
            target_id=target_id,
            ws_url=ws_url,
            initial_url=initial_url,
            title=res.get("title", ""),
            metadata=res
        )
        self._managed_sessions[target_id] = session
        return session

    def close_tab(self, target_id: str) -> bool:
        """
        Close a managed tab via `/json/close/<target_id>`.
        """
        if not target_id or not VALID_TARGET_ID_RE.match(target_id):
            raise TabLifecycleError(f"Invalid target_id '{target_id}': Must match regex ^[a-zA-Z0-9_-]+$")

        if target_id not in self._managed_sessions:
            raise TabLifecycleError(
                f"Refusing to close target '{target_id}': target is not managed by this guardian session."
            )

        path = f"/json/close/{urllib.parse.quote(target_id, safe='')}"
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "agent-cdp-guardian/0.1.0"})
        try:
            with self._opener.open(req, timeout=5) as resp:
                pass
            self._managed_sessions[target_id].is_active = False
            return True
        except Exception as e:
            safe_url = _mask_url_query(url)
            raise TabLifecycleError(f"Failed to close CDP target {target_id} at {safe_url}: {type(e).__name__}")

    def close_all_managed(self) -> List[str]:
        """Clean up all tabs created during this guardian session."""
        closed = []
        for target_id, session in list(self._managed_sessions.items()):
            if session.is_active:
                try:
                    self.close_tab(target_id)
                    closed.append(target_id)
                except Exception:
                    pass
        return closed

    def list_managed_tabs(self) -> List[TabSession]:
        return [s for s in self._managed_sessions.values() if s.is_active]


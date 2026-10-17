"""
agent_cdp_guardian.tab_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dedicated Tab and Lifecycle Isolation for CDP sessions.
Enforces isolated tab lifecycle, explicit attachment, strict navigation boundary,
and automatic fail-safe disposal without polluting browser profiles.
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from .exceptions import TabLifecycleError, NavigationDisallowedError


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
      - Never accesses user cookies, localStorage, or unassigned tabs.
      - Disposes tabs cleanly upon agent task completion or critical violations.
    """

    def __init__(self, cdp_host: str = "127.0.0.1", cdp_port: int = 9222):
        self.cdp_host = cdp_host
        self.cdp_port = cdp_port
        self.base_url = f"http://{cdp_host}:{cdp_port}"
        self._managed_sessions: Dict[str, TabSession] = {}

    def _http_get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "agent-cdp-guardian/0.1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except Exception as e:
            raise TabLifecycleError(f"Failed to communicate with CDP endpoint at {url}: {e}")

    def _http_put(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, data=b"", headers={"User-Agent": "agent-cdp-guardian/0.1.0"}, method="PUT")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data) if data else {}
        except Exception as e:
            raise TabLifecycleError(f"Failed PUT request to CDP endpoint at {url}: {e}")

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
        Close a tab via `/json/close/<target_id>`.
        """
        if target_id not in self._managed_sessions:
            # We can still close it if known, but log lifecycle
            pass

        path = f"/json/close/{target_id}"
        try:
            # CDP /json/close/<id> returns "Target is closing" string
            url = f"{self.base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "agent-cdp-guardian/0.1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass
            if target_id in self._managed_sessions:
                self._managed_sessions[target_id].is_active = False
            return True
        except Exception as e:
            raise TabLifecycleError(f"Failed to close CDP target {target_id}: {e}")

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

"""
Unit tests for agent_cdp_guardian.tab_manager (with mocked CDP HTTP endpoints)
"""

import unittest
from unittest.mock import patch, MagicMock
import json
from io import BytesIO
from agent_cdp_guardian.tab_manager import TabManager, TabSession
from agent_cdp_guardian.exceptions import TabLifecycleError


class TestTabManager(unittest.TestCase):

    def setUp(self):
        self.manager = TabManager(cdp_host="127.0.0.1", cdp_port=9222)

    @patch("urllib.request.urlopen")
    def test_create_isolated_tab_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "id": "tab-1234-abcd",
            "title": "New Tab",
            "url": "about:blank",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/tab-1234-abcd"
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        session = self.manager.create_isolated_tab("about:blank")
        self.assertEqual(session.target_id, "tab-1234-abcd")
        self.assertEqual(session.ws_url, "ws://127.0.0.1:9222/devtools/page/tab-1234-abcd")
        self.assertTrue(session.is_active)
        self.assertIn("tab-1234-abcd", [s.target_id for s in self.manager.list_managed_tabs()])

    @patch("urllib.request.urlopen")
    def test_close_tab_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"Target is closing"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Register a fake active session
        fake_session = TabSession(
            target_id="tab-to-close",
            ws_url="ws://127.0.0.1:9222/page/1",
            initial_url="about:blank"
        )
        self.manager._managed_sessions["tab-to-close"] = fake_session

        closed = self.manager.close_tab("tab-to-close")
        self.assertTrue(closed)
        self.assertFalse(fake_session.is_active)
        self.assertEqual(len(self.manager.list_managed_tabs()), 0)

    @patch("urllib.request.urlopen")
    def test_create_isolated_tab_failure(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Connection refused")
        with self.assertRaises(TabLifecycleError):
            self.manager.create_isolated_tab("https://github.com")


if __name__ == "__main__":
    unittest.main()

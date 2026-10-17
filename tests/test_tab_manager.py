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

    def test_create_isolated_tab_success(self):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "id": "tab-1234-abcd",
            "title": "New Tab",
            "url": "about:blank",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/tab-1234-abcd"
        }).encode("utf-8")
        mock_opener = MagicMock()
        mock_opener.open.return_value.__enter__.return_value = mock_response
        self.manager._opener = mock_opener

        session = self.manager.create_isolated_tab("about:blank")
        self.assertEqual(session.target_id, "tab-1234-abcd")
        self.assertEqual(session.ws_url, "ws://127.0.0.1:9222/devtools/page/tab-1234-abcd")
        self.assertTrue(session.is_active)
        self.assertIn("tab-1234-abcd", [s.target_id for s in self.manager.list_managed_tabs()])

    def test_close_tab_success(self):
        mock_response = MagicMock()
        mock_response.read.return_value = b"Target is closing"
        mock_opener = MagicMock()
        mock_opener.open.return_value.__enter__.return_value = mock_response
        self.manager._opener = mock_opener

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

    def test_create_isolated_tab_failure(self):
        mock_opener = MagicMock()
        mock_opener.open.side_effect = Exception("Connection refused")
        self.manager._opener = mock_opener
        with self.assertRaises(TabLifecycleError):
            self.manager.create_isolated_tab("https://github.com")

    def test_non_loopback_host_rejected(self):
        with self.assertRaises(TabLifecycleError) as ctx:
            TabManager(cdp_host="169.254.169.254", cdp_port=80)
        self.assertIn("Loopback", str(ctx.exception))

    def test_invalid_port_rejected(self):
        with self.assertRaises(TabLifecycleError) as ctx:
            TabManager(cdp_host="127.0.0.1", cdp_port=70000)
        self.assertIn("port", str(ctx.exception).lower())

    def test_invalid_target_id_rejected(self):
        with self.assertRaises(TabLifecycleError) as ctx:
            self.manager.close_tab("../version")
        self.assertIn("Invalid target_id", str(ctx.exception))

    def test_close_tab_not_managed_rejected(self):
        # Prevent unmanaged target IDs from being closed arbitrarily
        mock_opener = MagicMock()
        self.manager._opener = mock_opener
        with self.assertRaises(TabLifecycleError) as ctx:
            self.manager.close_tab("target-not-in-managed-sessions")
        self.assertIn("not managed", str(ctx.exception).lower())
        mock_opener.open.assert_not_called()

    def test_error_masks_query_parameters(self):
        mock_opener = MagicMock()
        mock_opener.open.side_effect = Exception("Internal connection failure")
        self.manager._opener = mock_opener
        with self.assertRaises(TabLifecycleError) as ctx:
            self.manager._http_get("/json/list?token=super_secret_token_123")
        err_msg = str(ctx.exception)
        self.assertNotIn("super_secret_token_123", err_msg)
        self.assertIn("token=%5BREDACTED%5D", err_msg)




if __name__ == "__main__":
    unittest.main()

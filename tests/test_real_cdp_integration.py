"""
tests/test_real_cdp_integration.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Real Chrome DevTools Protocol Integration Tests with Headless Chromium.
Tests real browser interaction, DOM extraction, isolated tab management,
and security invariant gates (IdentityDrift, TOCTOU, Redactor).

Controlled exclusively via loopback, random ephemeral port, and isolated profile.
"""

import http.server
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request

from agent_cdp_guardian import (
    CDPGuardian,
    GuardianConfig,
    PageState,
    TabManager,
    IdentityDriftError,
    TOCTOUDriftError,
    TabLifecycleError,
)
from lab.scenarios import (
    FIXTURES_DIR,
    run_account_drift_positive,
    run_account_drift_negative,
    run_toctou_mutation_positive,
    run_toctou_mutation_negative_mutated,
    run_toctou_mutation_negative_removed,
    run_sensitive_otp_positive,
    run_sensitive_otp_negative,
)
from examples.cdp_lite import CDPLiteClient


def find_browser_executable() -> str:
    """Detect available Chromium browser executable."""
    env_browser = os.environ.get("GUARDIAN_TEST_BROWSER")
    if env_browser and os.path.isfile(env_browser):
        return env_browser

    candidates = [
        # Linux / CI paths
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        # Windows standard paths
        "C:/Program Files/Google/Chrome/Application/chrome.exe",
        "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
        "C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe",
    ]

    for cand in candidates:
        # Check absolute or relative file exists
        if os.path.isfile(cand):
            return cand
        # Check PATH on Linux / POSIX
        which = shutil.which(cand)
        if which:
            return which

    return ""


def get_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    if port == 9222:  # Explicitly forbid default 9222
        return get_free_port()
    return port


class FixtureHttpServer:
    """Serves lab/fixtures over local loopback HTTP to avoid external network access."""

    def __init__(self, directory: str):
        self.directory = directory
        self.port = get_free_port()
        self.server = None
        self.thread = None

    def start(self):
        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=self.directory, **kwargs)

            def log_message(self, format, *args):
                pass

        class QuietServer(http.server.HTTPServer):
            def handle_error(self, request, client_address):
                # Suppress harmless socket connection reset warnings when browser closes keep-alive tabs
                pass

        Handler.directory = self.directory
        self.server = QuietServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None


class TestRealCDPIntegration(unittest.TestCase):
    """End-to-end integration tests using real Headless Chromium browser."""

    browser_proc = None
    browser_port = None
    temp_profile_dir = None
    http_server = None
    browser_ws_url = None

    @classmethod
    def setUpClass(cls):
        browser_exe = find_browser_executable()
        require_real_cdp = os.environ.get("GUARDIAN_REQUIRE_REAL_CDP") == "1"

        if not browser_exe:
            msg = "Real CDP tests skipped: No Chromium browser detected on system."
            if require_real_cdp:
                raise RuntimeError(f"GUARDIAN_REQUIRE_REAL_CDP=1 set but {msg}")
            raise unittest.SkipTest(msg)

        # 1. Start local loopback HTTP server for fixtures
        cls.http_server = FixtureHttpServer(FIXTURES_DIR)
        cls.http_server.start()

        # 2. Pick ephemeral loopback port for CDP (NEVER 9222)
        cls.browser_port = get_free_port()

        # 3. Dedicated clean profile dir under temp
        base_temp = os.environ.get("GUARDIAN_TEMP_DIR") or tempfile.gettempdir()
        cls.temp_profile_dir = tempfile.mkdtemp(prefix="guardian_real_cdp_", dir=base_temp)

        cmd = [
            browser_exe,
            "--headless=new",
            f"--remote-debugging-port={cls.browser_port}",
            "--remote-debugging-address=127.0.0.1",
            f"--user-data-dir={cls.temp_profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-extensions",
            "about:blank",
        ]

        try:
            cls.browser_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception as e:
            cls.tearDownClass()
            msg = f"Real CDP tests skipped: Failed to launch browser {browser_exe}: {e}"
            if require_real_cdp:
                raise RuntimeError(f"GUARDIAN_REQUIRE_REAL_CDP=1 set but {msg}")
            raise unittest.SkipTest(msg)

        # Wait for browser CDP endpoint to be ready
        ready = False
        start_t = time.time()
        while time.time() - start_t < 10.0:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cls.browser_port}/json/version", timeout=1.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    cls.browser_ws_url = data.get("webSocketDebuggerUrl")
                    if cls.browser_ws_url:
                        ready = True
                        break
            except Exception:
                time.sleep(0.3)

        if not ready:
            cls.tearDownClass()
            msg = f"Real CDP tests skipped: Browser on port {cls.browser_port} failed to report version in 10s."
            if require_real_cdp:
                raise RuntimeError(f"GUARDIAN_REQUIRE_REAL_CDP=1 set but {msg}")
            raise unittest.SkipTest(msg)

    @classmethod
    def tearDownClass(cls):
        # Gracefully terminate only our own launched browser process
        if cls.browser_proc:
            try:
                cls.browser_proc.terminate()
                cls.browser_proc.wait(timeout=5)
            except Exception:
                try:
                    cls.browser_proc.kill()
                except Exception:
                    pass
            finally:
                cls.browser_proc = None

        # Clean profile directory
        if cls.temp_profile_dir and os.path.isdir(cls.temp_profile_dir):
            shutil.rmtree(cls.temp_profile_dir, ignore_errors=True)
            cls.temp_profile_dir = None

        # Stop HTTP server
        if cls.http_server:
            cls.http_server.stop()
            cls.http_server = None

    def setUp(self):
        self.tab_manager = TabManager(cdp_host="127.0.0.1", cdp_port=self.browser_port)
        self.config = GuardianConfig(
            allowed_hosts=["127.0.0.1", "localhost"],
            expected_account="alice@example.test",
            dom_header_pattern="alice@example.test",
            enable_redaction=True,
            max_toctou_drift_seconds=3.0,
            fail_closed=True,
            cdp_host="127.0.0.1",
            cdp_port=self.browser_port,
        )
        self.guardian = CDPGuardian(self.config)

    def test_real_cdp_tab_lifecycle_isolation(self):
        """Verifies TabManager creates isolated tab and enforces managed ownership."""
        url = f"http://127.0.0.1:{self.http_server.port}/account_drift.html"
        session = self.tab_manager.create_isolated_tab(initial_url=url)
        self.assertTrue(session.is_active)
        self.assertTrue(session.target_id)
        self.assertIn(session.target_id, self.tab_manager._managed_sessions)

        # Verify closing unmanaged tab is strictly rejected
        with self.assertRaises(TabLifecycleError):
            self.tab_manager.close_tab("unmanaged_target_99999")

        # Closing managed session succeeds
        closed = self.tab_manager.close_tab(session.target_id)
        self.assertTrue(closed)
        self.assertFalse(session.is_active)

    def test_real_cdp_scenario_1_account_drift(self):
        """Tests Account Drift invariant against a live Chromium tab."""
        url = f"http://127.0.0.1:{self.http_server.port}/account_drift.html"
        session = self.tab_manager.create_isolated_tab(initial_url=url)
        client = CDPLiteClient(session.ws_url)

        try:
            # Enable DOM and wait for page render
            client.send_command("Page.enable")
            client.send_command("DOM.enable")
            time.sleep(0.5)

            def get_live_state() -> PageState:
                dom_html = client.evaluate("document.documentElement.outerHTML")
                badge_text = client.evaluate("document.getElementById('user-badge')?.textContent || ''")
                btn_html = client.evaluate("document.getElementById('save-btn')?.outerHTML || null")
                return PageState.compute(
                    url=url,
                    dom_content=dom_html,
                    target_node_content=btn_html,
                    dom_header_text=badge_text
                )

            # 1. Positive case: Consistent identity executes successfully
            action_executed = False

            def save_action():
                nonlocal action_executed
                action_executed = True
                return {"result": "success"}

            res = run_account_drift_positive(
                guardian=self.guardian,
                url=url,
                get_state_fn=get_live_state,
                action_fn=save_action
            )
            self.assertTrue(action_executed)
            self.assertEqual(res, {"result": "success"})

            # 2. Negative case: Trigger drift in DOM via JS execution
            client.evaluate("simulateAccountDrift('mallory@example.test')")
            time.sleep(0.1)

            drifted_action_executed = False

            def drifted_action():
                nonlocal drifted_action_executed
                drifted_action_executed = True

            initial_state = get_live_state()
            # Initial state now has mallory, so guard_action should fail on initial identity check or drift
            with self.assertRaises(IdentityDriftError):
                self.guardian.guard_action(
                    get_current_state=get_live_state,
                    initial_state=initial_state,
                    action_fn=drifted_action,
                    target_name="save_preferences"
                )
            self.assertFalse(drifted_action_executed, "Action must NOT execute when identity is drifted")
        finally:
            client.close()
            self.tab_manager.close_tab(session.target_id)

    def test_real_cdp_scenario_2_toctou_mutation(self):
        """Tests TOCTOU node mutation and removal detection on a live page."""
        url = f"http://127.0.0.1:{self.http_server.port}/toctou_mutation.html"
        session = self.tab_manager.create_isolated_tab(initial_url=url)
        client = CDPLiteClient(session.ws_url)

        try:
            client.send_command("Page.enable")
            client.send_command("DOM.enable")
            time.sleep(0.5)

            def get_live_state() -> PageState:
                dom_html = client.evaluate("document.documentElement.outerHTML")
                badge_text = client.evaluate("document.getElementById('user-badge')?.textContent || ''")
                btn_html = client.evaluate("document.getElementById('action-btn')?.outerHTML || null")
                return PageState.compute(
                    url=url,
                    dom_content=dom_html,
                    target_node_content=btn_html,
                    dom_header_text=badge_text
                )

            # 1. Positive: Target node unchanged -> action executed
            initial_state = get_live_state()
            action_executed = False

            def safe_action():
                nonlocal action_executed
                action_executed = True
                return {"status": "ok"}

            res = run_toctou_mutation_positive(
                guardian=self.guardian,
                url=url,
                get_state_fn=get_live_state,
                action_fn=safe_action
            )
            self.assertTrue(action_executed)
            self.assertEqual(res, {"status": "ok"})

            # 2. Negative A: Mutate button text in DOM right before action
            initial_before_mutation = get_live_state()
            client.evaluate("mutateTargetButton()")
            time.sleep(0.1)

            mutated_action_executed = False

            def dangerous_action():
                nonlocal mutated_action_executed
                mutated_action_executed = True

            blocked, exc = run_toctou_mutation_negative_mutated(
                guardian=self.guardian,
                url=url,
                get_initial_state_fn=lambda: initial_before_mutation,
                get_mutated_state_fn=get_live_state,
                action_fn=dangerous_action
            )
            self.assertTrue(blocked)
            self.assertFalse(mutated_action_executed)
            self.assertIsInstance(exc, TOCTOUDriftError)

            # 3. Negative B: Remove button completely from DOM
            initial_before_remove = get_live_state()
            client.evaluate("removeTargetButton()")
            time.sleep(0.1)

            removed_action_executed = False

            def removed_action():
                nonlocal removed_action_executed
                removed_action_executed = True

            blocked_rm, exc_rm = run_toctou_mutation_negative_removed(
                guardian=self.guardian,
                url=url,
                get_initial_state_fn=lambda: initial_before_remove,
                get_removed_state_fn=get_live_state,
                action_fn=removed_action
            )
            self.assertTrue(blocked_rm)
            self.assertFalse(removed_action_executed)
            self.assertIsInstance(exc_rm, TOCTOUDriftError)
        finally:
            client.close()
            self.tab_manager.close_tab(session.target_id)

    def test_real_cdp_scenario_3_otp_page_transcript_redaction(self):
        """Tests that live DOM evaluation containing OTP & Bearer token is properly sanitized."""
        url = f"http://127.0.0.1:{self.http_server.port}/sensitive_otp.html"
        session = self.tab_manager.create_isolated_tab(initial_url=url)
        client = CDPLiteClient(session.ws_url)

        try:
            client.send_command("Page.enable")
            time.sleep(0.5)

            # Extract raw text from page via CDP evaluate
            raw_otp_text = client.evaluate("document.getElementById('otp-display')?.textContent || ''")
            raw_session_text = client.evaluate("document.getElementById('session-info')?.textContent || ''")

            raw_transcript = {
                "source": "live_cdp_evaluation",
                "auth_display": raw_otp_text,
                "session_info": raw_session_text,
            }

            # Check that raw data indeed contained the secret
            self.assertIn("481920", raw_transcript["auth_display"])
            self.assertIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", raw_transcript["session_info"])

            # Sanitize transcript
            sanitized = self.guardian.sanitize_transcript(raw_transcript)

            # Verify secrets masked
            self.assertNotIn("481920", sanitized["auth_display"])
            self.assertIn("[REDACTED_OTP_CODE]", sanitized["auth_display"])
            self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", sanitized["session_info"])
            self.assertIn("[REDACTED_BEARER_TOKEN]", sanitized["session_info"])
        finally:
            client.close()
            self.tab_manager.close_tab(session.target_id)


if __name__ == "__main__":
    unittest.main()

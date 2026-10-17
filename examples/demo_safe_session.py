"""
examples/demo_safe_session.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Demonstrates fail-closed CDP security governance for autonomous AI agents.
Pure stdlib, zero dependencies, runs within seconds.

Default mode:
    python examples/demo_safe_session.py
    (Uses synthetic snapshots; zero browser requirement)

Live browser mode:
    python examples/demo_safe_session.py --real-browser
    (Spawns isolated headless Chromium on ephemeral loopback port)

Demonstrates four core security gates:
  1. Permitted Action Execution (Positive Case)
  2. Blocked Dangerous Navigation (Host Allowlist Gate)
  3. Blocked Account Drift (IdentityDrift Gate)
  4. Context Redaction of Sensitive OTP & Bearer Tokens (Transcript Redactor)
"""

import argparse
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_cdp_guardian import (
    CDPGuardian,
    GuardianConfig,
    PageState,
    TabManager,
    IdentityDriftError,
    HostMismatchError,
    NavigationDisallowedError,
    TOCTOUDriftError,
)
from examples.cdp_lite import CDPLiteClient

LAB_FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "fixtures")


def find_browser() -> str:
    env_b = os.environ.get("GUARDIAN_TEST_BROWSER")
    if env_b and os.path.isfile(env_b):
        return env_b
    candidates = [
        "C:/Program Files/Google/Chrome/Application/chrome.exe",
        "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
        "C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe",
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ]
    for c in candidates:
        if os.path.isfile(c) or shutil.which(c):
            return c
    return ""


def get_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p if p != 9222 else get_free_port()


def run_synthetic_demo() -> int:
    print("=" * 70)
    print("🛡️  agent-cdp-guardian Interactive Demo (Synthetic Snapshot Mode)")
    print("=" * 70)

    config = GuardianConfig(
        allowed_hosts=["example.test", "localhost", "127.0.0.1"],
        expected_account="alice@example.test",
        dom_header_pattern="alice@example.test",
        enable_redaction=True,
        max_toctou_drift_seconds=3.0,
        fail_closed=True,
    )
    guardian = CDPGuardian(config)

    # 1. Permitted Action Execution
    print("\n[Step 1/4] Permitted Action Execution (Consistent Identity & DOM)")
    initial_state = PageState.compute(
        url="http://example.test/settings",
        dom_content="<div id='user-badge'>alice@example.test</div><button id='save'>Save</button>",
        target_node_content="<button id='save'>Save</button>",
        dom_header_text="alice@example.test"
    )

    action_run = False

    def click_save():
        nonlocal action_run
        action_run = True
        return {"status": "SUCCESS", "action": "settings_updated"}

    result = guardian.guard_action(
        get_current_state=lambda: initial_state,
        initial_state=initial_state,
        action_fn=click_save,
        target_name="save_button"
    )
    assert action_run and result["status"] == "SUCCESS"
    print("  -> Result: PASS (Action permitted and executed successfully)")

    # 2. Block Dangerous Navigation
    print("\n[Step 2/4] Outbound Navigation Invariant Gate")
    malicious_nav = {"url": "https://malicious-phishing-site.example.com/steal"}
    try:
        guardian.filter_cdp_message("Page.navigate", malicious_nav)
        print("  -> Result: FAIL (Malicious navigation was unexpectedly permitted!)")
        return 1
    except (NavigationDisallowedError, HostMismatchError) as e:
        print(f"  -> Result: PASS (Blocked {type(e).__name__}: {e})")

    # 3. Block Account Drift
    print("\n[Step 3/4] Dual-Identity Account Drift Detection")
    drifted_state = PageState.compute(
        url="http://example.test/settings",
        dom_content="<div id='user-badge'>mallory@example.test</div><button id='save'>Save</button>",
        target_node_content="<button id='save'>Save</button>",
        dom_header_text="mallory@example.test"
    )

    drift_action_executed = False

    def dangerous_user_action():
        nonlocal drift_action_executed
        drift_action_executed = True

    try:
        guardian.guard_action(
            get_current_state=lambda: drifted_state,
            initial_state=initial_state,
            action_fn=dangerous_user_action,
            target_name="save_button"
        )
        print("  -> Result: FAIL (Account drift was NOT blocked!)")
        return 1
    except IdentityDriftError as e:
        assert not drift_action_executed
        print(f"  -> Result: PASS (Blocked IdentityDriftError: {e})")

    # 4. Transcript Sanitization (OTP + Bearer Token)
    print("\n[Step 4/4] Transcript Secret & OTP Code Sanitization")
    raw_cdp_transcript = {
        "event": "Network.responseReceived",
        "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummyPayload.syntheticSignature",
        "notification_text": "Your temporary verification code is: 481920 (valid for 5 minutes)",
        "internal_api_key": "ghp_111122223333444455556666777788889999",
    }
    sanitized = guardian.sanitize_transcript(raw_cdp_transcript)
    print(f"  -> Sanitized Output: {json.dumps(sanitized, indent=4)}")
    assert "481920" not in sanitized["notification_text"]
    assert "[REDACTED_OTP_CODE]" in sanitized["notification_text"]
    assert "[REDACTED_BEARER_TOKEN]" in sanitized["auth_header"]
    assert "[REDACTED_API_TOKEN]" in sanitized["internal_api_key"]
    print("  -> Result: PASS (All OTP codes and secrets masked before LLM context)")

    print("\n" + "=" * 70)
    print("✅ All 4 security gates PASSED successfully [Mode: Synthetic Snapshots]")
    print("=" * 70)
    return 0


def run_real_browser_demo() -> int:
    browser_exe = find_browser()
    if not browser_exe:
        print("❌ Cannot run --real-browser: No Chromium browser detected.")
        return 1

    print("=" * 70)
    print("🛡️  agent-cdp-guardian Interactive Demo (Real Browser Mode)")
    print(f"Browser: {browser_exe}")
    print("=" * 70)

    # 1. Ephemeral server for fixtures
    port_http = get_free_port()

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=LAB_FIXTURES_DIR, **kwargs)

        def log_message(self, format, *args):
            pass

    class QuietServer(http.server.HTTPServer):
        def handle_error(self, request, client_address):
            pass

    httpd = QuietServer(("127.0.0.1", port_http), QuietHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    # 2. Ephemeral browser on loopback
    cdp_port = get_free_port()
    base_temp = os.environ.get("GUARDIAN_TEMP_DIR") or tempfile.gettempdir()
    profile_dir = tempfile.mkdtemp(prefix="guardian_demo_profile_", dir=base_temp)

    browser_cmd = [
        browser_exe,
        "--headless=new",
        f"--remote-debugging-port={cdp_port}",
        "--remote-debugging-address=127.0.0.1",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-extensions",
        "about:blank",
    ]

    proc = subprocess.Popen(browser_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tab_manager = TabManager(cdp_host="127.0.0.1", cdp_port=cdp_port)

    # Wait for CDP ready
    ws_url = None
    start_t = time.time()
    while time.time() - start_t < 10.0:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json/version", timeout=1.0) as resp:
                ws_url = json.loads(resp.read().decode("utf-8")).get("webSocketDebuggerUrl")
                if ws_url:
                    break
        except Exception:
            time.sleep(0.3)

    if not ws_url:
        print("❌ Failed to connect to browser CDP endpoint.")
        proc.terminate()
        shutil.rmtree(profile_dir, ignore_errors=True)
        httpd.shutdown()
        return 1

    config = GuardianConfig(
        allowed_hosts=["127.0.0.1", "localhost"],
        expected_account="alice@example.test",
        dom_header_pattern="alice@example.test",
        enable_redaction=True,
        max_toctou_drift_seconds=3.0,
        fail_closed=True,
        cdp_host="127.0.0.1",
        cdp_port=cdp_port,
    )
    guardian = CDPGuardian(config)

    try:
        # Step 1: Open Tab and execute safe action
        print("\n[Step 1/4] Permitted Action on Live Chromium Tab")
        url = f"http://127.0.0.1:{port_http}/account_drift.html"
        session = tab_manager.create_isolated_tab(url)
        client = CDPLiteClient(session.ws_url)
        client.send_command("Page.enable")
        time.sleep(0.5)

        def get_live_state() -> PageState:
            dom = client.evaluate("document.documentElement.outerHTML")
            badge = client.evaluate("document.getElementById('user-badge')?.textContent || ''")
            btn = client.evaluate("document.getElementById('save-btn')?.outerHTML || null")
            return PageState.compute(url=url, dom_content=dom, target_node_content=btn, dom_header_text=badge)

        initial_state = get_live_state()
        action_executed = False

        def real_action():
            nonlocal action_executed
            action_executed = True
            return {"status": "SUCCESS"}

        res = guardian.guard_action(
            get_current_state=get_live_state,
            initial_state=initial_state,
            action_fn=real_action,
            target_name="save_preferences"
        )
        assert action_executed and res["status"] == "SUCCESS"
        print("  -> Result: PASS (Live tab evaluated and action executed)")

        # Step 2: Block Dangerous Navigation
        print("\n[Step 2/4] Outbound Navigation Invariant Gate")
        try:
            guardian.filter_cdp_message("Page.navigate", {"url": "https://unauthorized-destination.example.com"})
            print("  -> Result: FAIL (Malicious navigation was permitted!)")
            return 1
        except (NavigationDisallowedError, HostMismatchError) as e:
            print(f"  -> Result: PASS (Blocked {type(e).__name__}: {e})")

        # Step 3: Trigger Live DOM Account Drift
        print("\n[Step 3/4] Trigger Live Account Drift in Browser DOM")
        client.evaluate("simulateAccountDrift('mallory@example.test')")
        time.sleep(0.1)

        drift_executed = False

        def drift_action():
            nonlocal drift_executed
            drift_executed = True

        drifted_state = get_live_state()
        try:
            guardian.guard_action(
                get_current_state=get_live_state,
                initial_state=drifted_state,
                action_fn=drift_action,
                target_name="save_preferences"
            )
            print("  -> Result: FAIL (Live account drift was NOT blocked!)")
            return 1
        except IdentityDriftError as e:
            assert not drift_executed
            print(f"  -> Result: PASS (Blocked IdentityDriftError: {e})")

        client.close()
        tab_manager.close_tab(session.target_id)

        # Step 4: OTP Page Redaction from Live DOM
        print("\n[Step 4/4] Live DOM Secret & OTP Redaction")
        otp_url = f"http://127.0.0.1:{port_http}/sensitive_otp.html"
        otp_session = tab_manager.create_isolated_tab(otp_url)
        client_otp = CDPLiteClient(otp_session.ws_url)
        client_otp.send_command("Page.enable")
        time.sleep(0.5)

        raw_auth_text = client_otp.evaluate("document.getElementById('otp-display')?.textContent || ''")
        raw_bearer_text = client_otp.evaluate("document.getElementById('session-info')?.textContent || ''")

        raw_transcript = {
            "source": "live_chromium_dom",
            "auth_display": raw_auth_text,
            "session_info": raw_bearer_text,
        }
        sanitized = guardian.sanitize_transcript(raw_transcript)
        print(f"  -> Sanitized Live DOM Transcript: {json.dumps(sanitized, indent=4)}")
        assert "481920" not in sanitized["auth_display"]
        assert "[REDACTED_OTP_CODE]" in sanitized["auth_display"]
        assert "[REDACTED_BEARER_TOKEN]" in sanitized["session_info"]
        print("  -> Result: PASS (Live OTP code and Bearer token masked)")

        client_otp.close()
        tab_manager.close_tab(otp_session.target_id)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(profile_dir, ignore_errors=True)
        httpd.shutdown()

    print("\n" + "=" * 70)
    print("✅ All 4 security gates PASSED successfully [Mode: Real Headless Chromium]")
    print("=" * 70)
    return 0


def main():
    parser = argparse.ArgumentParser(description="agent-cdp-guardian Safe Session Demo")
    parser.add_argument("--real-browser", action="store_true", help="Run against real Headless Chromium")
    args = parser.parse_args()

    if args.real_browser:
        sys.exit(run_real_browser_demo())
    else:
        sys.exit(run_synthetic_demo())


if __name__ == "__main__":
    main()

<div align="center">

# 🛡️ agent-cdp-guardian

**A fail-closed, privacy-preserving Chrome DevTools Protocol (CDP) Security SDK & Invariant Guard for autonomous AI coding agents (Codex CLI, Hermes, OpenClaw).**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9--3.13-brightgreen.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](https://github.com/Jnocode/agent-cdp-guardian)
[![Test Suite](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/Jnocode/agent-cdp-guardian/actions)
[![Security Guard](https://img.shields.io/badge/architecture-fail--closed-red.svg)](https://github.com/Jnocode/agent-cdp-guardian)

</div>

---

## ⚡ The Problem: Why Unbounded CDP is Dangerous for Autonomous Agents

Autonomous coding and workflow agents (like OpenAI Codex CLI, Hermes Agent, and OpenClaw) increasingly drive local browser instances via CDP to scrape context, verify web features, and automate admin flows. 

However, direct CDP access introduces critical vulnerabilities:
1. **Identity & Session Hijacking**: An agent navigating to an unexpected domain or drifting into a different logged-in session can inadvertently modify or compromise the wrong account.
2. **Time-of-Check to Time-of-Use (TOCTOU) Front-Running**: If a target button or page structure mutates between agent inspection and click dispatch, the agent risks performing destructive or unintended actions.
3. **LLM Context Secret Exfiltration**: Sensitive credentials, 2FA SMS/OTP verification codes, session cookies, and Bearer tokens leak into agent transcript logs and external inference APIs.
4. **Tab & State Contamination**: Agents attaching directly to the user's primary browser profile risk clobbering active tabs, hijacking cookies, or leaving zombie processes behind.

**`agent-cdp-guardian`** solves this by acting as a zero-dependency, fail-closed **caller-side security SDK and invariant guard**. It enforces strict runtime gates on action execution, lifecycle management, and transcript logging without requiring a heavyweight proxy daemon.

---

## 🏗️ Architecture Overview

> **Design Note**: `agent-cdp-guardian` is an in-process Python SDK and invariant gate—**not** a network-level WebSocket proxy server. The caller provides the WebSocket / CDP transport and DOM extraction, while Guardian enforces identity invariants, TOCTOU consistency, outbound command validation, loopback tab isolation, and transcript redaction.

```
      +-------------------------------------------------------------+
      |        Autonomous AI Agent (Codex / Hermes / OpenClaw)      |
      +------------------------------+------------------------------+
                                     |
                       [Tool Action & Observables]
                                     |
                                     v
+-------------------------------------------------------------------------+
|                    AGENT-CDP-GUARDIAN (Security SDK)                    |
|                                                                         |
|  [ Dual-Identity Gate ]                [ In-Flight Secret Redactor ]    |
|   - Hostname Domain Allowlist           - 2FA / OTP Verification Mask   |
|   - DOM User Badge Validation           - Bearer Token & JWT Filter     |
|   - Pre/Post State Identity Invariant   - Transcript Sanitization       |
|                                                                         |
|  [ Fail-Closed TOCTOU Guard ]          [ Tab & Lifecycle Isolation ]   |
|   - Node Disappearance Assertion        - Strict Loopback HTTP Control  |
|   - Monotonic Timestamp Checks          - No-Redirect (_StrictNoRedirect)|
|   - Pre/Post Hash Invariant Gate        - Scoped Ephemeral Tab GC       |
+------------------------------------+------------------------------------+
                                     |
                       [Caller CDP / WebSocket Transport]
                                     |
                                     v
                     +-------------------------------+
                     |   Target Chrome / Brave CDP   |
                     |     (127.0.0.1:9222)          |
                     +-------------------------------+
```

---

## ✨ Core Pillars

### 1. 🔑 Dual-Identity Gate
Enforces dual-factor verification before and during any guarded action:
* **Host Gate**: Validates that target URLs match strictly permitted hostnames or subdomains.
* **DOM Header Gate**: Validates that dynamic in-DOM identity badges (e.g. `Signed in as user123`) match the expected agent scope in both initial observation and current execution state. If identity drifts, it **fails closed** immediately (`IdentityDriftError`).

### 2. ⏱️ Fail-Closed TOCTOU Guard
Eliminates race conditions between observation and execution:
* Computes SHA-256 hashes of DOM structure and target interactive elements.
* **Disappearance Detection**: Rejects actions if the targeted element was removed from the DOM before execution.
* **Timestamp & Latency Invariants**: Enforces monotonic time (`elapsed >= 0`), rejects `NaN` timestamps, and rejects stale observations exceeding latency thresholds (`TOCTOUDriftError`).

### 3. 🛡️ Transcript Secret & OTP Redactor
Sanitizes raw CDP transcripts, console evaluations, network payloads, and agent inspection logs before returning them to the LLM:
* Automatically masks 2FA/SMS/TOTP 6-to-8 digit codes (`[REDACTED_OTP_CODE]`).
* Strips Bearer authorization headers and raw JWTs.
* Masks sensitive credential dictionaries (`password`, `secret`, `token`, `private_key`) in transcript logs.
* **Non-Corrupting Outbound Validation**: `filter_cdp_message` performs pure destination validation without mutating legitimate outbound CDP command parameters (such as session tokens).

### 4. 🗂️ Dedicated Tab & Lifecycle Isolation
* Allocates pristine ephemeral tabs via CDP `/json/new`.
* **Hardened Loopback Enforcement**: Restricts connections strictly to `127.0.0.1`, `localhost`, and `::1`.
* **Anti-SSRF & No-Redirect**: Employs `_StrictNoRedirect` to prevent HTTP redirect hijacking.
* **Safe Target Lifecycle**: Regex-validates `target_id` against path traversal and blocks deletion of unmanaged tabs.
* **Error Sanitization**: Masks URL query parameters to ensure sensitive tokens are never leaked into error messages or agent context.

### 5. 🪶 Zero-Dependency Core
* Written strictly using Python's standard library (`urllib`, `re`, `hashlib`, `json`, `dataclasses`, `math`).
* Zero third-party supply chain vulnerabilities.
* Fast, lightweight, and embeddable into any Python agent runner.

---

## 🚀 Quick Start

### Interactive Demo (Synthetic ~0.25s / Real Browser ~2.3s)

Try the runnable demonstration script:

```bash
# Default mode: pure Python synthetic snapshots (no browser required, ~0.25s)
python examples/demo_safe_session.py

# Live browser mode: launches dedicated headless Chromium on an ephemeral port (~2.3s)
python examples/demo_safe_session.py --real-browser
```

The script demonstrates:
1. Permitted action execution on consistent DOM state
2. Interception of unauthorized outbound navigation
3. Blocking of live DOM identity drift
4. Sanitization of sensitive OTP codes and authorization tokens in transcripts

### Installation

```bash
git clone https://github.com/Jnocode/agent-cdp-guardian.git
cd agent-cdp-guardian
pip install -e .
```

### Basic Example

```python
from agent_cdp_guardian import CDPGuardian, GuardianConfig, PageState

# 1. Configure the security perimeter
config = GuardianConfig(
    allowed_hosts=["github.com"],
    expected_account="octocat",
    dom_header_selector=".header-user-status",
    dom_header_pattern="octocat",
    enable_redaction=True,
    max_toctou_drift_seconds=3.0,
    fail_closed=True,
)

guardian = CDPGuardian(config)

# 2. Allocate an isolated tab
session = guardian.create_session(initial_url="https://github.com/settings")
print(f"Allocated Isolated Tab: {session.target_id}")

# 3. Dual-Identity Check
# Ensures URL is github.com AND current DOM header displays 'octocat'
guardian.verify_identity(
    current_url="https://github.com/settings",
    dom_extracted_header="Signed in as octocat"
)

# 4. Guarded Action with TOCTOU Protection
initial_state = PageState.compute(
    url="https://github.com/settings",
    dom_content="<form>...</form>",
    target_node_content="<button id='save'>Save</button>",
    dom_header_text="Signed in as octocat"
)

def perform_click(element_id):
    print(f"Executing CDP click on #{element_id}")
    return {"status": "ok"}

# Re-inspects state immediately before dispatching execution
result = guardian.guard_action(
    get_current_state=lambda: initial_state, # In practice, fetch live state from CDP
    initial_state=initial_state,
    action_fn=perform_click,
    element_id="save"
)

# 5. Sanitize LLM Context Logs
raw_cdp_network_response = {
    "headers": {"Authorization": "Bearer abcdef1234567890abcdef"},
    "body": "User verification code is: 481920"
}
sanitized = guardian.sanitize_transcript(raw_cdp_network_response)
print(sanitized)
# Output:
# {'headers': {'Authorization': 'Bearer [REDACTED_BEARER_TOKEN]'}, 
#  'body': 'User verification code is: [REDACTED_OTP_CODE]'}

# 6. Teardown
guardian.close_session()
```

---

## 🤖 Integration with Autonomous AI Coding Agents

### Codex CLI / Hermes Agent Subagent Hook

In an autonomous agent loop (e.g. tool execution dispatcher), wrap your browser automation functions with `CDPGuardian`:

```python
from agent_cdp_guardian import CDPGuardian, GuardianConfig, HostMismatchError, TOCTOUDriftError

def agent_cdp_execute_tool(guardian: CDPGuardian, cdp_command: dict):
    # Pure validation of navigation or execution payload without mutating parameters
    safe_params = guardian.filter_cdp_message(
        method=cdp_command["method"],
        params=cdp_command.get("params", {})
    )
    
    # Dispatch to browser via caller's CDP connection
    raw_result = send_raw_cdp_command(cdp_command["method"], safe_params)
    
    # Redact before returning to agent conversation context
    return guardian.sanitize_transcript(raw_result)
```

---

## 🧪 Feature Comparison Matrix

| Security Feature | Unprotected CDP | Generic Proxy | **agent-cdp-guardian** |
| :--- | :---: | :---: | :---: |
| **Fail-Closed by Design** | ❌ No | ⚠️ Partial | ✅ **Yes (Strict Exceptions)** |
| **Dual Identity (Host + DOM)** | ❌ None | ❌ None | ✅ **Yes (SHA-256 + Substring Match)** |
| **TOCTOU Race & Drift Prevention** | ❌ None | ❌ None | ✅ **Yes (Hash & Node Pre-verification)** |
| **In-Flight 2FA/OTP Masking** | ❌ None | ⚠️ Static rules | ✅ **Yes (Dynamic Regex + Structural)** |
| **Dedicated Tab Isolation** | ❌ Shared | ⚠️ Manual | ✅ **Yes (Loopback + Strict No-Redirect)** |
| **Zero Dependencies** | ❌ N/A | ❌ Third-party pkgs | ✅ **Yes (Python stdlib only)** |

---


---

## 🚦 Verification Status

The integrity of `agent-cdp-guardian` is verified across multiple layers (total 47 automated tests = 35 core unit/invariant + 7 synthetic regression + 4 real CDP + 1 CI zero-skip guard):

| Layer | Method | Coverage / Invariants Tested | CI Status |
| :--- | :--- | :--- | :---: |
| **Unit & Invariant Suite** | `tests/test_*.py`<br>(35 tests across 5 modules) | • `test_guardian.py` (13 tests): TOCTOU hash/timestamp drift, orchestrator safe flow<br>• `test_identity_gate.py` (7 tests): Host allowlist & DOM badge gating<br>• `test_redactor.py` (6 tests): Bearer, JWT, OTP, recursive transcript masking<br>• `test_tab_manager.py` (8 tests): Port/host gating, query redaction (*using mock transport*)<br>• `test_ci_guard.py` (1 test): Subprocess regression assertion enforcing zero skips | ✅ Matrix (Python 3.9–3.13) |
| **Synthetic Regression Lab** | `lab/runner.py`<br>(7 tests) | Account drift (2), TOCTOU node mutation/removal (3), OTP masking (2) on synthetic DOM fixtures | ✅ Matrix (Python 3.9–3.13) |
| **Real CDP Integration** | `tests/test_real_cdp_integration.py`<br>(4 tests, *end-to-end integration*) | Live Headless Chromium, DOM extraction, ephemeral port allocation, lifecycle isolation | ✅ Dedicated `real-cdp` CI Job |
| **Standalone Probes** | `artifacts/.../run_repaired_probes.py` | 5 core vulnerability regression checks | ✅ Verified |

### Explicitly Unverified / Out of Scope
- **Non-Chromium Browsers**: WebKit / Firefox CDP adapters have not been tested.
- **Microsecond High-Frequency Execution**: Pre-check overhead on high-frequency scraping (> 1,000 req/sec) has not been profiled.
- **Non-Windows Desktop Tab Native Cleanup**: Beyond standard HTTP `/json/close` lifecycle commands.

## 🧪 Running Tests

`agent-cdp-guardian` provides pure-Python core invariant suites alongside live browser CDP integration tests:

### 1. Pure Python Invariants & Synthetic Lab (No Browser Required)
The core invariant unit tests and synthetic regression lab require no external setup or browser instances and complete in ~3 seconds:

```bash
# Run core unit and invariant tests (35 tests)
python -m unittest tests/test_guardian.py tests/test_identity_gate.py tests/test_redactor.py tests/test_tab_manager.py tests/test_ci_guard.py -v

# Run synthetic regression lab (7 tests)
python -m unittest lab.runner -v
```

### 2. Full Test Discovery (Includes Real Headless CDP)
Running standard `unittest discover` discovers all test modules under `tests/`, including `tests/test_real_cdp_integration.py`. When a local Chromium binary (Chrome, Chromium, Edge, or Brave) is present, it automatically launches an isolated headless Chromium instance on an ephemeral random loopback port (never default 9222) with a clean temporary profile, bringing total runtime to ~6–7 seconds:

```bash
python -m unittest discover tests -v
```

Sample output (with Chromium installed):
```text
Ran 39 tests in 6.905s

OK
```

> **Note on Environments without Chromium**:
> If no Chromium binary is detected, `test_real_cdp_integration` safely skips with `skipped=1` in the runner summary (`Ran 35 tests ... OK (skipped=1)`), while the 35 core invariant tests continue to pass. In CI environments, the dedicated `real-cdp` job sets `GUARDIAN_REQUIRE_REAL_CDP=1` to strictly enforce that real browser tests are never skipped.

---

## 📄 License

- Security policy, threat model, and vulnerability reporting: [SECURITY.md](SECURITY.md).
- Detailed release history: [CHANGELOG.md](CHANGELOG.md).
- Licensed under the [MIT License](LICENSE).

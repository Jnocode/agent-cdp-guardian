<div align="center">

# 🛡️ agent-cdp-guardian

**A fail-closed, privacy-preserving Chrome DevTools Protocol (CDP) security proxy & SDK for autonomous AI coding agents (Codex CLI, Hermes, OpenClaw).**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](https://github.com/Jnocode/agent-cdp-guardian)
[![Test Suite](https://img.shields.io/badge/tests-23%20passed-brightgreen.svg)](https://github.com/Jnocode/agent-cdp-guardian/actions)
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

**`agent-cdp-guardian`** solves this by acting as a zero-dependency, fail-closed mediation layer that enforces strict runtime gates on every CDP frame and DOM interaction.

---

## 🏗️ Architecture Overview

```
      +-------------------------------------------------------------+
      |        Autonomous AI Agent (Codex / Hermes / OpenClaw)      |
      +------------------------------+------------------------------+
                                     |
                       [CDP Invocations & Observables]
                                     |
                                     v
+-------------------------------------------------------------------------+
|                        AGENT-CDP-GUARDIAN                               |
|                                                                         |
|  [ Dual-Identity Gate ]                [ In-Flight Secret Redactor ]    |
|   - Hostname Domain Allowlist           - 2FA / OTP Verification Mask   |
|   - DOM User Badge Validation           - JWT & Bearer Token Filter     |
|   - Session Drift Interceptor           - Cookie Header Stripper        |
|                                                                         |
|  [ Fail-Closed TOCTOU Guard ]          [ Tab & Lifecycle Isolation ]   |
|   - Pre/Post State Checksum             - Dedicated Target Allocation   |
|   - Node Hash Stability Gate            - Cookie/Profile Isolation      |
|   - Staleness / Timeout Guard           - Graceful Ephemeral Teardown   |
+------------------------------------+------------------------------------+
                                     |
                     [Sanitized & Guarded CDP Pipe]
                                     |
                                     v
                     +-------------------------------+
                     |   Target Chrome / Brave CDP   |
                     |     (127.0.0.1:9222)          |
                     +-------------------------------+
```

---

## ✨ Core Pillars

### 1. 🔑 Dual-Identity Identity Gate
Enforces dual-factor verification before any CDP action commits:
* **Host Gate**: Validates that target URLs match strictly permitted hostnames or subdomains.
* **DOM Header Gate**: Validates that dynamic in-DOM identity badges (e.g. `Signed in as user123`) match the expected agent scope. If identity drifts, it **fails closed** immediately (`IdentityDriftError`).

### 2. ⏱️ Fail-Closed TOCTOU Guard
Eliminates race conditions between observation and execution:
* Computes cryptographic hashes (SHA-256) of both the DOM snapshot and the exact targeted interactive element.
* Validates state consistency immediately before executing an action.
* Rejects stale observations exceeding configured latency thresholds (`TOCTOUDriftError`).

### 3. 🛡️ In-Flight Secret & OTP Redactor
Sanitizes raw CDP streams, console evaluations, network payloads, and agent inspection logs before returning them to the LLM:
* Automatically masks 2FA/SMS/TOTP 6-to-8 digit codes (`[REDACTED_OTP_CODE]`).
* Strips Bearer authorization headers and raw JWTs.
* Masks sensitive credential dictionaries (`password`, `secret`, `token`, `private_key`).
* Completely scrubbed in-flight: sensitive values **never reach LLM token buffers**.

### 4. 🗂️ Dedicated Tab & Lifecycle Isolation
* Allocates pristine ephemeral tabs via CDP `/json/new`.
* Completely decouples from primary user tabs and avoids polluting persistent browser state.
* Automatically registers and cleans up all active targets upon task completion or violation.

### 5. 🪶 Zero-Dependency Core
* Written strictly using Python's standard library (`urllib`, `re`, `hashlib`, `json`, `dataclasses`).
* Zero third-party supply chain vulnerabilities.
* Fast, lightweight, and embeddable into any Python agent runner.

---

## 🚀 Quick Start

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
    target_node_content="<button id='save'>Save</button>"
)

def perform_click(element_id):
    print(f"Executing CDP click on #{element_id}")
    return {"status": "ok"}

# Re-inspects state atomically before triggering execution
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
    # Filter incoming navigation or execution payload
    safe_params = guardian.filter_cdp_message(
        method=cdp_command["method"],
        params=cdp_command.get("params", {})
    )
    
    # Dispatch to browser
    raw_result = send_raw_cdp_command(cdp_command["method"], safe_params)
    
    # Redact before returning to agent conversation context
    return guardian.sanitize_transcript(raw_result)
```

---

## 🧪 Feature Comparison Matrix

| Security Feature | Unprotected CDP | Generic Proxy | **agent-cdp-guardian** |
| :--- | :---: | :---: | :---: |
| **Fail-Closed by Default** | ❌ No | ⚠️ Partial | ✅ **Yes (Guaranteed)** |
| **Dual Identity (Host + DOM)** | ❌ None | ❌ None | ✅ **Yes (Cryptographic)** |
| **TOCTOU Race Prevention** | ❌ None | ❌ None | ✅ **Yes (Hash Pre-verification)** |
| **In-Flight 2FA/OTP Masking** | ❌ None | ⚠️ Static rules | ✅ **Yes (Dynamic + Structural)** |
| **Dedicated Tab Isolation** | ❌ Shared | ⚠️ Manual | ✅ **Yes (Isolated & Auto-GC)** |
| **Zero Dependencies** | ❌ N/A | ❌ Third-party pkgs | ✅ **Yes (Python stdlib only)** |

---

## 🚦 Running Tests

The test suite requires no external setup or browser instances and runs in < 200ms:

```bash
python -m unittest discover tests
```

Output:
```text
.......................
----------------------------------------------------------------------
Ran 23 tests in 0.155s

OK
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

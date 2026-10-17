# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x: (Deprecated due to cold audit findings) |

---

## Scope & Threat Model

`agent-cdp-guardian` is an in-process Python security SDK and invariant enforcement guard designed to protect autonomous AI agents (Codex CLI, Hermes Agent, OpenClaw) when automating browser workflows via the Chrome DevTools Protocol (CDP).

### What `agent-cdp-guardian` Covers
1. **Target Host Boundary Enforcement**: Fails closed if the agent attempts to navigate or evaluate commands targeting hostnames outside the explicitly permitted allowlist.
2. **Dual-Identity Account Drift Detection**: Validates both the current target URL and DOM identity badge elements (e.g. `Signed in as user123`) before and during action execution.
3. **Fail-Closed TOCTOU Verification**: Recomputes SHA-256 hashes of the target interactive element and DOM structure prior to executing an action, rejecting the action if the element mutated or disappeared, or if timestamps indicate invalid drift (e.g., stale observation, negative elapsed time, or `NaN`).
4. **Context Secret & OTP Redaction**: Dynamically strips 2FA/SMS/TOTP codes, Bearer authorization tokens, JWTs, and private keys from CDP network payloads and evaluation transcripts before they enter agent context logs.
5. **Loopback Lifecycle Tab Isolation**: Ensures ephemeral tabs are strictly created on loopback addresses (`127.0.0.1`, `localhost`, `::1`), disallows HTTP redirects (`_StrictNoRedirect`), sanitizes exception URLs to prevent token leaks, and enforces that agents can only close tabs they allocated.

---

## Explicit Non-Goals (Out of Scope)

To prevent misunderstandings about security guarantees, the following are explicitly **NOT** provided by this library:

1. **Not a Network Proxy / Daemon**: `agent-cdp-guardian` does not run a network daemon, MITM WebSocket server, or TCP proxy. It is an in-process SDK. The host agent application retains full ownership of its WebSocket connection and CDP client transport.
2. **No Hardware or Kernel Isolation**: The library does not protect against a compromised host OS, malicious root processes, or rogue local binaries tampering with memory.
3. **No Cryptographic Identity Proofs**: Identity verification relies on string matching and SHA-256 hashing of DOM and URL structures. It does not provide cryptographic non-repudiation or asymmetric signature verification.
4. **No Operating System Atomic Execution**: The library checks DOM state immediately prior to dispatching actions (`guard_action`), which drastically reduces the TOCTOU race window. However, because CDP is inherently asynchronous, browser rendering engines may theoretically mutate a node during network packet flight between the client and browser.
5. **No DOM Querying or Browser Driver**: The caller must extract the DOM strings or use an external driver/CDP client to provide `PageState`.

---

## Reporting a Vulnerability

We take the security of `agent-cdp-guardian` seriously.

If you believe you have discovered a security vulnerability, please report it responsibly:
* **Preferred Method**: Open a private advisory report via [GitHub Security Advisories](https://github.com/Jnocode/agent-cdp-guardian/security/advisories/new).
* **Alternative**: If private advisories are unavailable, please open a minimal issue on the [GitHub Issues tracker](https://github.com/Jnocode/agent-cdp-guardian/issues) marked with the `security` label, taking care not to include exploitable production secrets.

Please do not send reports to personal email inboxes. All valid reports will be acknowledged and reviewed promptly.

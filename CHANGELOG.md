# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-18

### Added
- **Synthetic Security Regression Lab (`lab/`)**:
  - Reusable test scenarios in `lab/scenarios.py` and HTML fixtures in `lab/fixtures/` covering Account Drift, TOCTOU DOM Mutation/Removal, and OTP Transcript Redaction.
  - Zero-browser synthetic runner in `lab/runner.py` verifying invariants in CI without external dependencies.
- **Real CDP Integration Test Suite (`tests/test_real_cdp_integration.py`)**:
  - Automated integration testing against real Headless Chromium instances (`chrome.exe`, `chromium`, `brave`, `edge`).
  - Spawns isolated browser processes on ephemeral loopback ports (forbidding default 9222) with isolated temporary user data directories.
  - Verifies DOM extraction, live tab allocation, ownership-restricted disposal, and active invariant enforcement.
  - Controlled via `GUARDIAN_REQUIRE_REAL_CDP=1` and `GUARDIAN_TEST_BROWSER`.
- **Minimal Standalone RFC6455 Client (`examples/cdp_lite.py`)**:
  - Standard-library-only RFC6455 WebSocket client for running live CDP commands in tests and interactive examples.
- **Interactive Safe Session Demo (`examples/demo_safe_session.py`)**:
  - Demonstrates 4 core invariant gates: permitted action, navigation host check, account drift block, and transcript secret redaction.
  - Supports both default zero-browser mode and `--real-browser` headless Chromium mode.
- **Security Policy (`SECURITY.md`)**:
  - Formally documents threat model, scope, explicit non-goals (not a proxy, no crypto identity, no atomicity guarantee), and vulnerability reporting guidelines.
- **CI Enhancements (`.github/workflows/ci.yml`)**:
  - Added dedicated `real-cdp` job executing on `ubuntu-latest` with `GUARDIAN_REQUIRE_REAL_CDP=1` and Google Chrome.
  - Added test suite guard enforcing zero unexpected skips on non-browser tests across the Python 3.9–3.13 matrix.

### Changed
- Clarified architecture positioning in `README.md` and `pyproject.toml` as an in-process caller-side security SDK and invariant guard, explicitly removing inaccurate "proxy" and "pipe" claims.
- Redacted OTP verification pattern enhanced to handle `verification code is: <digits>` structures.
- Updated version to `0.2.0`.

### Fixed
- Fixed target node disappearance bypass in `TOCTOUGuard` where missing elements were previously unhandled.
- Fixed timestamp validation in `TOCTOUGuard` to strictly reject negative elapsed time and `NaN` timestamps.
- Fixed `CDPGuardian.guard_action` identity verification call to prevent deadlocks when `expected_account` is configured.
- Fixed `TabManager` loopback enforcement, path traversal protection, and masked URL query parameters in error messages.
- Prevented corruption of outbound CDP command parameters in `filter_cdp_message`.

---

## [0.1.0] - 2026-10-18

### Added
- Initial release of `agent-cdp-guardian`.
- Dual-Identity Gate (`IdentityGate`).
- TOCTOU Invariant Guard (`TOCTOUGuard`, `PageState`).
- Sensitive Credential & OTP Redactor (`SecretRedactor`).
- Isolated Tab Manager (`TabManager`).
- Unit test suite (35 tests).

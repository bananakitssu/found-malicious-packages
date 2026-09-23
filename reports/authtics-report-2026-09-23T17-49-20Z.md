# Authtics npm Security Scan

Generated: 2026-09-23T17:49:20.532729+00:00

### Potential Administrative Control Vulnerability in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control, including restarting and shutting down the process. While these are protected by a 'dat' (likely 'data' or 'dat-token') check, the implementation relies on a simple equality check against a configuration value, which could be vulnerable if the token is leaked or predictable.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn to restart the server and process.kill to terminate it.
- `dist/devPanel.js` — Monkey-patches global window.fetch, window.WebSocket, and window.EventSource to intercept and monitor network requests, which is typical for dev-tools but invasive.

**Reviewer notes:**
- The administrative endpoints are intended for development environments, but their presence in a production-capable server framework requires caution.
- The 'dat' token authentication mechanism is simplistic and should not be relied upon as a robust security boundary.
- The use of monkey-patching in devPanel.js is standard for development tools but should be verified to ensure it does not leak sensitive data to external services.

## Omitted Results

2 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

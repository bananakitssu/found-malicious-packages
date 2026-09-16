# Authtics npm Security Scan

Generated: 2026-09-16T17:34:08.522961+00:00

### Potential Administrative API Exposure and Network Interception
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are protected by a 'dat' (data/token) check, the implementation relies on a simple equality check against a configuration value, which could be vulnerable if the 'dat' token is leaked or predictable.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn and process.kill to restart the server.
- `dist/cli.js` — Implements /__authtics_host_apis__/set-users-paused which allows modifying the 'usersPaused' state variable.
- `dist/devPanel.js` — Contains 'installNetworkInterceptor' which monkey-patches window.fetch, window.WebSocket, and window.EventSource to intercept and log network traffic.

**Reviewer notes:**
- The administrative APIs are intended for development/host management, but the authentication mechanism (a simple 'dat' string match) is weak.
- The network interception in devPanel is typical for development tools but should be carefully reviewed to ensure it does not exfiltrate sensitive data in production environments.
- The use of 'jiti' and 'esbuild' for dynamic compilation is standard for modern dev-server frameworks.

### Potential Arbitrary Code Execution via Build Scripts in @bananacool467/pt
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build/link utility that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) using child_process.execSync. While this is intended functionality for a build tool, it poses a risk if the tool is run in an untrusted environment or if the package.json is manipulated.

**Evidence:**
- `pt.js` — The build() function reads the 'prepublishOnly' or 'prepare' script from the local package.json and executes it using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of npm packages by copying files to a temporary directory and linking them. The execution of 'prepublishOnly' or 'prepare' scripts is standard for build tools, but the implementation lacks strict input validation on the script content.
- The use of 'child_process.execSync' with 'stdio: ['pipe', 'pipe', 'pipe']' is a common pattern but allows for potential command injection if the package.json is compromised.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

# Authtics npm Security Scan

Generated: 2026-09-25T17:49:49.394751+00:00

### Potential Unauthenticated Administrative API Exposure
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-284`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying on a 'dat' parameter check which may be insufficient depending on implementation.

**Evidence:**
- `dist/cli.js` — Contains POST handlers for /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown that execute process.kill(process.pid, 'SIGTERM').
- `dist/cli.js` — The 'dat' parameter check is the only form of authorization for sensitive administrative actions.
- `dist/devPanel.js` — Overrides native browser APIs (fetch, WebSocket, EventSource) to intercept and log network activity.

**Reviewer notes:**
- The administrative endpoints are clearly intended for a development environment, but they are exposed via the HTTP server. If this package is used in a production-like environment without proper firewalling or if the 'dat' configuration is leaked, it could lead to unauthorized server termination.
- The network interception in devPanel.js is typical for development tools but should be verified to ensure it does not leak sensitive data to external logs.

### Potential Arbitrary Code Execution via Build Scripts
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) via child_process.execSync. While this is a common pattern for build tools, it poses a security risk if the package is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build() function retrieves 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory. The execution of build scripts is a functional requirement for this purpose, but it inherently allows for arbitrary code execution on the host machine if the project being tested contains malicious scripts.
- The use of 'file:pack&bananacool467:pt' in devDependencies is unusual but appears to be a mechanism for the tool to reference itself during development.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

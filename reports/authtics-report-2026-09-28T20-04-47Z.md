# Authtics npm Security Scan

Generated: 2026-09-28T20:04:47.880160+00:00

### Potential Unauthenticated Administrative API and Runtime Control in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state manipulation (pause users). While these are intended for development/management, they lack robust authentication, relying on a 'dat' parameter which appears to be a simple string or array check against a configuration value.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn and process.kill to restart or terminate the server process based on a simple 'dat' parameter check.
- `dist/devPanel.js` — Injects a network interceptor into the browser's global fetch, WebSocket, and EventSource objects to monitor and log network activity.
- `dist/renderEngine.js` — Uses esbuild to dynamically compile and bundle code at runtime, including a 'patchForSsr' feature that injects a large block of mocked browser globals into the server-side environment.

**Reviewer notes:**
- The 'dat' parameter check is not a secure authentication mechanism. If this server is exposed to the public internet, an attacker could potentially discover the 'dat' value or exploit the lack of proper authorization to restart or shut down the server.
- The network interception in devPanel.js is typical for development tools but should be carefully reviewed to ensure it does not leak sensitive data (like authentication tokens) to the dev panel UI.
- The use of 'jiti' and 'esbuild' for runtime compilation is standard for modern dev-focused frameworks but increases the attack surface if user-provided code is processed.

### Potential Arbitrary Code Execution via Build Scripts
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) using child_process.execSync. While this is intended functionality for a build tool, it poses a security risk if the tool is used in an untrusted environment or if the package.json is manipulated.

**Evidence:**
- `pt.js` — The build function reads the 'prepublishOnly' or 'prepare' script from the local package.json and executes it using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of npm packages by copying files to a temporary directory. The execution of build scripts is a common pattern for such tools, but it requires caution as it runs code defined in the project being tested.
- The use of 'file:pack&bananacool467:pt' in devDependencies is unusual but appears to be a self-referential link mechanism for the tool itself.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

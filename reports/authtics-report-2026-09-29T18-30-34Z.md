# Authtics npm Security Scan

Generated: 2026-09-29T18:30:34.975731+00:00

### Potential Administrative API Exposure and Network Interception in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-305`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are protected by a 'dat' (data/token) check, the implementation relies on a simple equality check against a configuration value, which could be vulnerable if the 'dat' token is leaked or predictable.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn and process.kill to restart/terminate the server.
- `dist/cli.js` — Implements /__authtics_host_apis__/set-users-paused which allows modifying the 'usersPaused' state variable.
- `dist/devPanel.js` — Contains 'installNetworkInterceptor' which monkey-patches window.fetch, window.WebSocket, and window.EventSource to intercept and log network traffic.

**Reviewer notes:**
- The administrative APIs are intended for development/management purposes, but the authentication mechanism (a simple 'dat' string match) is weak.
- The network interception in the dev panel is typical for debugging tools but should be reviewed for potential data leakage if used in production environments.
- The use of 'jiti' and dynamic imports suggests a flexible but potentially complex runtime environment.

### Potential Arbitrary Code Execution via Build Scripts
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is intended functionality for a build tool, it poses a security risk if the package is used in an untrusted environment or if the user's own scripts are compromised.

**Evidence:**
- `pt.js` — The build() function retrieves 'prepublishOnly' or 'prepare' scripts from the user's package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory and linking them. The execution of 'prepublishOnly' or 'prepare' scripts is a common pattern in build tools, but it effectively grants the package the ability to run arbitrary code on the host machine based on the contents of the user's package.json.
- The code is not inherently malicious, but the design pattern of automatically executing build scripts from the local environment is a vector for supply chain attacks if the user's project is compromised.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

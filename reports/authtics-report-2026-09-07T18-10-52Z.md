# Authtics npm Security Scan

Generated: 2026-09-07T18:10:52.814315+00:00

### Potential Unauthenticated Administrative Access in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state manipulation (pause users). While these are intended for development/management, they lack robust authentication, relying only on a 'dat' (data) token check which may be insufficient depending on the implementation.

**Evidence:**
- `dist/cli.js` — Contains POST handlers for /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown that execute process.kill(process.pid, 'SIGTERM').
- `dist/devPanel.js` — Overrides native browser APIs (fetch, WebSocket, EventSource) to intercept and monitor network requests, which is typical for dev tools but requires careful handling.

**Reviewer notes:**
- The 'dat' token mechanism appears to be a simple shared secret or identifier. If this is exposed in the client-side code or configuration, it provides no real security for the administrative endpoints.
- The use of 'jiti' and dynamic imports for server-side rendering is standard for this type of framework, but the administrative endpoints should be restricted to local-only or authenticated access.
- The package is intended for development use, but if deployed in production without disabling these endpoints, it presents a significant security risk.

### Potential Arbitrary Code Execution via Build Lifecycle Scripts
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is intended functionality for a build tool, it poses a security risk if the package is used in an untrusted environment or if the build process is triggered unexpectedly.

**Evidence:**
- `pt.js` — The build() function retrieves 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory and linking them. The execution of lifecycle scripts is a common pattern in build tools, but it requires caution as it runs code from the project being built.
- The regex logic in __generatePackageTestName is somewhat fragile but does not appear inherently malicious.
- The package.json contains a circular dependency in devDependencies: '@bananacool467/pt': 'file:pack&bananacool467:pt', which is likely a result of the tool's own logic being applied to itself.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

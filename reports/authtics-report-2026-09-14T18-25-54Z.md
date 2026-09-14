# Authtics npm Security Scan

Generated: 2026-09-14T18:25:54.994676+00:00

### Administrative API Exposure in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying only on a 'dat' (data) token check which may be insufficient depending on the implementation.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn to restart the server process.
- `dist/cli.js` — Administrative endpoints rely on a simple 'dat' token comparison for authorization, which is a weak security mechanism for server-level control.

**Reviewer notes:**
- The package is designed as a development framework, which explains the presence of these administrative APIs.
- The 'dat' token mechanism should be reviewed to ensure it is not easily guessable or leaked in production environments.
- The use of child_process.spawn for server restarts is a common pattern in dev-servers but requires caution regarding process management.

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
- The package.json contains a circular dependency in devDependencies: '@bananacool467/pt': 'file:pack&bananacool467:pt', which is unusual but likely related to the tool's self-referential testing mechanism.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

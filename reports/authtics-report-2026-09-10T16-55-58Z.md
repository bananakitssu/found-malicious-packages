# Authtics npm Security Scan

Generated: 2026-09-10T16:55:58.610273+00:00

### Potential Unauthenticated Administrative API Exposure in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state manipulation (pause users). While these are intended for development/management, they lack robust authentication, relying only on a 'dat' (data) token check which may be insufficient depending on the implementation.

**Evidence:**
- `dist/cli.js` — The class App defines multiple POST routes under /__authtics_host_apis__/ that perform sensitive actions like process.kill(process.pid, 'SIGTERM') and spawning new processes without standard authentication middleware.
- `dist/cli.js` — The 'dat' token check is a simple equality check against a config value, which is not a secure authentication mechanism for administrative endpoints.

**Reviewer notes:**
- The package appears to be a development-focused framework. The administrative endpoints are likely intended for local development environments.
- The risk is elevated if this package is accidentally deployed to a production environment without proper firewalling or if the 'dat' token is exposed.
- The use of 'jiti' and dynamic imports is consistent with a development-oriented framework and does not appear inherently malicious.

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
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory. The execution of 'prepublishOnly' or 'prepare' scripts is a common pattern in build tools, but it effectively grants the tool the ability to run arbitrary code on the developer's machine based on the contents of their own package.json.
- The code is not inherently malicious, but the pattern of executing user-defined scripts during a build process is a common vector for supply chain attacks if the tool is used in CI/CD pipelines or on untrusted projects.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

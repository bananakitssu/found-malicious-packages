# Authtics npm Security Scan

Generated: 2026-09-12T16:05:17.487989+00:00

### Potential Unauthenticated Administrative API Access in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state manipulation (pause users). While these are intended for development/management, they lack robust authentication, relying only on a 'dat' (data) token check which may be insufficient depending on the implementation.

**Evidence:**
- `dist/cli.js` — The class App defines multiple POST routes under /__authtics_host_apis__/ that perform sensitive actions like restarting the process, shutting down, or modifying internal state, protected only by a simple 'dat' token comparison.
- `dist/cli.js` — The /__authtics_host_apis__/restart endpoint uses child_process.spawn to restart the server, which is a high-privilege operation.

**Reviewer notes:**
- The 'dat' token mechanism appears to be a simple shared secret or identifier. If this is exposed in the client-side code or configuration, it provides no real security against unauthorized access to these administrative endpoints.
- The package is intended for development use, but the lack of explicit warnings or stronger authentication for these endpoints in a production-capable framework is a concern.
- The code uses 'jiti' for dynamic loading, which is common in dev-focused tools but adds complexity to static analysis.

### Potential Arbitrary Code Execution via Build Scripts
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is intended functionality for a build tool, it poses a risk if the tool is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build function retrieves 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory and linking them. The execution of 'prepublishOnly' or 'prepare' scripts is standard for build tools, but it effectively grants the package the ability to run arbitrary code on the host machine based on the contents of the user's package.json.
- The use of 'file:pack&bananacool467:pt' in devDependencies is unusual but appears to be a mechanism for the tool to reference itself during development or testing.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

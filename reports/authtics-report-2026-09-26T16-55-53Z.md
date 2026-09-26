# Authtics npm Security Scan

Generated: 2026-09-26T16:55:53.996370+00:00

### Potential Unauthenticated Administrative API Exposure in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying on a 'dat' parameter check which may be insufficient depending on implementation.

**Evidence:**
- `dist/cli.js` — The class App defines multiple POST routes under /__authtics_host_apis__/ that perform sensitive actions like process.kill(process.pid, 'SIGTERM') for restart/shutdown, protected only by a simple 'dat' string comparison.
- `dist/cli.js` — The restart functionality uses child_process.spawn to re-execute the current process, which is a high-privilege operation.

**Reviewer notes:**
- The 'dat' parameter appears to be a simple shared secret or identifier. If this is exposed in client-side code or logs, an attacker could potentially trigger a denial-of-service by shutting down the server.
- The package is intended for development environments, but the lack of explicit warnings about exposing these endpoints in production is a concern.
- The code uses 'jiti' for dynamic loading, which is common in dev tools but requires careful handling.

### Potential Arbitrary Code Execution via Build Scripts in @bananacool467/pt
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) via child_process.execSync. While this is a common pattern for build tools, it poses a security risk if the package is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build function retrieves 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a new directory and linking them. The execution of build scripts is a functional requirement for many packages, but it is a high-privilege operation that should be noted.
- The use of 'file:pack&bananacool467:pt' in devDependencies is unusual but appears to be a self-referential mechanism for the tool's own testing/linking logic.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

# Authtics npm Security Scan

Generated: 2026-09-15T17:34:44.349070+00:00

### Insecure Administrative API Endpoints in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-284`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying on a 'dat' parameter check which may be insufficient depending on implementation.

**Evidence:**
- `dist/cli.js` — The class App defines multiple POST routes under /__authtics_host_apis__/ that perform sensitive operations like process.kill(process.pid, 'SIGTERM') for restart and shutdown, protected only by a simple 'dat' parameter check.
- `dist/cli.js` — The restart functionality uses child_process.spawn to re-execute the current process, which is a powerful capability that should be strictly guarded.

**Reviewer notes:**
- The 'dat' parameter check is a weak form of authentication. If this package is used in a production environment or exposed to the public internet, these endpoints could be exploited to cause Denial of Service (DoS) by shutting down or restarting the server.
- The package appears to be intended for development use (as suggested by 'devPanel' and 'hotReload' features), but the lack of explicit warnings or production-mode disabling of these APIs is a security concern.
- The code uses 'jiti' for dynamic loading, which is common in dev tools but adds complexity to static analysis.

### Potential Arbitrary Code Execution via Build Script Automation
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
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory. The execution of build scripts is a functional requirement for this purpose, but it inherently allows for arbitrary code execution on the host machine if the project being tested contains malicious scripts.
- The use of 'file:pack&bananacool467:pt' in devDependencies is unusual but appears to be a self-referential mechanism for the tool's own development/testing.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

# Authtics npm Security Scan

Generated: 2026-09-08T17:07:29.693244+00:00

### Potential Insecure Administrative Endpoints in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying on a 'dat' parameter check which may be insufficient depending on implementation.

**Evidence:**
- `dist/cli.js` — The server exposes POST endpoints under /__authtics_host_apis__/ that perform sensitive actions like process.kill(process.pid, 'SIGTERM') for restart and shutdown, protected only by a simple 'dat' parameter check.
- `dist/cli.js` — The restart functionality uses child_process.spawn to re-execute the current process, which is a powerful capability that should be strictly guarded.

**Reviewer notes:**
- The 'dat' parameter check is a weak form of authentication. If this package is used in a production environment without additional layers of security, these endpoints could be exploited.
- The package is clearly intended as a development framework, but the inclusion of these administrative endpoints in the core 'cli.js' logic warrants caution.
- No evidence of malicious obfuscation or hidden payloads was found; the code appears to be a functional web framework.

### Potential Arbitrary Code Execution via Build Scripts
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is intended functionality for a development tool, it poses a risk if the tool is used in an untrusted environment or if the package.json is manipulated.

**Evidence:**
- `pt.js` — The build() function reads the 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The tool is designed to facilitate local testing of npm packages by copying files to a temporary directory. The execution of 'prepublishOnly' or 'prepare' scripts is a common pattern in build tools, but it allows for arbitrary code execution on the developer's machine if the package.json is compromised or if the tool is run in a malicious project directory.
- The regex logic in __generatePackageTestName is somewhat brittle but does not appear inherently malicious.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

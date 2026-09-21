# Authtics npm Security Scan

Generated: 2026-09-21T18:32:56.378139+00:00

### Potential Insecure Administrative Endpoints in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown, and configuration modification) based on a 'dat' token validation. While intended for development/management, these endpoints pose a risk if exposed in production environments without strict access control.

**Evidence:**
- `dist/cli.js` — The class 'App' defines multiple POST routes under '/__authtics_host_apis__/' that perform sensitive actions like 'restart', 'shutdown', and 'set-users-paused' based on a 'dat' token.
- `dist/cli.js` — The 'restart' endpoint uses 'spawn' to restart the process, which is a high-privilege operation.

**Reviewer notes:**
- The 'dat' token mechanism appears to be a simple string comparison or array inclusion check. If this token is leaked or predictable, an attacker could remotely shut down or restart the server.
- The package is intended as a development framework, but the presence of these endpoints in the production-ready 'cli.js' is concerning if not explicitly disabled in production.
- No evidence of malicious intent found; the code appears to be a functional implementation of a development server with hot-reloading and management features.

### Potential Arbitrary Code Execution via Build Script Trigger
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is a common pattern for build tools, it poses a risk if the tool is used in an untrusted environment or if the package.json is manipulated.

**Evidence:**
- `pt.js` — The build function reads the 'prepublishOnly' or 'prepare' script from the local package.json and executes it using child_process.execSync, which could lead to arbitrary code execution if the package.json is malicious.

**Reviewer notes:**
- The tool is designed to facilitate local testing of npm packages by copying files to a temporary directory and linking them. The execution of build scripts is a functional requirement for many packages, but it should be noted that this tool runs these scripts automatically during the 'pt build' command.
- The regex logic in __generatePackageTestName is somewhat fragile but appears intended for path manipulation rather than malicious obfuscation.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

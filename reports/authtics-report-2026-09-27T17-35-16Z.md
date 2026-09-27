# Authtics npm Security Scan

Generated: 2026-09-27T17:35:16.352806+00:00

### Potential Unauthenticated Remote Server Control via Administrative APIs
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown, and state modification) protected only by a 'dat' token check. If this token is leaked or misconfigured, an attacker could remotely restart or shut down the server.

**Evidence:**
- `dist/cli.js` — The class App defines POST endpoints like '/__authtics_host_apis__/restart' and '/__authtics_host_apis__/shutdown' which execute process.kill(process.pid, 'SIGTERM') and spawn a new process. These are protected only by a 'dat' token check.
- `dist/cli.js` — The '/__authtics_host_apis__/set-users-paused' endpoint allows external modification of the 'usersPaused' variable, which affects application logic.

**Reviewer notes:**
- The 'dat' token mechanism appears to be a simple shared secret or identifier. If not properly secured by the user, these administrative endpoints are exposed to anyone who can guess or discover the 'dat' value.
- The use of 'child_process.spawn' for restarting the server is a common pattern in development tools but carries risks if exposed in production environments.
- The package is intended as a development/hosting framework, so these features might be intentional, but they represent a significant security risk if deployed in an untrusted environment.

### Potential Command Execution via Build Scripts in @bananacool467/pt
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the 'build' process. While this is intended functionality for a build tool, it poses a risk if the tool is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build() function reads the 'prepublishOnly' or 'prepare' scripts from the user's package.json and executes them using child_process.execSync.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory. The execution of 'prepublishOnly' or 'prepare' scripts is a common pattern in build tools, but it effectively grants the package the ability to run arbitrary code on the user's machine based on the contents of the user's own package.json.
- The code does not appear to contain obfuscated payloads or hidden network calls, but the reliance on execSync makes it a potential vector for command injection if the package.json scripts are manipulated.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

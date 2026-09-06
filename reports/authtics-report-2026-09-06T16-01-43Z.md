# Authtics npm Security Scan

Generated: 2026-09-06T16:01:43.464335+00:00

### Unauthenticated Administrative API Endpoints in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown, and state modification) based on a 'dat' configuration parameter. While intended for development/management, these endpoints lack robust authentication, relying instead on a simple string or array match against a 'dat' value provided in the request body.

**Evidence:**
- `dist/cli.js` — The class App defines multiple POST endpoints under '/__authtics_host_apis__/' (e.g., /restart, /shutdown, /set-users-paused) that execute sensitive operations based on a simple 'dat' match check.
- `dist/cli.js` — The /restart endpoint uses 'child_process.spawn' to restart the server process and 'process.kill' to terminate the current instance, which could be abused if the 'dat' value is leaked or guessed.

**Reviewer notes:**
- The 'dat' parameter appears to be a simple shared secret or identifier defined in the user's configuration. If this value is exposed or predictable, an attacker could potentially shut down or restart the server.
- The implementation of these APIs is clearly intended for internal development tooling (as suggested by the path prefix), but they are exposed on the server without standard authentication middleware.
- The use of 'eval' or similar dynamic execution is not present, but the dynamic spawning of the process is a significant control risk.

### Potential risk from arbitrary script execution and package.json modification in @bananacool467/pt
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is common for build tools, the tool also automatically modifies the user's package.json file to inject devDependencies, which could lead to unexpected state changes in the user's project.

**Evidence:**
- `pt.js` — The build function executes scripts defined in the user's package.json (prepublishOnly or prepare) using child_process.execSync, which allows arbitrary code execution.
- `pt.js` — The link function automatically writes to the user's package.json file to add devDependencies, which is a high-impact action that could be misused.

**Reviewer notes:**
- The package is designed as a local development utility, which explains the need for file system access and script execution. However, the automatic modification of package.json and execution of arbitrary scripts are high-risk behaviors that warrant caution.
- The use of 'file:pack&bananacool467:pt' in devDependencies is unusual and suggests a custom protocol or naming convention that might be fragile.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

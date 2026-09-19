# Authtics npm Security Scan

Generated: 2026-09-19T16:18:06.879832+00:00

### Potential Insecure Administrative API Endpoints in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these endpoints include a 'dat' (data/token) check, the implementation relies on a simple equality check against a configuration value, which could be vulnerable if the 'dat' value is leaked or predictable.

**Evidence:**
- `dist/cli.js` — The server exposes endpoints like '/__authtics_host_apis__/restart' and '/__authtics_host_apis__/shutdown' which use 'process.kill' and 'spawn' to manipulate the server process lifecycle.
- `dist/cli.js` — The authentication mechanism for these administrative endpoints relies on a simple 'dat' string comparison, which is a weak form of access control for sensitive operations.

**Reviewer notes:**
- The package is a web framework, and these features appear intended for development-mode server management. However, the lack of robust authentication for these administrative endpoints is a security concern if deployed in production environments.
- The 'dat' check is implemented consistently across multiple endpoints, suggesting it is the intended security model, but it does not follow standard authentication practices.

### Arbitrary script execution via build tool
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is intended functionality for a build tool, it poses a risk if the tool is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build function retrieves 'prepublishOnly' or 'prepare' scripts from the user's package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a local directory and linking them. The execution of 'prepublishOnly' or 'prepare' scripts is a common pattern in build tools, but it effectively grants the package the ability to run arbitrary code on the host machine based on the contents of the user's package.json.
- The code does not appear to contain obfuscated payloads or malicious network activity, but the execution of user-defined scripts is a significant security vector.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

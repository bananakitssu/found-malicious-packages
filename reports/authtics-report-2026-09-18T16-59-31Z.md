# Authtics npm Security Scan

Generated: 2026-09-18T16:59:31.095985+00:00

### Potential Unauthorized Administrative Access in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains administrative API endpoints that allow for server-side process control, including restarting and shutting down the server. While these are gated by a 'dat' configuration check, the implementation relies on a simple equality check against a potentially user-controlled or environment-injected configuration, which could lead to unauthorized administrative access if not properly secured by the end-user.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn to restart the server process and process.kill to terminate it.
- `dist/cli.js` — The administrative endpoints rely on a 'dat' check (config_.dat) which is used as a simple authentication token. If this configuration is not handled securely by the user, it provides a vector for unauthorized administrative actions.

**Reviewer notes:**
- The package is a web framework intended for development environments, which explains the presence of administrative APIs and HMR features.
- The use of 'jiti' and dynamic file watching is consistent with a development-focused framework.
- The administrative endpoints are clearly prefixed with '__authtics_host_apis__', suggesting they are intended for internal use, but they are exposed via the public server interface.
- The 'dat' authentication mechanism is weak and should be highlighted to users as a security risk if exposed to untrusted networks.

### Potential Arbitrary Code Execution via Build Scripts
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-77`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the 'build' process. While this is intended functionality for a build tool, it poses a risk if the tool is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build() function reads the 'prepublishOnly' or 'prepare' scripts from the user's package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory. The execution of 'prepublishOnly' or 'prepare' scripts is a common pattern in build tools, but it effectively grants the package the ability to run arbitrary code on the host machine based on the contents of the user's package.json.
- The code does not appear to contain obfuscated payloads or hidden malicious logic, but the design pattern of executing user-defined scripts during a build process requires caution.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

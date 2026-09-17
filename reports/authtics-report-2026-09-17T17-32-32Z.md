# Authtics npm Security Scan

Generated: 2026-09-17T17:32:32.089983+00:00

### Potential Unauthenticated Administrative API Exposure in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying only on a 'dat' (data) token check which may be insufficient depending on the implementation context.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn and process.kill to restart/terminate the server.
- `dist/cli.js` — Implements /__authtics_host_apis__/set-users-paused which modifies the 'usersPaused' state variable based on a simple 'dat' token check.

**Reviewer notes:**
- The 'dat' token mechanism appears to be a simple shared secret or identifier. If this is not properly secured by the user, these endpoints could be exploited to disrupt service.
- The use of 'child_process.spawn' for restarting the server is a common pattern in dev-tools but requires careful handling to avoid process leakage or privilege escalation.
- The package is intended as a development framework, which mitigates the risk, but these features should be explicitly disabled in production environments.

### Potential Arbitrary Code Execution via Lifecycle Script Trigger
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is intended functionality for a build tool, it poses a risk if the tool is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build function retrieves 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using child_process.execSync, which could lead to arbitrary code execution if the package.json is manipulated.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory and linking them. The execution of lifecycle scripts is a common pattern in build tools, but it requires caution as it runs code from the project being processed.
- The regex logic in glob-ignore.js and the file copying logic in pt.js appear to be standard utility code for this type of tool.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

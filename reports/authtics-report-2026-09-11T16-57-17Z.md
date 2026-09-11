# Authtics npm Security Scan

Generated: 2026-09-11T16:57:17.339262+00:00

### Potential Unauthenticated Administrative API Access in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying only on a 'dat' (data) token check which may be insufficient depending on the implementation.

**Evidence:**
- `dist/cli.js` — Implements /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn to restart the server process.
- `dist/cli.js` — Administrative endpoints rely on a simple 'dat' token comparison for authorization, which is a weak security mechanism for server-level control.

**Reviewer notes:**
- The package is designed as a development framework, which explains the presence of these administrative APIs.
- The 'dat' token mechanism should be reviewed to ensure it is not easily guessable or leaked in production environments.
- The use of child_process.spawn for server restarts is a common pattern in dev-servers but carries risks if exposed to the public internet.

### Potential risk from arbitrary script execution in @bananacool467/pt
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) via child_process.execSync. While this is common for build tools, the tool automatically copies files to a new directory and modifies the local package.json, which could lead to unexpected side effects or persistence of malicious scripts if the user is not careful.

**Evidence:**
- `pt.js` — The build function uses child_process.execSync to run 'prepublishOnly' or 'prepare' scripts from the user's package.json, which can execute arbitrary code.
- `pt.js` — The link function modifies the local package.json by adding or updating devDependencies, which is a sensitive operation.

**Reviewer notes:**
- The package is intended to be a local development utility for testing NPM packages. The execution of 'prepublishOnly' or 'prepare' scripts is standard behavior for many build tools, but it poses a security risk if the user runs this tool in an untrusted environment.
- The code does not appear to contain obfuscated payloads or malicious network activity, but the ability to execute arbitrary scripts and modify project configuration files warrants caution.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

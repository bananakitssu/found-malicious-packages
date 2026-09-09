# Authtics npm Security Scan

Generated: 2026-09-09T17:04:46.088333+00:00

### Potential Administrative API Exposure in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these endpoints include a 'dat' (data/token) check, the implementation relies on a simple equality check against a configuration value, which could be vulnerable if the 'dat' value is leaked or predictable.

**Evidence:**
- `dist/cli.js` — The /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown endpoints allow remote triggering of process termination and spawning, protected only by a simple 'dat' token check.
- `dist/cli.js` — The /__authtics_host_apis__/set-users-paused endpoint allows modifying internal server state based on the same 'dat' token.

**Reviewer notes:**
- The 'dat' token mechanism appears to be a custom authentication/authorization scheme. If 'dat' is not properly secured or is exposed in client-side code, these endpoints could be exploited.
- The use of 'child_process.spawn' with 'detached: true' and 'process.kill' for restarts is a common pattern in development tools but carries risks if exposed to the public internet.
- The package is intended as a development/hosting framework, so these features might be intentional, but they require careful configuration by the end user.

### Potential risk from automatic execution of build scripts in @bananacool467/pt
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is a common pattern for build tools, it poses a risk if the tool is used in an untrusted environment or if the user is unaware that these scripts will be executed automatically when running 'pt build'.

**Evidence:**
- `pt.js` — The build() function automatically executes 'prepublishOnly' or 'prepare' scripts from the local package.json using child_process.execSync without explicit user confirmation.

**Reviewer notes:**
- The package is designed to facilitate local testing of NPM packages by copying files to a temporary directory. The execution of build scripts is a functional requirement for many packages, but it should be noted that this tool runs these scripts in the context of the current user.
- The code does not appear to contain malicious obfuscation or hidden payloads; it is a straightforward utility script.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

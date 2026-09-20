# Authtics npm Security Scan

Generated: 2026-09-20T16:42:59.525014+00:00

### Insecure Administrative API Endpoints in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying on a 'dat' parameter which appears to be a simple string or array check against a configuration value.

**Evidence:**
- `dist/cli.js` — The class App exposes POST endpoints like /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which trigger process.kill(process.pid, 'SIGTERM') and process spawning, protected only by a simple 'dat' string match.
- `dist/cli.js` — The /__authtics_host_apis__/set-users-paused endpoint allows modifying internal server state without proper authentication.
- `dist/renderEngine.js` — Uses esbuild to dynamically compile and bundle code, which is standard for dev servers but requires careful handling of input.

**Reviewer notes:**
- The 'dat' parameter check is not a secure authentication mechanism. If this package is used in a production environment or exposed to the public internet, it could lead to unauthorized server restarts or state manipulation.
- The use of 'jiti' and 'esbuild' for runtime compilation is common in modern JS frameworks but increases the attack surface if user-controlled input influences the files being compiled.

### Potential Arbitrary Code Execution via Build Script Trigger
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) during the build process. While this is a common pattern for build tools, it poses a risk if the tool is used in an untrusted environment or if the user's package.json contains malicious scripts.

**Evidence:**
- `pt.js` — The build function reads the 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using child_process.execSync without sanitization.

**Reviewer notes:**
- The package is designed to facilitate local testing of npm packages by copying files to a temporary directory. The execution of build scripts is a functional requirement for this purpose, but it inherently allows for arbitrary code execution on the host machine if the package.json being processed is malicious.
- The use of 'file:pack&bananacool467:pt' in devDependencies is unusual but appears to be a self-referential mechanism for the tool's own development/testing.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

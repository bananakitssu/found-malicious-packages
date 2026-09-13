# Authtics npm Security Scan

Generated: 2026-09-13T16:53:16.189725+00:00

### Potential Unauthenticated Administrative Access in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-287`, `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state modification (pause users). While these are intended for development/management, they lack robust authentication, relying on a 'dat' parameter which appears to be a simple string or array match against a configuration value.

**Evidence:**
- `dist/cli.js` — Implements POST endpoints like /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown that execute process.kill(process.pid, 'SIGTERM') and spawn new processes without standard authentication.
- `dist/cli.js` — The 'dat' parameter check (config_.dat == req.dat) is a weak security mechanism for protecting administrative endpoints.
- `dist/renderEngine.js` — Uses esbuild to dynamically compile and bundle code, which is standard for dev frameworks but requires careful handling of user-provided input.

**Reviewer notes:**
- The package is designed as a development framework, which explains the presence of administrative endpoints. However, if deployed in a production environment without external protection, these endpoints could be exploited.
- The 'dat' parameter acts as a shared secret or token, but its implementation is trivial and not a substitute for proper authentication.
- The use of 'jiti' and 'esbuild' for runtime compilation is common in modern JS frameworks but increases the attack surface if the source files are user-controllable.

### Potential risk from arbitrary script execution and package.json modification
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `@bananacool467/pt@0.1.0-beta.5`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a build tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) via child_process.execSync. While this is common for build tools, the tool automatically copies files to a new directory and modifies the user's package.json file to add a devDependency pointing to the local copy, which could lead to unexpected side effects or persistence if used maliciously.

**Evidence:**
- `pt.js` — The build function uses child_process.execSync to run 'prepublishOnly' or 'prepare' scripts from the user's package.json, which can execute arbitrary code.
- `pt.js` — The link function modifies the user's package.json file by writing to it directly, adding a devDependency that points to the generated test folder.

**Reviewer notes:**
- The package is designed as a utility to test NPM packages locally. The behavior of running build scripts and modifying package.json is consistent with its stated purpose, but it carries inherent risks if the package.json contains malicious scripts.
- The use of execSync with stdio: 'pipe' is a standard way to capture output, but it does not prevent the execution of malicious commands if the package.json is compromised.

## Omitted Results

1 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

# Authtics Advisories — Package Scan Report

**Generated:** 2026-09-06T00:03:07Z
**Model:** `gemini-3.1-flash-lite`
**Packages analyzed:** 3
**Actionable findings:** 2

> AI-generated draft. Every advisory requires human review before publication.

---

## 1. `@bananacool467/authtics-host@0.2.6`

- **Advisory:** `AUTH-2026-00001`
- **CWE:** `CWE-287`, `CWE-306`
- **Severity:** `medium`
- **Confidence:** 0.7
- **Review:** `PENDING`

### Summary

The package contains administrative API endpoints that allow for server control (restart, shutdown) and information disclosure (CPU/memory usage, server info) without robust authentication, relying instead on a 'dat' configuration check which may be easily bypassed or misconfigured.

### Evidence

- `dist/cli.js` — The class App defines multiple POST endpoints under '/__authtics_host_apis__/' such as '/restart', '/shutdown', and '/get-cpu_memory'. These endpoints perform sensitive actions like spawning new processes or killing the current process based on a simple 'dat' check that is easily spoofed if the configuration is not strictly managed.
- `dist/cli.js` — The '/restart' endpoint uses 'child_process.spawn' with 'detached: true' and 'stdio: inherit' to restart the server, which is a powerful capability that should be protected by strong authentication.

### Reviewer Notes

- The 'dat' check is a simple equality check against a configuration value. If 'config_.dat' is not set or is easily guessable, these administrative endpoints are effectively public.
- The package appears to be a development-focused framework, which might explain the lack of robust authentication, but these endpoints are present in the production-ready 'dist' files.
- The use of 'process.kill(process.pid, 'SIGTERM')' for shutdown and restart is standard but dangerous if exposed to unauthorized users.

---

## 2. `@bananacool467/pt@0.1.0-beta.5`

- **Advisory:** `AUTH-2026-00002`
- **CWE:** `CWE-78`
- **Severity:** `medium`
- **Confidence:** 0.7
- **Review:** `PENDING`

### Summary

The package includes a 'pt.js' script that executes arbitrary commands defined in the 'prepublishOnly' or 'prepare' scripts of the user's package.json during the build process. While this is intended for local testing, it introduces a risk where malicious scripts defined in a package.json could be executed automatically when running 'pt build'.

### Evidence

- `pt.js` — The 'build' function reads 'prepublishOnly' or 'prepare' scripts from the local package.json and executes them using 'child_process.execSync' without sanitization.

### Reviewer Notes

- The package is designed to facilitate local testing of npm packages. The behavior of executing 'prepublishOnly' or 'prepare' scripts is common in build tools, but it is a security risk if the user is unaware that these scripts will run during the 'pt build' process.
- The use of 'child_process.execSync' is inherently dangerous if the input (the script content) is not controlled by the user or is sourced from an untrusted package.json.
- The package name and structure appear to be a utility tool, but the execution of arbitrary scripts warrants caution.

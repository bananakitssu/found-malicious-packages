# Authtics Advisories — Package Scan Report

**Generated:** 2026-09-06T00:14:01Z
**Model:** `gemini-3.1-flash-lite`
**Packages analyzed:** 3
**Actionable findings:** 2

> AI-generated draft. Every advisory requires human review before publication.

---

## 1. `@bananacool467/authtics-host@0.2.6`

- **Advisory:** `AUTH-2026-00001`
- **CWE:** `CWE-284`, `CWE-306`
- **Severity:** `medium`
- **Confidence:** 0.7
- **Review:** `PENDING`

### Summary

The package includes administrative API endpoints that allow for server control, including restarting and shutting down the process, protected only by a 'dat' configuration check. While intended for development/management, these endpoints pose a risk if misconfigured or exposed in production.

### Evidence

- `dist/cli.js` — The class App exposes POST endpoints like /__authtics_host_apis__/restart and /__authtics_host_apis__/shutdown which use child_process.spawn and process.kill to manipulate the server lifecycle.
- `dist/devPanel.js` — The function installNetworkInterceptor monkey-patches global fetch, WebSocket, and EventSource to monitor and log network activity, which is typical for dev tools but sensitive in nature.

### Reviewer Notes

- The 'dat' check acts as a simple shared-secret authentication mechanism. If this secret is leaked or not configured, unauthorized users could potentially trigger a server restart or shutdown.
- The package is designed as a development framework, so these features are likely intended for local development workflows. However, they should be carefully reviewed for production usage.
- No evidence of malicious exfiltration or obfuscated payloads was found; the code appears to be a legitimate, albeit powerful, development server framework.

---

## 2. `@bananacool467/pt@0.1.0-beta.5`

- **Advisory:** `AUTH-2026-00002`
- **CWE:** `CWE-78`
- **Severity:** `medium`
- **Confidence:** 0.7
- **Review:** `PENDING`

### Summary

The package includes a CLI tool that executes arbitrary scripts defined in the user's package.json (prepublishOnly/prepare) via child_process.execSync. While this is intended for build automation, it poses a risk if the package is used in an untrusted environment or if the user's package.json contains malicious scripts.

### Evidence

- `pt.js` — The build() function reads the 'prepublishOnly' or 'prepare' script from the local package.json and executes it using child_process.execSync without sanitization.

### Reviewer Notes

- The package is designed to facilitate local testing of npm packages by copying files to a temporary directory and linking them. The use of execSync is a common pattern for build tools, but it is inherently dangerous if the input package.json is not controlled by the user. The code appears to be a utility tool rather than explicitly malicious, but the execution pattern warrants caution.

# Authtics npm Security Scan

Generated: 2026-09-22T17:39:08.295371+00:00

### Potential Unauthenticated Administrative API Access in @bananacool467/authtics-host
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-306`
- **Package:** `@bananacool467/authtics-host@0.2.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements administrative API endpoints that allow for server control (restart, shutdown) and state manipulation (pause users). While these are intended for development/management, they lack robust authentication, relying only on a 'dat' (data) token check which may be insufficient depending on the implementation.

**Evidence:**
- `dist/cli.js` — The class App defines multiple POST routes under /__authtics_host_apis__/ that perform sensitive actions like process.kill(process.pid, 'SIGTERM') for restart and shutdown, protected only by a simple 'dat' token comparison.
- `dist/cli.js` — The restart functionality uses child_process.spawn to re-execute the current process, which is a powerful capability that should be strictly guarded.

**Reviewer notes:**
- The 'dat' token appears to be a configuration-based secret. If this secret is not properly managed or is exposed in client-side code, these endpoints could be exploited by unauthorized parties.
- The package is intended for development use, which mitigates the risk, but the lack of explicit authentication middleware for these administrative routes is a security concern.
- The code uses 'jiti' for dynamic loading and 'esbuild' for bundling, which is standard for modern JS frameworks but requires careful review of the generated output.

## Omitted Results

2 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

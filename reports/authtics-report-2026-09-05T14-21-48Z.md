# Authtics Advisories — Package Scan Report

**Generated:** 2026-09-05T14-21-48Z
**Model:** `gemini-3.1-flash-lite`
**Packages analyzed:** 5

> This report contains AI-generated draft analysis only. A human reviewer must verify any potential finding before publication.

---

## 1. `openid-client@6.8.8`

- **Published:** 2026-09-05T10:31:57.701Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9
- **Review:** `PENDING`

### Summary

The package openid-client@6.8.8 is a well-structured OAuth 2.0 and OpenID Connect client library. The code relies on established dependencies (oauth4webapi, jose) and provides standard authentication strategies. No evidence of malicious intent or obfuscated behavior was observed in the provided files.

### Observed Behaviors

- None reported.

### Evidence

- `build/index.js` — The library correctly delegates core OAuth/OIDC logic to the 'oauth4webapi' dependency and implements standard client authentication methods (e.g., ClientSecretPost, PrivateKeyJwt) as expected for this type of package.
- `build/passport.js` — The Passport strategy implementation follows standard patterns for integrating OIDC with Express, including proper session handling and parameter validation.

### Reviewer Notes

- The package uses 'structuredClone' and 'AbortSignal.timeout', which are modern standard APIs. Ensure the target runtime environment supports these features.
- The library includes 'skipStateCheck' and 'skipSubjectCheck' exports. While these are documented as having security implications, they are standard features in OIDC libraries for specific edge cases and are clearly marked with warnings.

---

## 2. `oauth4webapi@3.8.8`

- **Published:** 2026-09-05T10:22:40.052Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9
- **Review:** `PENDING`

### Summary

The package oauth4webapi@3.8.8 is a low-level OAuth 2.0 and OpenID Connect client library. The code appears to be a standard implementation of cryptographic operations and HTTP request handling for OAuth flows. No evidence of malicious intent, obfuscation, or unauthorized data exfiltration was observed in the provided files.

### Observed Behaviors

- None reported.

### Evidence

- `build/index.js` — The library uses standard Web Crypto APIs (crypto.subtle) for cryptographic operations and standard fetch for network requests, which is expected for this type of library.
- `build/index.js` — The library includes a 'User-Agent' header construction that identifies the package name and version, which is standard practice for API clients.
- `build/index.js` — The library provides mechanisms for developers to override the fetch implementation (customFetch) and allow insecure requests (allowInsecureRequests), which are documented as features for testing and specific runtime requirements.

### Reviewer Notes

- The library is designed to be runtime-agnostic and uses 'globalThis' to access crypto and fetch APIs. Ensure that the environment where this is deployed provides secure implementations of these globals.
- The 'allowInsecureRequests' symbol is provided for testing purposes; ensure that applications using this library do not enable this in production environments.

---

## 3. `pocketbase@0.28.1`

- **Published:** 2026-09-05T09:36:16.109Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9
- **Review:** `PENDING`

### Summary

The package pocketbase@0.28.1 is a JavaScript SDK for the PocketBase backend. The code appears to be a standard client-side library for interacting with a REST API, managing authentication state (tokens/records), and handling real-time subscriptions via EventSource. No evidence of obfuscated malicious code, unauthorized network activity, or suspicious dependency manipulation was found in the provided files.

### Observed Behaviors

- None reported.

### Evidence

- `dist/pocketbase.cjs.js` — The code implements standard authentication storage (LocalAuthStore) and API communication logic consistent with a legitimate SDK.
- `dist/pocketbase.es.js` — The implementation of RealtimeService uses standard browser EventSource APIs for real-time updates, which is expected functionality for this type of library.

### Reviewer Notes

- The SDK includes functionality to export authentication state to cookies. Ensure that users of this SDK are aware of the security implications of storing sensitive tokens in cookies (e.g., XSS risks).
- The SDK provides methods for testing S3 and email configurations. Verify that these administrative endpoints are properly protected on the server side by the PocketBase backend.

---

## 4. `workerd@1.20260905.1`

- **Published:** 2026-09-05T01:16:46.609Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9
- **Review:** `PENDING`

### Summary

The package 'workerd' is a runtime environment that uses a postinstall script to download platform-specific binary executables from the official registry. The code implements standard practices for managing native dependencies in Node.js, including platform detection, binary validation, and fallback mechanisms for different package managers.

### Observed Behaviors

- Downloads and executes binary files from the internet during installation
- Uses 'child_process.execSync' to run 'npm install' within a postinstall script

### Evidence

- `install.js` — Contains logic to detect the host platform and download the corresponding binary from the npm registry.
- `package.json` — Defines a 'postinstall' script that triggers the 'install.js' file.
- `install.js` — Uses 'child_process.execSync' to perform a secondary 'npm install' if the primary binary resolution fails.

### Reviewer Notes

- Verify that the URLs used in 'downloadDirectlyFromNPM' point exclusively to the official npm registry.
- Confirm that the binary validation logic ('validateBinaryVersion') is sufficient to prevent the execution of tampered binaries.
- The 'worker.mjs' file is extremely large (4.9MB) and appears to be a bundled TypeScript compiler or similar large dependency; verify its source and integrity.

---

## 5. `@cloudflare/workerd-linux-64@1.20260905.1`

- **Published:** 2026-09-05T01:13:27.855Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9
- **Review:** `PENDING`

### Summary

The package @cloudflare/workerd-linux-64 is a platform-specific binary distribution of the Cloudflare workerd runtime. The package structure is consistent with standard binary-only npm packages, containing a large executable in the bin directory and metadata pointing to the official Cloudflare repository.

### Observed Behaviors

- None reported.

### Evidence

- `package.json` — The package metadata correctly identifies the package as a platform-specific binary distribution for Linux x64, matching the package name and intended functionality.
- `bin/workerd` — The presence of a large binary file is expected for a runtime distribution package.

### Reviewer Notes

- The binary file 'bin/workerd' was not analyzed due to its size and the constraints of this review. A human reviewer should verify the binary's integrity against the official Cloudflare release artifacts if necessary.

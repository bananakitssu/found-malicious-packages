# Authtics Advisories — Package Scan Report

**Generated:** 2026-09-05T03-01-54Z
**Model:** `gemini-3.7-flash`
**Packages analyzed:** 5

> This report contains AI-generated draft analysis only. A human reviewer must verify any potential finding before publication.

---

## 1. `workerd@1.20260905.1`

- **Published:** 2026-09-05T01:16:46.609Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.95

### Summary

Standard npm wrapper for Cloudflare's workerd binary runtime. The postinstall script locates or fetches legitimate platform-specific companion packages from the npm registry without malicious behavior.

### Observed Behaviors

- None reported.

### Evidence

- `install.js` — Standard native binary installer fallback logic fetching platform packages from registry.npmjs.org when optionalDependencies fail to install.
- `lib/main.js` — Exports the resolved path to the platform-specific workerd executable.

### Reviewer Notes

- Verify that the publish provenance aligns with Cloudflare's official releases.

---

## 2. `@cloudflare/workerd-linux-64@1.20260905.1`

- **Published:** 2026-09-05T01:13:27.855Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9

### Summary

Platform-specific binary distribution package (@cloudflare/workerd-linux-64) containing the compiled workerd binary for Linux x64 with no suspicious lifecycle scripts or JavaScript code.

### Observed Behaviors

- None reported.

### Evidence

- `package.json` — Standard platform-specific wrapper configuration with os/cpu constraints and no pre/post-install execution scripts.

### Reviewer Notes

- The package contains a large precompiled binary (bin/workerd). Standard binary verification against official Cloudflare workerd release artifacts can be conducted if binary integrity verification is required.

---

## 3. `dd-trace@6.14.0`

- **Published:** 2026-09-04T16:39:34.929Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.95

### Summary

dd-trace@6.14.0 contains standard Datadog APM and CI Visibility libraries, framework integrations, and test optimization diagnostic/validation utilities. No malicious patterns or security issues were found.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- None.

---

## 4. `eslint@10.10.0`

- **Published:** 2026-09-04T14:34:21.799Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.95

### Summary

The inspected codebase matches standard ESLint library implementation files, including CLI handling, configuration loading, caching, and rule evaluation logic without indications of malicious code.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- Package files and structures reflect standard ESLint core repository code.
- Verify integrity against upstream official ESLint repository releases and standard npm publish signatures if verifying version continuity.

---

## 5. `@renovatebot/pep440@5.0.1`

- **Published:** 2026-09-04T13:08:25.548Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 1.0

### Summary

The package is a legitimate JavaScript implementation of Python's PEP 440 versioning and specifier specification, matching standard Renovate repository code with no suspicious behaviors.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- Confirmed absence of lifecycle install scripts.
- Code strictly implements PEP 440 parsing, comparison, and range specifier resolution without external I/O or network requests.

# Authtics Advisories — Package Scan Report

**Generated:** 2026-09-05T03-29-21Z
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

The package contains standard installation and execution logic for the Cloudflare workerd runtime wrapper. The postinstall script handles locating or downloading platform-specific native binaries from the official npm registry.

### Observed Behaviors

- None reported.

### Evidence

- `install.js` — Implements platform-specific binary resolution with standard fallback download mechanism from registry.npmjs.org for optional native dependencies.
- `lib/main.js` — Exports path resolution and metadata for the platform-specific workerd binary.

### Reviewer Notes

- Verify that the publish provenance matches expected official Cloudflare release pipelines.
- Inspect the large worker.mjs bundle if full static verification of bundled dependencies is required.

---

## 2. `@cloudflare/workerd-linux-64@1.20260905.1`

- **Published:** 2026-09-05T01:13:27.855Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.8

### Summary

The package manifest defines an architecture-specific distribution package for the Cloudflare workerd runtime without any install scripts or obvious indicators of malicious activity. The binary payload 'bin/workerd' was not analyzed.

### Observed Behaviors

- None reported.

### Evidence

- `package.json` — Manifest specifies platform ('linux') and architecture ('x64') constraints without preinstall or postinstall scripts.

### Reviewer Notes

- Verify the authenticity and integrity of the compiled binary 'bin/workerd' (153MB) against official Cloudflare workerd release builds.
- Verify that the publishing account is an authorized maintainer under the '@cloudflare' npm scope.

---

## 3. `dd-trace@6.14.0`

- **Published:** 2026-09-04T16:39:34.929Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.95

### Summary

Review of dd-trace@6.14.0 code and file inventory shows legitimate APM tracing, instrumentation plugins, and CI visibility/test optimization diagnostic tooling consistent with the Datadog tracing library. No malicious or suspicious behaviors were detected in the inspected files.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- Package contains extensive APM and test optimization logic across multiple frameworks (Jest, Vitest, Mocha, Cypress, Playwright). Verify release signatures against upstream repository tags if necessary.

---

## 4. `eslint@10.10.0`

- **Published:** 2026-09-04T14:34:21.799Z
- **Status:** `ANALYSIS_FAILED`
- **Verdict:** `insufficient_evidence`
- **Confidence:** 0

### Summary

Gemini analysis could not be completed. This is not a security finding.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- Analysis engine error: HTTP Error 429: Too Many Requests

---

## 5. `@renovatebot/pep440@5.0.1`

- **Published:** 2026-09-04T13:08:25.548Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 1.0

### Summary

The package contains a pure JavaScript implementation of PEP 440 version parsing and specifier matching with no install scripts, network activity, or suspicious code patterns.

### Observed Behaviors

- None reported.

### Evidence

- `package.json` — No preinstall, install, or postinstall lifecycle scripts are configured.
- `lib/version.js` — Standard regex-based parsing and formatting logic for PEP 440 version strings.
- `lib/operator.js` — Implements comparison and ordering logic conforming to PEP 440 without external calls or side effects.
- `lib/specifier.js` — Implements version constraint filtering and matching logic in pure JavaScript.

### Reviewer Notes

- None.

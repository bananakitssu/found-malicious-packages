# Authtics Advisories — Package Scan Report

**Generated:** 2026-09-05T06-01-48Z
**Model:** `gemini-3.7-flash`
**Packages analyzed:** 5

> This report contains AI-generated draft analysis only. A human reviewer must verify any potential finding before publication.

---

## 1. `workerd@1.20260905.1`

- **Published:** 2026-09-05T01:16:46.609Z
- **Status:** `ANALYSIS_FAILED`
- **Verdict:** `insufficient_evidence`
- **Confidence:** 0
- **Review:** `PENDING`

### Summary

Gemini analysis could not be completed. This is not a security finding.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- Analysis engine error: HTTP Error 429: Too Many Requests

---

## 2. `@cloudflare/workerd-linux-64@1.20260905.1`

- **Published:** 2026-09-05T01:13:27.855Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.8
- **Review:** `PENDING`

### Summary

The package manifest defines an architecture-specific distribution package for Linux x64 containing a compiled binary (bin/workerd). No install scripts or suspicious lifecycle hooks were found in package.json.

### Observed Behaviors

- None reported.

### Evidence

- `package.json` — Manifest defines standard metadata for @cloudflare/workerd-linux-64 with os/cpu restrictions and no lifecycle scripts.

### Reviewer Notes

- The large precompiled binary 'bin/workerd' (153.9 MB) was not inspected; verify binary integrity against upstream release artifacts if required.
- Verify that this package is published by the official Cloudflare scope maintainers.

---

## 3. `dd-trace@6.14.0`

- **Published:** 2026-09-04T16:39:34.929Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.95
- **Review:** `PENDING`

### Summary

dd-trace 6.14.0 contains standard Datadog APM tracing, instrumentation plugins, and CI visibility tooling. Inspected files show legitimate framework adapters, diagnostic tools, and test optimization validation utilities with strong safety controls.

### Observed Behaviors

- None reported.

### Evidence

- `ci/init.js` — Standard Datadog CI visibility initialization logic routing to appropriate framework worker exporters.
- `ci/diagnose.js` — Static repository diagnosis script checking configuration compatibility for supported test frameworks.
- `ci/test-optimization-validation/approval.js` — Structured execution plan and approval hashing utilities ensuring validation runs only execute approved test commands.

### Reviewer Notes

- Verified CI visibility and test optimization validation components.
- No suspicious pre/postinstall hooks, obfuscated payloads, or unauthorized external telemetry endpoints were observed in the inspected files.

---

## 4. `eslint@10.10.0`

- **Published:** 2026-09-04T14:34:21.799Z
- **Status:** `ANALYSIS_FAILED`
- **Verdict:** `insufficient_evidence`
- **Confidence:** 0
- **Review:** `PENDING`

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
- **Confidence:** 0.95
- **Review:** `PENDING`

### Summary

The package contains standard PEP 440 version parsing and comparison utilities with no network access, filesystem interaction, lifecycle scripts, or obfuscation.

### Observed Behaviors

- None reported.

### Evidence

- `package.json` — No install scripts or suspicious dependency declarations present.
- `lib/version.js` — Pure JavaScript regular expression parsing and normalization for Python PEP 440 version strings.
- `lib/operator.js` — Implements standard version comparison logic without external side effects.
- `lib/specifier.js` — Implements PEP 440 version specifier and range evaluation routines.

### Reviewer Notes

- Verify that the future timestamp on publish date (2026-09-04) matches metadata expectations or is an artifact of the input dataset.

# Authtics Advisories — Package Scan Report

**Generated:** 2026-09-05T06-26-55Z
**Model:** `gemini-3.1-flash-lite`
**Packages analyzed:** 5

> This report was reviewed and approved through the merged Authtics pull request. The original analysis was AI-generated draft analysis; publication is based on human review.

---

## 1. `workerd@1.20260905.1`

- **Published:** 2026-09-05T01:16:46.609Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9
- **Review:** `APPROVED`

### Summary

The package 'workerd' is a runtime environment that uses a post-install script to download platform-specific binary executables from the official registry. The code implements standard practices for cross-platform binary distribution in Node.js, including checksum-like version validation and handling of optional dependencies. No evidence of malicious intent or obfuscated payloads was found in the provided files.

### Observed Behaviors

- Downloads binary executables during post-install
- Uses child_process.execSync to run npm commands during installation

### Evidence

- `install.js` — Contains logic to download platform-specific binaries from the npm registry and execute them to verify version compatibility.
- `package.json` — Defines 'postinstall' script and 'optionalDependencies' to manage platform-specific binary distribution.

### Reviewer Notes

- Verify that the download URLs in install.js point exclusively to the official registry.
- Confirm that the binary validation logic (validateBinaryVersion) is sufficient to prevent execution of tampered binaries.
- The file 'worker.mjs' is extremely large and appears to be a bundled TypeScript compiler or similar tool; ensure this is expected for the package's functionality.

---

## 2. `@cloudflare/workerd-linux-64@1.20260905.1`

- **Published:** 2026-09-05T01:13:27.855Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 0.9
- **Review:** `APPROVED`

### Summary

The package @cloudflare/workerd-linux-64 is a platform-specific binary distribution of the Cloudflare workerd runtime. The package structure is consistent with standard binary-only npm packages, containing a large executable in the bin directory and metadata pointing to the official Cloudflare repository.

### Observed Behaviors

- None reported.

### Evidence

- `package.json` — The package metadata correctly identifies the package as a platform-specific binary for Linux x64, matching the package name and official repository.
- `bin/workerd` — The presence of a large binary file is expected for a runtime distribution package.

### Reviewer Notes

- The binary file 'bin/workerd' was not analyzed due to its size and the instruction to not execute code. A manual audit of the binary's integrity against official Cloudflare releases is recommended.
- Verify that the package version matches the official release tags on the Cloudflare workerd GitHub repository.

---

## 3. `dd-trace@6.14.0`

- **Published:** 2026-09-04T16:39:34.929Z
- **Status:** `ANALYSIS_FAILED`
- **Verdict:** `insufficient_evidence`
- **Confidence:** 0
- **Review:** `APPROVED`

### Summary

Gemini analysis could not be completed. This is not a security finding.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- Analysis engine error: list indices must be integers or slices, not str

---

## 4. `eslint@10.10.0`

- **Published:** 2026-09-04T14:34:21.799Z
- **Status:** `ANALYSIS_FAILED`
- **Verdict:** `insufficient_evidence`
- **Confidence:** 0
- **Review:** `APPROVED`

### Summary

Gemini analysis could not be completed. This is not a security finding.

### Observed Behaviors

- None reported.

### Evidence

- None reported.

### Reviewer Notes

- Analysis engine error: list indices must be integers or slices, not str

---

## 5. `@renovatebot/pep440@5.0.1`

- **Published:** 2026-09-04T13:08:25.548Z
- **Status:** `PENDING_REVIEW`
- **Verdict:** `no_obvious_issue`
- **Confidence:** 1
- **Review:** `APPROVED`

### Summary

The package @renovatebot/pep440@5.0.1 is a utility library for parsing and comparing Python PEP 440 version strings. The code is straightforward, lacks obfuscation, and performs standard string manipulation and comparison logic consistent with its stated purpose. No network activity, file system access, or execution of external commands was observed.

### Observed Behaviors

- None reported.

### Evidence

- `lib/version.js` — Contains the core logic for parsing PEP 440 version strings using regex and standard JavaScript array/string methods.
- `lib/operator.js` — Implements comparison logic for versions, including a port of Python's comparison rules, which is standard for this type of library.
- `package.json` — Standard configuration for a utility library with no post-install scripts or suspicious dependencies.

### Reviewer Notes

- The library uses a custom implementation of PEP 440 logic. A reviewer should verify if the regex in lib/version.js and the comparison logic in lib/operator.js correctly handle edge cases defined in the PEP 440 specification.

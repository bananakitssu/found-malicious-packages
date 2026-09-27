# Authtics PyPI Security Scan

Generated: 2026-09-27T18:28:45.106810+00:00

### Potential Arbitrary Code Execution via CWL Hint Custom Functions
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-94`
- **Package:** `assertions-mate@0.10.1`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package uses the 'exec()' function to execute user-provided custom functions within a Rego/CQL2 validation context. While the documentation and code comments acknowledge this as a security risk, it remains a potential vector for arbitrary code execution if untrusted CWL workflows are processed.

**Evidence:**
- `src/assertions_mate/cql2_validator.py` — The Cql2Validator class uses exec(custom_functions, function_map) to execute arbitrary Python code provided via CWL hints. The code includes a comment explicitly noting that this permits arbitrary code execution if untrusted workflows are loaded.

**Reviewer notes:**
- The package is designed to validate CWL workflows. The use of exec() is a deliberate design choice for extensibility but poses a significant security risk if the input CWL files are not from a trusted source.
- The package includes security-conscious practices such as using bandit for static analysis and strict typing, which mitigates some risks, but the core design of executing hint-provided code remains a high-impact feature.

### Dynamic binary download and execution in uncomment package
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-829`
- **Package:** `uncomment@3.9.0`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package functions as a wrapper that dynamically downloads and executes a binary from GitHub at runtime. While this is a common pattern for cross-platform CLI tools, it bypasses standard package integrity checks and introduces a supply chain risk where the executed code is not part of the PyPI distribution.

**Evidence:**
- `uncomment/downloader.py` — The 'ensure_binary' function fetches a binary from a GitHub release URL and saves it to the user's home directory, then 'run_uncomment' executes it using subprocess.

**Reviewer notes:**
- The package does not contain the actual logic for comment removal; it acts solely as a downloader and wrapper for a Rust-based binary.
- The use of certifi for SSL verification is a positive security practice, but the reliance on external binaries remains a significant security concern for auditing purposes.
- The binary is fetched from 'https://github.com/Goldziher/uncomment/releases/download/'. Users should verify the integrity of these releases independently.

## Omitted Results

98 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

# Authtics PyPI Security Scan

Generated: 2026-09-25T19:40:41.539297+00:00

### Runtime binary dependency fetching in PyPatchMatch
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-494`, `CWE-78`
- **Package:** `PyPatchMatch@1.0.2`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package dynamically downloads binary libraries from a remote GitHub repository at runtime, which introduces a supply chain risk if the remote repository is compromised.

**Evidence:**
- `PyPatchMatch-1.0.2/patchmatch/patch_match.py` — The code performs an unauthenticated HTTP request to GitHub API to fetch and download binary files (DLLs/shared objects) based on the user's platform, which are then loaded via ctypes.
- `PyPatchMatch-1.0.2/patchmatch/patch_match.py` — The package attempts to compile C extensions using 'make' via subprocess if the pre-compiled binaries are not found, which could lead to arbitrary code execution if the build environment is manipulated.

**Reviewer notes:**
- The package is designed to provide C-based performance for image processing. The dynamic downloading of binaries is a common pattern in some Python packages (like those wrapping C++ libraries), but it bypasses standard package integrity checks (like hashes in requirements.txt).
- The use of 'subprocess.run' with 'shell=True' to execute 'make' is a potential security risk if the environment is not controlled, though it is intended for local compilation.

### Security Analysis of galaxymidi: System Command Execution and Redundant Code
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `galaxymidi@26.9.25`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains multiple modules that execute system-level commands (apt-get, tar, pigz) and include potentially dangerous patterns like subprocess.run with shell-like behavior or external dependencies. While these appear to be intended for dataset management, they pose risks if paths are not properly sanitized.

**Evidence:**
- `galaxymidi-26.9.25/galaxymidi/fast_parallel_extract.py` — Uses subprocess.run to execute 'tar' and 'pigz' with user-provided paths. The security note acknowledges the risk of command injection.
- `galaxymidi-26.9.25/galaxymidi/helpers.py` — Contains functions that execute 'apt-get' via subprocess.run to install system packages, which requires root privileges.
- `galaxymidi-26.9.25/galaxymidi/MIDI.py` — Contains a large, possibly redundant copy of a MIDI processing library, which increases the attack surface and complicates security auditing.

**Reviewer notes:**
- The package is designed for large-scale dataset processing, which explains the use of parallel extraction and system-level tools.
- The code appears to be a collection of utilities for the 'Galaxy MIDI Dataset'.
- The use of 'sudo' and 'apt-get' inside a Python package is generally discouraged as it can lead to unexpected system modifications and security issues.
- The duplication of MIDI.py across multiple files is poor practice and makes maintenance and security review difficult.

## Omitted Results

98 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

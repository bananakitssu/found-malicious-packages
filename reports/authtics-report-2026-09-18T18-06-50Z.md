# Authtics PyPI Security Scan

Generated: 2026-09-18T18:06:50.217817+00:00

### Potential Security Risk: Automatic Self-Update and Data Collection in Dokugen
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-200`, `CWE-88`
- **Package:** `dokugen@14.0.11`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package includes an automatic update mechanism that executes 'pip install --upgrade' or 'uv pip install --upgrade' at runtime. This behavior is risky as it allows the package to modify its own installation environment without explicit user confirmation during the update process, potentially introducing arbitrary code if the PyPI package is compromised.

**Evidence:**
- `src/dokugen/utils.py` — The 'check_and_update' function performs an automatic 'pip install --upgrade' or 'uv pip install --upgrade' if a newer version is detected on PyPI, which is a significant security risk.
- `src/dokugen/utils.py` — The 'get_user_info' function collects system metadata (OS, architecture, release, username) and sends it to a remote backend.
- `src/dokugen/commands/aic.py` — The package executes 'git' commands via subprocess to stage files and commit changes, which could be abused if the input to these commands is not properly sanitized.

**Reviewer notes:**
- The package's primary functionality is to generate documentation and commit messages using a remote AI backend. The collection of user info and the automatic update mechanism are the primary security concerns.
- The automatic update mechanism is particularly concerning as it runs with the privileges of the user executing the CLI tool.
- The code uses 'requests' to send project data to a remote server. While this is expected for an AI-based tool, users should be aware that their codebase is being sent to a third-party server.

## Omitted Results

99 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

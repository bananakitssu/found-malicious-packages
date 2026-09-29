# Authtics PyPI Security Scan

Generated: 2026-09-29T19:54:57.797293+00:00

### Automatic modification of .bashrc for persistence
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-426`
- **Package:** `semapapo@1.4.1`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package automatically modifies the user's .bashrc file to inject shell code that executes the 'semapapo' command upon shell startup. While the intent appears to be a greeting utility, modifying shell configuration files without explicit user consent or clear warning is a risky practice.

**Evidence:**
- `semapapo-1.4.1/src/semapapo/semapapo.py` — The 'configurar' function reads and appends a 'source' command to the user's ~/.bashrc file, ensuring that the package's custom script runs every time a new shell session starts.

**Reviewer notes:**
- The package provides a CLI tool that, when invoked with specific flags, modifies the user's environment. This behavior is persistent and affects the user's shell environment globally. While not inherently malicious, this pattern is often used by malware for persistence. The code is transparent, but the side effect of modifying .bashrc should be clearly documented and require explicit user interaction.

## Omitted Results

99 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

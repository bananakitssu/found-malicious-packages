# Authtics PyPI Security Scan

Generated: 2026-09-28T20:54:18.268062+00:00

### Security Analysis of AI-Driven Automation in Secator
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-78`, `CWE-829`
- **Package:** `secator@0.46.1`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes an AI-driven automation module that allows for the execution of arbitrary shell commands and tasks. While guardrails are implemented, the dynamic nature of AI-generated commands and the potential for bypasses in complex shell environments warrant caution.

**Evidence:**
- `secator/ai/actions.py` — Implements 'run_shell' functionality which executes arbitrary commands provided by an LLM, posing a risk of command injection if guardrails are bypassed.
- `secator/ai/guardrails.py` — Contains complex logic to parse and filter shell commands, which is inherently prone to bypasses when dealing with obfuscated or complex shell syntax.
- `scripts/install.sh` — Downloads and executes external scripts and binaries, which is a common vector for supply chain attacks.

**Reviewer notes:**
- The package is designed as a 'pentester's swiss knife', which inherently involves risky operations (scanning, executing exploits, shell commands).
- The AI module's guardrails are a positive security feature, but they should be reviewed for robustness against adversarial prompt engineering.
- The installation scripts rely on external downloads (e.g., Go, Ruby, pipx), which should be pinned to specific hashes for better security.

### Arbitrary Code Execution via Insecure Configuration Parsing
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `phylogenie@3.12.0`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package uses 'eval()' in multiple locations to process user-provided configuration strings, which could lead to arbitrary code execution if a user is tricked into using a malicious configuration file.

**Evidence:**
- `src/phylogenie/generators/factories.py` — The function 'eval_expression' uses 'eval()' to process strings from configuration files. This is a high-risk pattern for arbitrary code execution.
- `src/phylogenie/io/newick.py` — The 'parse_newick' function uses 'eval()' to parse metadata values embedded in Newick strings, which can be manipulated to execute arbitrary code.
- `src/phylogenie/plugins/native/base.py` — The 'generate' method uses 'eval_expression' to evaluate 'acceptance_criterion' and 'tree_logs'/'model_logs' expressions, which are derived from user-provided configuration.

**Reviewer notes:**
- The package is explicitly marked as deprecated and inactive, which increases the likelihood that these security issues will not be addressed.
- The use of 'eval()' is pervasive in the configuration parsing logic, making it difficult to safely use this package with untrusted input.
- While the intent is to allow users to define mathematical expressions for simulation parameters, the implementation is insecure.

## Omitted Results

98 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

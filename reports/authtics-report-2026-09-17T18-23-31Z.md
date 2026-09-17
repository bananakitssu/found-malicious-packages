# Authtics PyPI Security Scan

Generated: 2026-09-17T18:23:31.242368+00:00

### Arbitrary Code Execution Risk in PODPAC Algorithm Nodes
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-94`
- **Package:** `podpac@4.0.5`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains nodes (Arithmetic and Generic) that allow for arbitrary Python code execution via eval() and exec(). While these nodes include a safety check (settings.allow_unsafe_eval), they are designed to execute user-provided code strings, which poses a significant security risk if misused or if the safety mechanism is bypassed.

**Evidence:**
- `podpac-4.0.5/podpac/core/algorithm/generic.py` — The Arithmetic node uses eval() to execute mathematical expressions provided by the user, and the Generic node uses exec() to execute arbitrary multi-line Python code provided by the user.

**Reviewer notes:**
- The package implements a 'settings.allow_unsafe_eval' flag to gate these dangerous functions. However, the presence of these features in a library that might be used in data processing pipelines warrants caution, as it allows for remote code execution if the input strings are controlled by an attacker.
- The use of eval/exec is clearly documented as a feature for flexibility, but it remains a high-risk pattern.

### Arbitrary Code Execution via Generic and Arithmetic Nodes
- **Advisory:** `AUTH-2026-00004`
- **Package:** `podpac@4.0.5`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains nodes ('Generic' and 'Arithmetic') that explicitly allow for the execution of arbitrary Python code via 'exec()' and 'eval()'. While these features are guarded by a settings flag ('allow_unsafe_eval'), they present a significant security risk if enabled, as they allow arbitrary code execution through PODPAC node definitions.

**Evidence:**
- `podpac-4.0.5/podpac/core/algorithm/generic.py` — The 'Generic' class uses 'exec(self.code, inputs)' to execute arbitrary code provided in the 'code' attribute.
- `podpac-4.0.5/podpac/core/algorithm/generic.py` — The 'Arithmetic' class uses 'eval(eqn, f_locals)' as a fallback if 'numexpr' fails, allowing arbitrary expression evaluation.

**Reviewer notes:**
- The package implements a security control ('allow_unsafe_eval') to prevent accidental use of these features.
- The risk is high because if a user or application enables this setting, any untrusted input passed to these nodes could lead to remote code execution.
- The implementation of these features is intentional for the package's functionality, but it is inherently dangerous.

### Malicious Data Exfiltration and Privilege Escalation in aiosendletter
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-200`, `CWE-269`, `CWE-506`
- **Package:** `aiosendletter@4.6`
- **Severity:** `critical`
- **Confidence:** `1`
- **Review:** `PENDING`

The package 'aiosendletter' contains code designed to exfiltrate local data from the user's system to a remote server. It specifically attempts to escalate privileges to administrator level and exfiltrate the contents of the 'LOCALAPPDATA/logs' directory.

**Evidence:**
- `aiosendletter-4.6/e.py` — The script explicitly requests administrative privileges and attempts to zip and upload the contents of the user's 'logs' folder to a remote server.

**Reviewer notes:**
- The package claims to be a 'bug reporter' but performs unauthorized data collection and privilege escalation, which is characteristic of malicious software or spyware.
- The code is not a library but an executable script that runs immediately upon execution, which is highly suspicious for a package named 'aiosendletter'.

### Potential Arbitrary Code Execution via .codex/hooks.json
- **Advisory:** `AUTH-2026-00006`
- **Package:** `testguard-cli@0.5.0`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package includes a .codex/hooks.json file that defines command-line hooks to execute arbitrary Node.js scripts (pre-read.js, pre-write.js, etc.) during tool usage. While these appear to be intended for a development environment (likely related to the 'testguard' tool's own workflow), they represent a mechanism for executing arbitrary code based on file system events, which could be abused if the environment is compromised.

**Evidence:**
- `testguard_cli-0.5.0/.codex/hooks.json` — Defines hooks that execute node commands (e.g., 'node "$CLAUDE_PROJECT_DIR/.wolf/hooks/pre-read.js"') upon file system events, which is a high-risk pattern for arbitrary code execution.

**Reviewer notes:**
- The package is a CLI tool for fault injection and test quality assurance. The hooks.json file seems to be part of a development-time automation suite (possibly for an AI-assisted coding environment).
- While not inherently malicious, the ability to trigger arbitrary node scripts on file read/write events is a significant security concern if this package is used in an untrusted environment or if the hooks directory is writable by an attacker.
- The package itself is a Python wrapper for a Node.js CLI, which explains the reliance on Node.js.

### Malicious Data Exfiltration in aiosendletter
- **Advisory:** `AUTH-2026-00007`
- **Package:** `aiosendletter@4.6`
- **Severity:** `critical`
- **Confidence:** `1`
- **Review:** `PENDING`

The package 'aiosendletter' contains malicious code designed to exfiltrate local user data. It attempts to escalate privileges to administrator and exfiltrate the contents of the user's 'LOCALAPPDATA\logs' directory to a remote server.

**Evidence:**
- `aiosendletter-4.6/e.py` — The script explicitly requests administrative privileges and then reads the contents of the user's LOCALAPPDATA\logs folder to zip and upload it to a remote Cloudflare worker URL.

**Reviewer notes:**
- The package claims to be a 'bug reporter' but performs unauthorized data collection and exfiltration.
- The code is clearly designed for credential or data theft, masquerading as a utility library.
- The use of 'ctypes' to force an admin prompt is a classic indicator of malicious intent in Python packages.

### Invasive Runtime Monkey-patching in supply-chain-guard
- **Advisory:** `AUTH-2026-00008`
- **CWE:** `CWE-693`
- **Package:** `supply-chain-guard@0.3.1`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package implements a global import hook and monkey-patches core Python functionality (os.environ, builtins.open) to monitor and block sensitive operations. While intended for security, this approach is highly invasive, prone to breaking legitimate applications, and introduces significant stability risks.

**Evidence:**
- `supply_chain_guard-0.3.1/supply_chain_guard/__init__.py` — The package uses monkey-patching on os.environ and builtins.open to intercept file and environment access, which can cause unpredictable behavior in host applications.
- `supply_chain_guard-0.3.1/supply_chain_guard/__init__.py` — The package automatically registers a global audit hook and meta_path finder upon import, which affects the entire Python runtime environment.

**Reviewer notes:**
- The package's intent appears to be security-focused (detecting supply chain attacks), but the implementation method (monkey-patching core runtime components) is considered dangerous and non-standard for production libraries.
- The package version in setup.py (0.1.0) does not match the version in pyproject.toml (0.3.1), suggesting poor maintenance or packaging errors.
- The use of sys.addaudithook is a powerful feature that, if misconfigured or bypassed, could lead to unexpected application crashes.

### Malicious Data Exfiltration in aiosendletter
- **Advisory:** `AUTH-2026-00009`
- **Package:** `aiosendletter@4.6`
- **Severity:** `critical`
- **Confidence:** `1`
- **Review:** `PENDING`

The package 'aiosendletter' contains malicious code designed to exfiltrate local data. It attempts to escalate privileges to administrator and exfiltrate the contents of the user's 'logs' directory to a remote server.

**Evidence:**
- `aiosendletter-4.6/e.py` — The script explicitly requests administrative privileges and then proceeds to zip and upload the contents of the user's 'logs' folder to a hardcoded remote URL.

**Reviewer notes:**
- The package claims to be a 'bug reporter' but performs unauthorized data exfiltration. This is a clear case of malicious intent disguised as a utility.
- The code uses 'ctypes' to force an administrative prompt, which is highly suspicious for a library that claims to be a simple log reporter.

### Invasive Security Hook Implementation in supply-chain-guard
- **Advisory:** `AUTH-2026-00010`
- **CWE:** `CWE-1068`
- **Package:** `supply-chain-guard@0.3.1`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package implements a global import hook and monkey-patches core Python functionality (os.environ, builtins.open) to monitor and block sensitive operations. While intended as a security tool, the implementation uses aggressive runtime patching that could cause instability or unexpected behavior in host applications.

**Evidence:**
- `supply_chain_guard-0.3.1/supply_chain_guard/__init__.py` — The package uses monkey-patching on os.environ and builtins.open within a custom loader to intercept file and environment access.
- `supply_chain_guard-0.3.1/supply_chain_guard/__init__.py` — The package registers a global audit hook via sys.addaudithook to block subprocess execution and network connections.
- `supply_chain_guard-0.3.1/supply_chain_guard/__init__.py` — The install() function is called at the module level, ensuring the security hooks are active immediately upon import.

**Reviewer notes:**
- The package is designed as a security guard, but its implementation is highly invasive. Global monkey-patching of built-in functions is generally discouraged due to potential side effects on other libraries.
- The use of sys.addaudithook is a legitimate Python feature for security monitoring, but combined with the custom import loader, it creates a very broad interception surface.
- The package version in setup.py (0.1.0) does not match the version in pyproject.toml (0.3.1), suggesting poor maintenance or packaging errors.

## Omitted Results

92 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

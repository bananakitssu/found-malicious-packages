# Authtics PyPI Security Scan

Generated: 2026-09-14T19:52:24.812047+00:00

### Security Analysis of OTPme Deployment Scripts
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-214`, `CWE-377`, `CWE-522`
- **Package:** `otpme@0.3.0a276`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains several shell scripts that perform sensitive operations, including handling of encryption keys and passwords. Specifically, 'key_script.sh' and 'agent_script.sh' contain logic that handles passphrases and private keys, including potential exposure via environment variables or temporary files.

**Evidence:**
- `otpme-0.3.0a276/deploy/scripts/agent_script.sh` — Creates a temporary script in /tmp to handle PIN input for ssh-add, which could be vulnerable to race conditions or local information disclosure.
- `otpme-0.3.0a276/deploy/scripts/key_script.sh` — Contains complex logic for decrypting keys using openssl and bash, including reading passwords from stdin and handling temporary files for signing operations.
- `otpme-0.3.0a276/otpme/bin/command.py` — Implements a workaround to avoid leaking passwords in /proc/<pid>/cmdline by using setproctitle and environment variables, which indicates awareness of the risk but relies on complex process-level manipulation.

**Reviewer notes:**
- The package is a complex system for OTP management and includes many administrative scripts. The use of /tmp for sensitive operations is a common pattern in older or legacy shell-based tooling but is inherently risky.
- The Python code appears to be a wrapper around these shell scripts and backend logic. The security of the system heavily depends on the correct configuration of the backend and the environment.
- The use of setproctitle and environment variable passing for passwords is a mitigation for command-line leakage, but it does not eliminate the risk of password exposure via other local vectors.

### Potential Arbitrary Code Execution via Configuration Files
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-94`
- **Package:** `esa-climate-toolbox@1.7.1`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package uses 'exec()' on content read from user-configurable files, which is a security risk if an attacker can influence the content of these files.

**Evidence:**
- `esa_climate_toolbox-1.7.1/esa_climate_toolbox/conf/conf.py` — The function _read_python_config uses exec() to execute arbitrary Python code read from configuration files, which can lead to arbitrary code execution if the configuration files are tampered with.

**Reviewer notes:**
- The package is designed to load configuration from files like '~/.ect/conf.py'. While this is a common pattern for configuration, using exec() on these files allows any user with write access to the configuration directory to execute arbitrary code with the privileges of the user running the toolbox.
- The risk is mitigated by the fact that these are local configuration files, but it remains a potential vector for local privilege escalation or persistence if the environment is shared or if the user is tricked into placing a malicious config file.

### Runtime binary download and execution in agent-doc
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-829`
- **Package:** `agent-doc@0.35.395`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements a bootstrap mechanism that downloads and executes arbitrary binary code from GitHub at runtime. While this is a common pattern for distributing native binaries via PyPI, it bypasses standard package integrity checks and introduces a dependency on external network resources during execution.

**Evidence:**
- `agent_doc_bootstrap/cli.py` — The package downloads a binary archive from a GitHub release URL, verifies it against a downloaded SHA256SUMS file, and then executes the binary using os.execv or subprocess.call.

**Reviewer notes:**
- The bootstrap logic is well-implemented with security features like SHA256 verification and file locking. However, the fundamental design of downloading and executing binaries at runtime is inherently risky as it relies on the security of the GitHub repository and the network connection.
- The code does not contain obfuscation or malicious intent, but the pattern itself warrants caution for users concerned about supply chain security.

## Omitted Results

97 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

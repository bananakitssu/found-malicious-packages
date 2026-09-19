# Authtics PyPI Security Scan

Generated: 2026-09-19T17:23:05.323985+00:00

### Security Analysis of chatty-agent: Sandboxed AI Agent with Command Execution
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-184`, `CWE-78`, `CWE-94`
- **Package:** `chatty-agent@0.3.1`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements a sandboxed AI agent that executes shell commands and Python scripts. While it includes safety mechanisms like Landlock and path validation, the ability to execute arbitrary shell commands and Python scripts (even with some safety checks) presents a significant risk if the sandbox is misconfigured or if the LLM is manipulated to bypass restrictions.

**Evidence:**
- `src/chatty/runner.py` — The tool_run_command function uses subprocess.Popen to execute shell commands, which is a high-risk operation.
- `src/chatty/safety.py` — The validate_command_safety function attempts to block dangerous commands, but relies on blacklisting and parsing, which is inherently prone to bypasses.
- `src/chatty/landlock.py` — The package compiles and uses a custom C binary for Landlock sandboxing, which adds complexity and potential for security vulnerabilities.

**Reviewer notes:**
- The package is designed to be a powerful AI agent, which inherently requires dangerous capabilities (file system access, command execution).
- The security model relies on a combination of path validation, Landlock, and command blacklisting. These are good practices but are not foolproof against sophisticated LLM-based attacks.
- The use of a custom C binary for Landlock is a notable design choice that requires careful auditing.

### Hardcoded Paths and Risky Internal Overrides in allopockets
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-1076`, `CWE-73`
- **Package:** `allopockets@1.0.17`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains hardcoded local file paths in 'allopockets/features/embeddings.py' and 'allopockets/database/allodb.py', which may cause runtime errors or security concerns if the environment is not configured as expected. Additionally, the package includes a modified version of 'pdbecif''s '_parseFile' method in 'allopockets/database/cifutils.py', which is a significant deviation from standard library behavior and requires careful review.

**Evidence:**
- `allopockets/features/embeddings.py` — Hardcoded absolute path '/data/fnerin/huggingface/hub/models--facebook--esm2_t33_650M_UR50D' used to load machine learning models.
- `allopockets/database/cifutils.py` — The package overrides the private '_parseFile' method of 'pdbecif.mmcif_tools.MMCIF2Dict', which is a risky practice that could lead to unexpected behavior or vulnerabilities if the upstream library changes.
- `allopockets/database/allodb.py` — Hardcoded path 'data' relative to the module directory for saving CIF files.

**Reviewer notes:**
- The hardcoded path in 'embeddings.py' is highly specific to a single user's environment ('fnerin'), which is a major red flag for portability and security.
- The modification of 'pdbecif' internals suggests the package relies on specific, potentially fragile, parsing logic that might not be maintained or secure.
- The package uses 'peewee' and 'playhouse' for database operations, which is generally safe, but the custom parsing logic in 'cifutils.py' should be audited for potential injection or parsing vulnerabilities.

### Potential Remote Command Execution via Unauthenticated Terminal WebSocket
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-306`, `CWE-78`
- **Package:** `git-juggler@0.1.2`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package provides a web-based terminal interface that spawns a shell process on the host machine. While this is a core feature of the application, it introduces significant security risks if exposed to untrusted users, as it allows arbitrary command execution within the context of the user running the application.

**Evidence:**
- `src/backend/git_juggler/terminal.py` — The application uses pty.fork() to spawn a shell (defaulting to /bin/bash) and relays input from a WebSocket directly to the shell's stdin, enabling remote command execution.

**Reviewer notes:**
- The terminal functionality is clearly intended for local use, as evidenced by the CORS configuration restricting access to localhost. However, the lack of authentication on the WebSocket endpoint means that any process on the local machine (or any entity that can bypass the CORS check) could potentially interact with the terminal. The risk is primarily relevant if the tool is exposed to a network or if a malicious local process interacts with the port.

## Omitted Results

97 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

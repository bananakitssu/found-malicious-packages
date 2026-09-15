# Authtics PyPI Security Scan

Generated: 2026-09-15T18:52:46.967053+00:00

### Potential Arbitrary Code Execution and Remote Command Injection in sbdl
- **Advisory:** `AUTH-2026-00003`
- **CWE:** Not assigned
- **Package:** `sbdl@1.27.1`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains multiple files that execute arbitrary code via 'eval()' or similar mechanisms, and includes a remote server component ('sbdl_server.py') that executes arbitrary commands based on user input.

**Evidence:**
- `sbdl_server.py` — The 'run_sbdl' function executes external commands using 'subprocess.run' with arguments derived from user input, and the server accepts remote requests to execute these commands.
- `sbdl_compliance.py` — Contains a 'VERIFIER_TYPE' string that includes a '[[[#!python ... ]]]' block, which is intended to be executed as Python code within the SBDL compiler.
- `sbdl_model.py` — The SBDL compiler architecture includes mechanisms to execute embedded Python code blocks (e.g., 'custom_verifier' attribute) which could lead to arbitrary code execution if the input SBDL files are untrusted.

**Reviewer notes:**
- The package is designed as a DSL compiler that explicitly supports embedding Python code within the DSL files for verification and custom logic. This is a powerful feature but inherently dangerous if the input files are not trusted.
- The 'sbdl_server.py' file appears to be a remote RPC server that allows executing the compiler remotely. This is a significant security risk if exposed to the network without authentication.
- The 'Proprietary' license and the nature of the code suggest this is a specialized tool, but the security implications of the embedded code execution and remote server are high.

## Omitted Results

99 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

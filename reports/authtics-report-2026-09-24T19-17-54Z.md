# Authtics PyPI Security Scan

Generated: 2026-09-24T19:17:54.883370+00:00

### Analysis of GoodbyeSQL 0.5.3
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-391`, `CWE-703`
- **Package:** `GoodbyeSQL@0.5.3`
- **Severity:** `low`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package GoodbyeSQL contains a broken entry point reference and a potential logic error in the session provider implementation.

**Evidence:**
- `goodbyesql-0.5.3/setup.py` — The entry point 'goodbyesql=goodbyesql.main:main' references a function 'main' that does not exist in 'goodbyesql/main.py'.
- `goodbyesql-0.5.3/goodbyesql/registry.py` — The get_session function creates a RuntimeError object but fails to raise it, meaning the function will return None instead of failing when the session provider is not set.

**Reviewer notes:**
- The package appears to be a work-in-progress or poorly maintained library rather than malicious.
- The missing 'main' function in setup.py will cause an ImportError if a user attempts to run the console script.
- The logic in registry.py is flawed as it does not actually raise the exception.

### Potential security risks in gitera CLI utilities
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-78`
- **Package:** `gitera@0.0.16`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains a utility 'gitnuke' that performs automated git operations using shell=True, which is inherently risky if input were ever sourced from untrusted locations, though currently it prompts for user input. The package also uses terminal control sequences and shell commands to manipulate the user's git repository state.

**Evidence:**
- `src/gitera/gitnuke.py` — The function 'inp' uses subprocess.run with shell=True and an f-string to execute git commands. While the input is currently an integer, this pattern is dangerous and prone to command injection if modified.
- `src/gitera/gitout.py` — The script performs automated 'git checkout' operations based on user input and terminal interaction, which could lead to unexpected repository states or data loss if not handled carefully.

**Reviewer notes:**
- The package is a CLI tool for git management. The 'gitnuke' functionality is destructive (it runs 'git init' and 'rm gitout' repeatedly). While not explicitly malicious, it is highly dangerous for a user to run in an existing repository.
- The use of shell=True in gitnuke.py is unnecessary and should be replaced with list-based arguments to subprocess.run for security best practices.

### Potential risk from unverified binary component in lowlevel package
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-506`
- **Package:** `lowlevel@1.0.0`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package includes a pre-compiled binary (memory.dll) which is loaded at runtime via ctypes. This bypasses standard Python security analysis and introduces potential risks associated with arbitrary binary execution.

**Evidence:**
- `lowlevel-1.0.0/lowlevel/memory/memory.py` — The module loads a local file named 'memory.dll' using ctypes.CDLL. The source code for this binary is not provided, making it impossible to verify the safety of the memory management operations.

**Reviewer notes:**
- The package relies on a pre-compiled binary component. Without the source code for 'memory.dll', the security of the memory allocation and read/write operations cannot be verified.
- The use of ctypes to interface with a binary is a common pattern for performance, but it is also a common vector for hiding malicious functionality.
- The package appears to be a wrapper for low-level memory operations, which inherently carries risks if the underlying binary is compromised.

### Potential Arbitrary Code Execution via Database-Stored Logic
- **Advisory:** `AUTH-2026-00006`
- **CWE:** `CWE-94`
- **Package:** `pytigon-standard-prj@0.260924`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains multiple instances of dynamic code execution patterns, specifically using 'run_code_from_db_field' to execute Python code stored in database fields. This is a high-risk pattern that allows for arbitrary code execution if the database content is compromised or if user-supplied input is improperly handled.

**Evidence:**
- `pytigon_standard_prj/prj/_schbi/schbi/models.py` — Uses 'run_code_from_db_field' to execute code from the 'refresh_data' field.
- `pytigon_standard_prj/prj/_schbi/schbi/views.py` — Uses 'run_code_from_db_field' to execute code from 'view' fields in models.
- `pytigon_standard_prj/prj/_schdata/schchart/views.py` — Uses 'run_code_from_db_field' to execute code from 'get_config', 'get_data', 'get_layout', and 'on_event' fields.
- `pytigon_standard_prj/prj/_schdata/schdoc/views.py` — Uses 'run_code_from_db_field' to execute code from 'save_fun' and 'load_fun' fields.

**Reviewer notes:**
- The package architecture relies heavily on storing and executing Python code within database fields. While this may be a design choice for a framework, it presents a significant security risk if the database is not strictly protected or if the input validation for these fields is insufficient.
- The 'prepare_for_pypi.sh' script performs various database migrations and setup tasks, which is unusual for a standard package installation and suggests a complex, state-dependent deployment process.

## Omitted Results

96 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

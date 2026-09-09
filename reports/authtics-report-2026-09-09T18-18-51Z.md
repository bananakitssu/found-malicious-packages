# Authtics PyPI Security Scan

Generated: 2026-09-09T18:18:51.782730+00:00

### Dynamic Python Tracing via Process Injection
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-250`
- **Package:** `pymontrace@0.1.0.dev14`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package implements a dynamic Python tracing tool that uses process injection techniques (ptrace-like behavior on Linux/Darwin) to execute arbitrary Python code within a target process. While the intent is debugging, the mechanism of injecting code into running processes is inherently high-risk and requires elevated privileges (e.g., sudo/ptrace capabilities).

**Evidence:**
- `pymontrace-0.1.0.dev14/setup.py` — Defines C extensions (attacher, _tracebuffer) that interface with OS-level process manipulation APIs (mach_excServer on Darwin, attacher_linux_64bit on Linux).
- `pymontrace-0.1.0.dev14/src/pymontrace/attacher.pyi` — Exposes 'attach_and_exec' and 'exec_in_threads', which are the primary primitives for injecting code into a target process.
- `pymontrace-0.1.0.dev14/src/pymontrace/tracer.py` — Contains 'format_bootstrap_snippet' which generates Python code to be executed inside the target process, including dynamic sys.path manipulation and module importing.

**Reviewer notes:**
- The package is a sophisticated debugging tool. The use of process injection is consistent with its stated purpose (dynamic tracing).
- The code is well-structured, but the capability to inject code into arbitrary processes is a significant security vector if misused.
- The use of 'py_limited_api' and C extensions suggests a focus on performance for tracing, which is common in this domain.
- The package requires careful review of the C source code (not fully provided in the snippet) to ensure the injection mechanism is robust and does not introduce memory corruption vulnerabilities.

### Dynamic Code Execution in AppManager Sub-App Loader
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-22`, `CWE-94`
- **Package:** `appmanager-server@0.4.1`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package implements a dynamic sub-application loading mechanism that executes arbitrary Python code from uploaded ZIP files or Git repositories. While it includes security checks like AST parsing and path validation, the dynamic execution of code via importlib and exec_module poses a significant risk if these controls are bypassed or misconfigured.

**Evidence:**
- `appmanager_server-0.4.1/appmanager/admin/app_installer.py` — The function 'load_wsgi_app_from_path' uses 'importlib.util.spec_from_file_location' and 'exec_module' to load and execute Python code from arbitrary paths within the installed apps directory.
- `appmanager_server-0.4.1/appmanager/admin/registry.py` — The function '_resolve_blueprint' uses 'importlib.import_module' to dynamically load Flask blueprints from sub-apps, which are then registered into the main application.
- `appmanager_server-0.4.1/appmanager/admin/app_installer.py` — The 'normalize_and_flatten_app_dir' function performs file system operations (shutil.move, shutil.rmtree) on user-provided content, which requires careful validation to prevent directory traversal.

**Reviewer notes:**
- The package is designed as a host portal for sub-applications, making dynamic code loading a core feature rather than a typical vulnerability. However, the security of this architecture relies entirely on the robustness of the 'validate_entrypoint_path' and 'extract_zip_safely' functions.
- The use of 'ast.parse' in 'validate_subapp_package' is a good defensive practice to detect syntax errors, but it does not prevent malicious logic execution.
- The 'admin_guard' in 'registry.py' correctly attempts to enforce admin-only access for mounted blueprints, which mitigates some risks of unauthorized access to sub-app admin panels.

### Runtime Dependency Fetching from External CDN
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-829`
- **Package:** `tinyleaf@0.6.0`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements a dynamic dependency management system that downloads JavaScript modules from a CDN (jsdelivr.net) at runtime. While this is a common pattern for self-hosted web applications to avoid bundling large dependencies, it introduces a supply-chain risk where the application's functionality depends on external, unpinned (or loosely pinned) remote content.

**Evidence:**
- `src/tinyleaf/vendor.py` — The module contains logic to download ESM bundles from jsdelivr.net, rewrite import paths, and save them to a local vendor directory. This behavior is triggered by the CLI or API.
- `src/tinyleaf/cli.py` — The CLI automatically triggers the vendor download process if the vendor directory is not ready, potentially executing network requests without explicit user confirmation during the first run.

**Reviewer notes:**
- The package uses a 'zerodep' philosophy, which explains the inclusion of vendor-specific code. The risk is primarily related to the trust placed in the CDN and the lack of cryptographic verification (e.g., SRI hashes) for the downloaded files.
- The code does not appear to be intentionally malicious, but the design pattern of fetching and executing remote code at runtime is a significant security consideration for self-hosted applications.

## Omitted Results

97 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

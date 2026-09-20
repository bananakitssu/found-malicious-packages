# Authtics PyPI Security Scan

Generated: 2026-09-20T17:39:19.916263+00:00

### Security Analysis of pyfixer-ai: Dynamic Execution and API Key Probing
- **Advisory:** `AUTH-2026-00003`
- **Package:** `pyfixer-ai@0.5.9`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains dynamic code execution patterns and network-based API key probing that warrant careful review. Specifically, the use of exec() and eval() in _pair_probe.py and the automatic network probing of API keys in byok.py pose security risks.

**Evidence:**
- `pyfixer_ai-0.5.9/pyfixer/_pair_probe.py` — Uses exec() to load and execute code from arbitrary paths and eval() to evaluate expressions from a JSON file, which is a high-risk pattern for code injection.
- `pyfixer_ai-0.5.9/pyfixer/byok.py` — Contains _is_deepseek_key which performs an automatic network POST request to an external API (api.deepseek.com) using the user's provided API key to probe its validity.

**Reviewer notes:**
- The package is designed to perform automated code analysis and fixing, which inherently requires some level of dynamic analysis. However, the implementation of _pair_probe.py is particularly dangerous as it executes code from files provided as arguments.
- The network probing in byok.py is a privacy and security concern as it sends the user's API key to an external service without explicit user confirmation during the probe.
- The package uses a local SQLite database for caching, which is standard, but the overall architecture relies on significant trust in the input files being analyzed.

### Hardcoded User Path in repo_searcher.py
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-798`
- **Package:** `hashenv@0.1.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains a hardcoded path in 'src/helpers/repo_searcher.py' that attempts to walk the filesystem starting at '/Users/chestor'. This is highly suspicious as it targets a specific user directory, which is likely a developer's local path, and could lead to unauthorized file enumeration or privacy concerns if executed on a different machine.

**Evidence:**
- `src/helpers/repo_searcher.py` — The function 'repo_searcher' uses 'os.walk("/Users/chestor")', which is a hardcoded path specific to a local development environment and poses a security risk by scanning arbitrary files on a user's system.

**Reviewer notes:**
- The package appears to be a CLI tool for managing environment variables. While the functionality seems intended for syncing repositories, the hardcoded path in 'repo_searcher.py' is a significant red flag for a distributed package.
- The code also uses 'keyring' to store tokens, which is a standard practice, but the overall implementation should be reviewed for potential data exfiltration risks given the server-side communication.

### Hardcoded User Path in repo_searcher.py
- **Advisory:** `AUTH-2026-00005`
- **Package:** `hashenv@0.1.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains a hardcoded path in 'src/helpers/repo_searcher.py' that attempts to walk the filesystem starting at '/Users/chestor'. This is highly suspicious as it targets a specific user directory, which is likely a developer's local path, and could lead to unauthorized file enumeration or privacy concerns if executed on a different machine.

**Evidence:**
- `src/helpers/repo_searcher.py` — The function 'repo_searcher' uses 'os.walk("/Users/chestor")', which is a hardcoded path specific to a local development environment and poses a security risk by scanning arbitrary files on a user's system.

**Reviewer notes:**
- The package appears to be a CLI tool for environment management. While the functionality seems intended for syncing .env files, the hardcoded path in repo_searcher is a significant red flag.
- The code also uses 'keyring' to store tokens, which is a standard practice, but the overall implementation should be reviewed for potential data exfiltration risks given the server-side communication.

### Runtime C++ Compilation and Hardcoded Paths in kernel-lens
- **Advisory:** `AUTH-2026-00006`
- **CWE:** `CWE-200`, `CWE-94`
- **Package:** `kernel-lens@1.1.7`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package performs dynamic compilation of C++ code using 'nvcc' and 'g++' at runtime, which involves downloading external binaries and executing system commands. While this is a core feature of the package's functionality (compiling Triton kernels), it introduces security risks related to arbitrary code execution and dependency on system-level tools.

**Evidence:**
- `kernel_lens-1.1.7/kernel_lens/backends/builder.py` — The build_ort_plugin function downloads a tarball from GitHub and executes system commands (curl, nvcc, g++) to compile shared libraries at runtime.
- `kernel_lens-1.1.7/kernel_lens/compiler/core.py` — The _get_cache_dir function contains a hardcoded absolute path (/home/ostentatoire/...) as a fallback, which is a significant security and privacy concern.
- `kernel_lens-1.1.7/kernel_lens/utils/env_check.py` — The check_environment function modifies the system PATH environment variable to locate nvcc, which could be exploited if an attacker controls the environment.

**Reviewer notes:**
- The package is designed to compile Triton kernels into shared libraries at runtime. This behavior is intentional but inherently risky.
- The hardcoded path in _get_cache_dir is likely a developer oversight but should be removed as it leaks local system information.
- The reliance on system-level compilers (nvcc, g++) means the package's security is tied to the security of the host's build environment.
- No evidence of malicious intent was found; the code appears to be a legitimate, albeit complex, compiler tool.

### Hardcoded local filesystem path in repo_searcher.py
- **Advisory:** `AUTH-2026-00007`
- **Package:** `hashenv@0.1.6`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains a hardcoded path in 'src/helpers/repo_searcher.py' that attempts to walk the filesystem starting at '/Users/chestor'. This is highly suspicious as it targets a specific user directory, which is likely a developer's local environment path, and could lead to unauthorized file enumeration or privacy concerns if executed on a machine where that path exists.

**Evidence:**
- `src/helpers/repo_searcher.py` — The function 'repo_searcher' uses 'os.walk("/Users/chestor")', which is a hardcoded path specific to a local development environment. This behavior is unexpected for a general-purpose CLI tool and suggests potential unauthorized access to user files.

**Reviewer notes:**
- The package appears to be a CLI tool for managing environment variables. While the functionality seems intended for syncing repositories, the hardcoded path in 'repo_searcher.py' is a significant red flag.
- The 'login' command takes a token and stores it using 'keyring', which is standard practice, but the hardcoded path suggests the developer may have accidentally included local development code in the production release.

### Hardcoded absolute paths in geomagpy
- **Advisory:** `AUTH-2026-00008`
- **CWE:** `CWE-426`
- **Package:** `geomagpy@2.0.2`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains hardcoded absolute file paths in multiple source files, which is a poor practice that can lead to security issues or runtime failures in environments where these paths do not exist.

**Evidence:**
- `magpy/absolutes.py` — Contains hardcoded path: sys.path.insert(1, '/home/leon/Software/magpy/')
- `magpy/core/activity.py` — Contains hardcoded path: sys.path.insert(1,'/home/leon/Software/magpy/')
- `magpy/core/database.py` — Contains hardcoded path: sys.path.insert(1, '/home/leon/Software/magpy/')
- `magpy/core/flagbrain.py` — Contains hardcoded path: sys.path.insert(1,'/home/leon/Software/magpy/')
- `magpy/core/flagging.py` — Contains hardcoded path: sys.path.insert(1, '/home/leon/Software/magpy/')
- `magpy/core/plot.py` — Contains hardcoded path: sys.path.insert(1,'/home/leon/Software/magpy/')

**Reviewer notes:**
- The hardcoded paths appear to be remnants of a developer's local environment. While not inherently malicious, they indicate poor development practices and could potentially be exploited if an attacker can create directories matching these paths on a target system to inject malicious modules.
- The package uses standard libraries and does not show signs of obfuscation or malicious intent.

### Potential Security Risk: Runtime C++ Compilation and Hardcoded Paths
- **Advisory:** `AUTH-2026-00009`
- **CWE:** `CWE-78`, `CWE-807`
- **Package:** `kernel-lens@1.1.7`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package performs dynamic compilation of C++ code using 'nvcc' and 'g++' at runtime, which involves downloading external binaries and executing system commands. While this is a core feature of the package's functionality, it introduces security risks related to arbitrary code execution and dependency on system-level tools.

**Evidence:**
- `kernel_lens-1.1.7/kernel_lens/backends/builder.py` — The build_ort_plugin function downloads a tarball from GitHub and uses subprocess to compile C++ code at runtime.
- `kernel_lens-1.1.7/kernel_lens/compiler/core.py` — The _get_cache_dir function contains a hardcoded fallback path pointing to a specific user's directory (/home/ostentatoire/...), which is a potential security and privacy concern.
- `kernel_lens-1.1.7/kernel_lens/utils/env_check.py` — The check_environment function modifies the system PATH environment variable to locate nvcc.

**Reviewer notes:**
- The package is designed as a JIT compiler for Triton kernels, so runtime compilation is expected behavior. However, the hardcoded developer path in _get_cache_dir is unprofessional and potentially sensitive.
- The reliance on system-level compilers (nvcc, g++) and external downloads makes the package's security posture dependent on the host environment's integrity.
- No evidence of malicious intent was found, but the design pattern is inherently high-risk for supply chain attacks if the build process is compromised.

### Hardcoded Credentials and Automated Data Deletion in meteorbase
- **Advisory:** `AUTH-2026-00010`
- **Package:** `meteorbase@0.1.0`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains hardcoded Firebase credentials and implements automated database management logic that performs remote deletions without user confirmation. The presence of a telemetry cache file suggests potential data exfiltration or tracking behavior.

**Evidence:**
- `meteorbase-0.1.0/firebase-applet-config.json` — Contains hardcoded Firebase API keys, project IDs, and storage bucket information.
- `meteorbase-0.1.0/meteorbase/app.py` — The function 'verify_and_cleanup_database' performs automated deletions of Firestore records based on timestamps without explicit user confirmation.
- `meteorbase-0.1.0/.telemetry_cache.json` — Contains a detailed log of request paths, timestamps, and latency, indicating potential tracking or telemetry collection.

**Reviewer notes:**
- The package appears to be a wrapper for a specific Firebase project ('itsjustayush').
- The 'telemetry_cache.json' file is highly unusual for a standard Python library and suggests the package might be tracking usage patterns or exfiltrating data.
- The hardcoded credentials in 'firebase-applet-config.json' pose a significant security risk if this package is intended for general use.

## Omitted Results

92 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

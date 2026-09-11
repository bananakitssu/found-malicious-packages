# Authtics PyPI Security Scan

Generated: 2026-09-11T17:57:39.565736+00:00

### Potential Arbitrary Code Execution via Configuration and Cloud Infrastructure Risks
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-522`, `CWE-78`, `CWE-94`
- **Package:** `labdata@0.1.17`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package uses 'eval()' to dynamically load analysis classes from user-defined preferences, which could lead to arbitrary code execution if the preference file is tampered with. Additionally, the package includes functionality to generate and execute shell scripts for cloud infrastructure (EC2/SLURM) that involve handling credentials and executing commands, which requires careful configuration to avoid security risks.

**Evidence:**
- `labdata-0.1.17/labdata/compute/utils.py` — The function 'load_analysis_object' uses 'eval(prefs['compute']['analysis'][analysis])' to instantiate classes, which is a security risk if the configuration file is compromised.
- `labdata-0.1.17/labdata/compute/ec2.py` — The function 'ec2_cmd_for_launch' generates shell scripts for EC2 user-data that include AWS credentials and execute commands, potentially exposing sensitive information if not handled securely.
- `labdata-0.1.17/labdata/compute/schedulers.py` — The function 'slurm_schedule_remote' injects database credentials into environment variables for remote SLURM jobs, which could be exposed if the remote environment is not secure.

**Reviewer notes:**
- The use of eval() is limited to loading classes defined in a local configuration file (prefs). While this is a common pattern in some scientific software, it is inherently risky if the configuration file is writable by an attacker.
- The cloud infrastructure management features (EC2/SLURM) are powerful and require the user to manage credentials securely. The package provides mechanisms to store these, but the security of the storage depends on the user's environment.
- The code appears to be designed for a research lab environment where users are expected to have trusted access to the configuration files and infrastructure.

### Potential Typosquatting: openaii package
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-1037`
- **Package:** `openaii@1.55.3`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package 'openaii' appears to be a typosquatting attempt targeting the legitimate 'openai' library. It imports all symbols from the 'openai' package, likely to act as a transparent wrapper or proxy for the legitimate library while masquerading under a similar name.

**Evidence:**
- `openaii/__init__.py` — The package attempts to import and expose the entire namespace of the 'openai' library, which is a common pattern for malicious packages attempting to intercept or proxy traffic for legitimate libraries.

**Reviewer notes:**
- The package name 'openaii' is a clear attempt to mimic 'openai'. While the code itself is a simple import wrapper, the intent is highly suspicious as it provides no unique functionality and relies entirely on the presence of the legitimate library.

### Typosquatting detected in package transfomers
- **Advisory:** `AUTH-2026-00005`
- **Package:** `transfomers@4.44.2`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package 'transfomers' (note the typo in the name, missing the 's' after 'n') appears to be a typosquatting attempt targeting the legitimate 'transformers' library by Hugging Face.

**Evidence:**
- `transfomers/__init__.py` — The package name 'transfomers' is a clear typosquat of 'transformers'. The code attempts to import from the legitimate library, which is a common pattern for malicious packages to maintain functionality while potentially intercepting data or executing arbitrary code.

**Reviewer notes:**
- The package name 'transfomers' is highly suspicious due to the missing 's'. This is a classic typosquatting technique. The implementation in __init__.py confirms it is attempting to shadow or wrap the legitimate 'transformers' library.
- No malicious payload was found in the provided snippet, but the intent to impersonate a major library is high-risk.

## Omitted Results

97 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

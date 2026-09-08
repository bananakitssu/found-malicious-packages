# Authtics PyPI Security Scan

Generated: 2026-09-08T18:20:27.446605+00:00

### Potential Remote Code Execution via AI-Generated Automation Scripts
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-94`
- **Package:** `simo@3.5.65`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains functionality to dynamically execute Python code provided by an external AI service, which poses a significant security risk if the service is compromised or if the input is not properly sanitized.

**Evidence:**
- `src/simo/automation/controllers.py` — The ai_assistant method sends user intent to an external URL and expects a Python script in return, which is then presumably used in the system.
- `src/simo/automation/gateways.py` — The run_code method uses exec() to execute code stored in the component configuration, which is populated by the AI assistant.

**Reviewer notes:**
- The use of exec() on data retrieved from an external API is inherently dangerous. While the system appears to be designed for smart home automation, the ability to inject arbitrary Python code via the AI assistant feature is a high-risk vector.
- The implementation uses multiprocessing for script isolation, which is a good practice, but it does not prevent the execution of malicious code within the isolated process.
- The package relies on a proprietary AI service (simo.io) to generate automation scripts. The security of this feature depends entirely on the integrity of that service.

### Use of eval() in civis/_retries.py
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-95`
- **Package:** `civis@2.10.0`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package uses `eval()` in `src/civis/_retries.py` to instantiate a `tenacity.Retrying` object from a string constant. While the string constant is hardcoded and appears safe, the use of `eval()` is a dangerous pattern that should be replaced with direct instantiation.

**Evidence:**
- `src/civis/_retries.py` — The function `get_default_retrying` uses `eval()` to parse and execute a string representation of a `tenacity.Retrying` object. Although the string is a hardcoded constant, this is a risky practice.

**Reviewer notes:**
- The use of eval() is restricted to a hardcoded string constant `DEFAULT_RETRYING_STR` within the same module. The globals and locals are explicitly restricted, which mitigates the risk of arbitrary code execution. However, this remains a poor security practice that should be refactored to direct object instantiation.

## Omitted Results

98 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

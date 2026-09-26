# Authtics PyPI Security Scan

Generated: 2026-09-26T17:55:45.732783+00:00

### Security Review: Telemetry and Insecure HTTP usage in hcs-core
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-295`, `CWE-94`
- **Package:** `hcs-core@0.1.355`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains telemetry functionality that sends data to an external endpoint (collie.omnissa.com) without explicit user opt-in, and uses 'verify=False' in its HTTP requests, which disables SSL certificate verification.

**Evidence:**
- `hcs_core-0.1.355/hcs_core/ctxp/telemetry.py` — The _injest function sends telemetry data to an external endpoint using verify=False, which is insecure.
- `hcs_core-0.1.355/hcs_core/ctxp/cli_processor.py` — The _read_group_meta function uses eval() on content read from files, which is a security risk if the file content is attacker-controlled.

**Reviewer notes:**
- The telemetry feature is enabled by default. While it appears to be for internal usage by Omnissa, the lack of SSL verification and the default-enabled state are security concerns.
- The use of eval() in _read_group_meta should be replaced with a safer alternative like ast.literal_eval().

### Insecure SSL Configuration in dikgames SDK
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-295`
- **Package:** `dikgames@1.0.1`
- **Severity:** `low`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package disables SSL certificate verification in its API client, which exposes the application to potential Man-in-the-Middle (MitM) attacks when communicating with the DikGames API.

**Evidence:**
- `dikgames-1.0.1/dikgames/client.py` — The DikGamesClient class explicitly sets self.ctx.verify_mode = ssl.CERT_NONE and self.ctx.check_hostname = False, which disables TLS/SSL validation for all API requests.

**Reviewer notes:**
- While the package appears to be a legitimate SDK for a specific website, the decision to disable SSL verification is a security anti-pattern. It allows any attacker capable of intercepting the network traffic to present a fraudulent certificate and potentially inject malicious data into the API responses.
- No other malicious behavior (such as obfuscated code, unauthorized data exfiltration, or persistence mechanisms) was detected.

### Inclusion of functional exploit payload in demo directory
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-506`
- **Package:** `mcp-trentina-crunchtools@0.39.0`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package contains a 'demo/attack-sim' directory that includes a 'struct.py' file designed to act as a module shadow payload. This file uses obfuscated character codes to perform file system operations (writing '.status' file). While this is presented as part of a security demonstration/challenge, the inclusion of functional exploit payloads in a package is a significant security risk.

**Evidence:**
- `mcp_trentina_crunchtools-0.39.0/demo/attack-sim/payload/struct.py` — Contains obfuscated code using chr() to write a file named '.status' to the current working directory, acting as a malicious module shadow.
- `mcp_trentina_crunchtools-0.39.0/demo/attack-sim/server.py` — Implements a stateful challenge server that provides the malicious archive to users/agents.

**Reviewer notes:**
- The package is a security tool (MCP gateway) and the demo/attack-sim appears to be a legitimate educational/testing harness for demonstrating the tool's defense capabilities.
- The obfuscation in 'struct.py' is explicitly acknowledged in 'gourmand-exceptions.toml' as a design choice for testing the tool's detection capabilities.
- Despite the benign intent (security testing), shipping functional exploit payloads in a production package is dangerous and violates standard security practices.

### Remote Code Execution via Dynamic Code Loading in fintech-hub
- **Advisory:** `AUTH-2026-00006`
- **CWE:** `CWE-94`
- **Package:** `fintech-hub@0.1.0`
- **Severity:** `high`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package implements a remote code execution (RCE) pattern by design, allowing users to fetch and execute arbitrary Python code from a remote server. While this is the stated functionality of the package, it poses a significant security risk if the remote server is compromised or if the user is tricked into connecting to a malicious endpoint.

**Evidence:**
- `fintech_hub-0.1.0/fintech_hub/__init__.py` — The _run function uses exec(compile(code, filename, 'exec'), namespace) to execute code retrieved from the network, which is a direct RCE vector.
- `fintech_hub-0.1.0/fintech_hub/__init__.py` — The _ask function performs network requests to a configurable URL (HUB_URL) using an authorization key, which could be intercepted or redirected.

**Reviewer notes:**
- The package is designed to act as a remote function runner. The security risk is inherent to the design. Users should be warned that this package executes arbitrary code from the configured server.
- The use of linecache to map the executed code to a filename is a clever way to handle tracebacks but does not mitigate the risk of executing malicious code.
- The package does not appear to perform any signature verification or integrity checks on the code received from the server.

## Omitted Results

96 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

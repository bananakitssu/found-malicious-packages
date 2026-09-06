# Authtics PyPI Security Scan

Generated: 2026-09-06T18:05:40.522980+00:00

### High-Risk System Automation and Privilege Escalation in zoraai
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-250`, `CWE-312`, `CWE-798`
- **Package:** `zoraai@1.2.1`
- **Severity:** `high`
- **Confidence:** `0.9`
- **Review:** `PENDING`

The package 'zoraai' contains extensive system-level automation capabilities, including keyboard/mouse control, file system manipulation, and browser automation. It includes a 'license' verification system that uses hardcoded Firebase credentials and attempts to elevate privileges to Administrator/Root. The package also includes obfuscated credentials for external services.

**Evidence:**
- `zoraai-1.2.1/nion_filesystem_agent.py` — Explicitly checks for and attempts to elevate to Administrator/Root privileges using ShellExecuteW.
- `zoraai-1.2.1/agent.py` — Uses XOR-based obfuscation (_d function) to hide API keys and credentials.
- `zoraai-1.2.1/nion_keyboard_mouse_CTRL.py` — Provides tools for full keyboard and mouse control, including hotkey simulation and volume control.
- `zoraai-1.2.1/nion_auth.py` — Contains hardcoded Firebase API keys and implements a license verification system that forces user interaction.

**Reviewer notes:**
- The package is designed as an 'AI Girlfriend' assistant but includes dangerous capabilities like arbitrary file deletion, system command execution, and browser automation.
- The use of 'runas' to elevate privileges is highly suspicious for a standard Python package.
- The obfuscation of credentials suggests an attempt to hide the underlying service usage or prevent easy auditing of the API keys.
- The package relies on external AI models (Gemini/OpenAI) to drive these system-level tools, creating a significant risk if the model is prompted to perform malicious actions.

### Security Analysis of zoraai: High-Privilege Autonomous Assistant
- **Advisory:** `AUTH-2026-00004`
- **CWE:** `CWE-269`, `CWE-798`
- **Package:** `zoraai@1.2.1`
- **Severity:** `high`
- **Confidence:** `0.9`
- **Review:** `PENDING`

The package 'zoraai' contains extensive system-level automation capabilities, including mouse/keyboard control, file system manipulation, and browser automation. It also includes an 'activation' mechanism that requires a license key verified against a Firebase backend, and it attempts to elevate its own privileges to Administrator/Root on the host machine.

**Evidence:**
- `zoraai-1.2.1/nion_filesystem_agent.py` — Explicitly checks for and attempts to elevate to Administrator/Root privileges using ctypes.windll.shell32.ShellExecuteW.
- `zoraai-1.2.1/agent.py` — Contains obfuscated hardcoded API credentials and logic to run in the background as an invisible process.
- `zoraai-1.2.1/nion_keyboard_mouse_CTRL.py` — Provides tools for full mouse and keyboard control, including hotkey simulation and cursor movement, which can be triggered by the AI agent.
- `zoraai-1.2.1/nion_auth.py` — Implements a license verification system that communicates with a remote Firebase database, potentially tracking user activity or enforcing access control.

**Reviewer notes:**
- The package is designed as a highly autonomous AI assistant with broad system access. The combination of privilege escalation, background execution, and full GUI control presents a significant security risk if the AI model is compromised or manipulated via prompt injection.
- The 'activation' system and hardcoded credentials suggest a centralized control mechanism.
- The code is clearly intended for personal use but possesses capabilities that could be abused for malicious purposes if the package is installed in an untrusted environment.

### Security and Reliability Review of qcdrivers Instrument Drivers
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-703`, `CWE-798`
- **Package:** `qcdrivers@0.1.0`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package contains several instances of hardcoded IP addresses and potentially insecure network communication practices, particularly in the 'BlueFors' and 'Entropy' drivers. Additionally, the 'Heater' class implements a custom PID loop that uses 'time.sleep(1)' inside a 'while True' loop, which could lead to blocking behavior in a QCoDeS measurement environment.

**Evidence:**
- `src/qcdrivers/bluefors/fridges/fridges.py` — The driver uses hardcoded network parameters and performs HTTP requests to user-supplied IPs, which could be exploited if the instrument network is untrusted.
- `src/qcdrivers/entropy/adr/adr.py` — The driver uses raw TCP socket communication with hardcoded command strings and lacks robust error handling for socket timeouts or connection drops.
- `src/qcdrivers/entropy/heater/heater.py` — The 'set_T' method implements a PID loop with a blocking 'time.sleep(1)' call, which is generally discouraged in asynchronous QCoDeS instrument drivers.

**Reviewer notes:**
- The package appears to be a collection of specialized laboratory instrument drivers. The identified issues are common in academic/research code but represent potential reliability and security concerns in a production environment.
- The 'Heater' PID loop implementation should be reviewed for potential deadlocks or blocking issues during long-running measurements.
- The use of 'requests' without session management or strict timeout enforcement in some methods could lead to resource exhaustion.

### Security Analysis of zoraai: High-Risk System Automation and Privilege Escalation
- **Advisory:** `AUTH-2026-00006`
- **CWE:** `CWE-269`, `CWE-312`, `CWE-798`
- **Package:** `zoraai@1.2.1`
- **Severity:** `high`
- **Confidence:** `0.9`
- **Review:** `PENDING`

The package 'zoraai' contains extensive system-level automation capabilities, including mouse/keyboard control, file system manipulation, and browser automation, which are triggered by voice commands. It also includes an 'activation' mechanism that requires a license key, and it attempts to elevate its own privileges to Administrator/Root on the host machine.

**Evidence:**
- `nion_filesystem_agent.py` — Contains explicit code to check for and elevate privileges to Administrator/Root using ctypes and ShellExecuteW.
- `nion_keyboard_mouse_CTRL.py` — Implements a 'SafeController' that simulates mouse and keyboard input, which can be used to bypass user interaction for system tasks.
- `agent.py` — Contains obfuscated credentials (using XOR and base64) for various APIs, which is a common pattern for hiding sensitive information.
- `nion_social_messenger.py` — Uses Playwright with persistent user data directories to automate interactions with WhatsApp Web and Facebook, potentially exposing user sessions.

**Reviewer notes:**
- The package is designed as an 'AI Girlfriend' assistant, but its capabilities are highly intrusive.
- The use of 'nion_filesystem_agent.py' to force administrative privileges is a significant security risk.
- The obfuscation in 'agent.py' for API keys is unnecessary and suspicious.
- The package includes tools for automated email sending and social media posting, which could be abused if the AI is compromised.

## Omitted Results

96 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.

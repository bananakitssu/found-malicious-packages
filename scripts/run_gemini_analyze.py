#!/usr/bin/env python3
"""Run the Gemini scanner with additional obfuscation-focused review guidance."""

from scripts import gemini_analyze


gemini_analyze.ANALYSIS_SYSTEM_INSTRUCTION += """

OBFUSCATION AND SUSPICIOUS-RUNTIME GUIDANCE:
- Treat suspicious obfuscation as a reason for closer human review when it materially hinders security analysis.
- Pay attention to eval(), Function(), dynamic require/import, runtime-generated code, encoded or packed payloads, Base64/hex decoding, runtime decryption, and similar techniques when they conceal executable behavior.
- Do NOT treat ordinary minification, bundling, transpilation, generated code, or source maps as malicious by themselves.
- If suspicious behavior is present but its final intent cannot be established, it may still be reported as a potential_finding when the evidence supports a meaningful security concern. Clearly describe the uncertainty.
- Never claim that an obfuscated or encoded payload is malicious unless the supplied evidence demonstrates malicious behavior.
- Evidence must identify the relevant file and explain why the behavior is suspicious.
"""


if __name__ == "__main__":
    gemini_analyze.main()

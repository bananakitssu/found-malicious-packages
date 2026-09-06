#!/usr/bin/env python3
"""Add AI-proposed CWE classifications to pending Authtics advisories."""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from scripts.ecosystem import get_ecosystem

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
CWE_RE = re.compile(r"^CWE-[0-9]+$")
MAX_RETRIES = 5
ECOSYSTEM = get_ecosystem(os.environ.get("AUTHTICS_ECOSYSTEM", "npm"))

CWE_SYSTEM_INSTRUCTION = """
You are the strict JSON CWE-classification engine for Authtics Advisories.
Your output is machine-consumed. Follow the requested output schema exactly.

NON-NEGOTIABLE OUTPUT RULES:
1. Return EXACTLY ONE JSON OBJECT.
2. NEVER return a JSON array at the top level.
3. NEVER return Markdown, code fences, prose, explanations, or multiple JSON values outside the object.
4. Use only the fields defined by the schema. Do not add extra fields.
5. Every required field must be present, even when its value is empty.
6. The response must be valid JSON that can be parsed directly by json.loads().
7. CWE IDs are proposals for human review, not confirmed classifications.
8. Only select CWE IDs directly supported by the supplied advisory evidence.
9. Never invent a CWE ID. Do not infer a CWE merely because behavior sounds suspicious.
"""

CWE_RESPONSE_SCHEMA = {"type": "OBJECT", "properties": {
    "cwe_ids": {"type": "ARRAY", "items": {"type": "STRING"}},
    "cwe_notes": {"type": "ARRAY", "items": {"type": "STRING"}},
}, "required": ["cwe_ids", "cwe_notes"]}


def call_gemini(prompt):
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured")
    body = {"systemInstruction": {"parts": [{"text": CWE_SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.0, "responseMimeType": "application/json", "responseSchema": CWE_RESPONSE_SCHEMA}}
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(API_URL, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-goog-api-key": key, "User-Agent": "Authtics/0.1.0"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                data = json.load(response)
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt == MAX_RETRIES:
                raise
            print(f"Gemini CWE request returned HTTP {exc.code}; retrying ({attempt}/{MAX_RETRIES})...", file=sys.stderr)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == MAX_RETRIES:
                raise
            print(f"Gemini CWE request failed; retrying ({attempt}/{MAX_RETRIES}): {exc}", file=sys.stderr)
        time.sleep(min(2 ** (attempt - 1), 16))
    raise RuntimeError(f"Gemini CWE request failed after retries: {last_error}")


def classify(advisory):
    prompt = f"""
Classify the security behavior described in this ONE {ECOSYSTEM.display_name} advisory.

Return exactly one JSON object matching the supplied response schema.
The only fields are:
- cwe_ids: an array of standard CWE numeric identifiers such as "CWE-123"
- cwe_notes: an array of brief reasons corresponding to the proposed classifications

If no CWE clearly applies, return empty arrays.
Do not invent a CWE ID, and do not classify behavior that is not directly supported by the advisory evidence.

Advisory:
{json.dumps(advisory, indent=2)}
"""
    result = json.loads(call_gemini(prompt))
    if not isinstance(result, dict):
        raise ValueError(f"CWE response must be a JSON object, got {type(result).__name__}")
    extra_fields = set(result) - {"cwe_ids", "cwe_notes"}
    if extra_fields:
        raise ValueError(f"CWE response contains unexpected fields: {', '.join(sorted(extra_fields))}")
    ids, notes = result.get("cwe_ids"), result.get("cwe_notes")
    if not isinstance(ids, list) or not isinstance(notes, list):
        raise ValueError("CWE response fields must be arrays")
    if any(not isinstance(item, str) or not CWE_RE.fullmatch(item) for item in ids):
        raise ValueError("CWE response contains an invalid CWE ID")
    if any(not isinstance(item, str) for item in notes):
        raise ValueError("CWE response contains a non-string note")
    if len(ids) > 5:
        raise ValueError("CWE response contains more than 5 CWE IDs")
    return sorted(set(ids)), notes


def update_reports(advisories):
    reports = sorted(Path("reports").glob("*.md"))
    if not reports:
        return
    for report in reports:
        text = report.read_text(encoding="utf-8")
        for advisory_id, cwe_ids in advisories.items():
            marker = f"- **Advisory:** `{advisory_id}`"
            if marker not in text:
                continue
            cwe_line = f"- **CWE:** {', '.join(f'`{cwe}`' for cwe in cwe_ids) if cwe_ids else 'Not assigned'}"
            if cwe_line in text:
                continue
            text = text.replace(marker, marker + "\n" + cwe_line, 1)
        report.write_text(text, encoding="utf-8")


def main():
    root = Path("findings") / ECOSYSTEM.key
    if not root.exists():
        print(f"No {ECOSYSTEM.display_name} findings directory; nothing to classify.")
        return
    classified = {}
    for path in sorted(root.rglob("AUTH-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        review = data.get("database_specific", {}).get("review", {})
        if review.get("status") != "PENDING":
            continue
        try:
            ids, notes = classify(data)
            data.setdefault("database_specific", {})["cwe_ids"] = ids
            data["database_specific"]["cwe_notes"] = notes
            data["database_specific"]["cwe_status"] = "AI_PROPOSED"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            classified[data.get("id", path.stem)] = ids
            print(f"{path}: proposed CWE IDs: {', '.join(ids) if ids else 'none'}")
        except Exception as exc:
            print(f"{path}: CWE classification skipped: {exc}", file=sys.stderr)
            data.setdefault("database_specific", {})["cwe_ids"] = []
            data["database_specific"]["cwe_notes"] = [f"CWE classification unavailable: {exc}"]
            data["database_specific"]["cwe_status"] = "UNAVAILABLE"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            classified[data.get("id", path.stem)] = []
    update_reports(classified)


if __name__ == "__main__":
    main()

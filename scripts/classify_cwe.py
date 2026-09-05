#!/usr/bin/env python3
"""Add AI-proposed CWE classifications to pending Authtics advisories."""

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
CWE_RE = re.compile(r"^CWE-[0-9]+$")


def call_gemini(prompt):
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured")
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.0, "responseMimeType": "application/json"},
    }
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": key, "User-Agent": "Authtics/0.1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        data = json.load(response)
    return data["candidates"][0]["content"]["parts"][0]["text"]


def classify(advisory):
    prompt = f"""
You are a CWE classification assistant for Authtics Advisories.

Classify the security behavior described in this ONE advisory. CWE IDs are a proposal for a human reviewer, not a confirmed classification.
Only select CWE IDs that are directly supported by the advisory evidence. Do not infer a CWE merely because a behavior sounds suspicious.
If no CWE clearly applies, return an empty array.

Return JSON with exactly:
{{"cwe_ids": ["CWE-123"], "cwe_notes": ["brief reason for each proposed classification"]}}

Never invent a CWE ID. Use the standard CWE numeric identifier format.

Advisory:
{json.dumps(advisory, indent=2)}
"""
    result = json.loads(call_gemini(prompt))
    if not isinstance(result, dict):
        raise ValueError(f"CWE response must be a JSON object, got {type(result).__name__}")
    ids = result.get("cwe_ids", [])
    notes = result.get("cwe_notes", [])
    if not isinstance(ids, list) or not isinstance(notes, list):
        raise ValueError("CWE response fields must be arrays")
    ids = [item for item in ids if isinstance(item, str) and CWE_RE.fullmatch(item)]
    notes = [item for item in notes if isinstance(item, str)]
    if len(ids) > 5:
        ids = ids[:5]
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
            next_marker = "- **Confidence:**"
            if cwe_line in text:
                continue
            replacement = marker + "\n" + cwe_line
            text = text.replace(marker, replacement, 1)
        report.write_text(text, encoding="utf-8")


def main():
    root = Path("findings/npm")
    if not root.exists():
        print("No npm findings directory; nothing to classify.")
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
            # CWE classification is enrichment, so a classifier failure must not turn
            # a security finding into a different verdict or prevent human review.
            print(f"{path}: CWE classification skipped: {exc}", file=sys.stderr)
            data.setdefault("database_specific", {})["cwe_ids"] = []
            data["database_specific"]["cwe_notes"] = [f"CWE classification unavailable: {exc}"]
            data["database_specific"]["cwe_status"] = "UNAVAILABLE"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            classified[data.get("id", path.stem)] = []
    update_reports(classified)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.7-flash")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
MAX_FILE_CHARS = 12000
MAX_TOTAL_CHARS = 120000


def collect_evidence(package_dir):
    files = []
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(package_dir).as_posix()
        if rel.startswith(".git/"):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        files.append({"path": rel, "size": size})

    preferred = []
    extensions = {
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json",
        ".sh", ".bash", ".py", ".rb", ".php", ".ps1", ".yml", ".yaml",
    }
    interesting_names = {
        "package.json", "install.js", "postinstall.js", "preinstall.js",
        "index.js", "index.mjs", "cli.js",
    }

    for item in files:
        name = Path(item["path"]).name
        if name in interesting_names or Path(item["path"]).suffix.lower() in extensions:
            preferred.append(item)

    evidence = []
    total = 0
    for item in preferred:
        path = package_dir / item["path"]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS] + "\n...[file truncated]..."
        if total + len(text) > MAX_TOTAL_CHARS:
            break
        evidence.append({"path": item["path"], "content": text})
        total += len(text)

    return files, evidence


def call_gemini(prompt):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured")

    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
            "User-Agent": "Authtics/0.1.0",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=180) as response:
        data = json.load(response)

    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected Gemini response: {json.dumps(data)[:4000]}") from exc


def parse_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        raise


def main():
    metadata_path = Path("metadata/recent-packages.json")
    if not metadata_path.exists():
        raise RuntimeError("metadata/recent-packages.json does not exist")

    packages = json.loads(metadata_path.read_text())
    findings_dir = Path("findings")
    findings_dir.mkdir(parents=True, exist_ok=True)

    for package in packages:
        name = package["name"]
        version = package["version"]
        safe_name = name.replace("/", "__").replace("@", "")
        package_dir = Path("packages") / "npm" / name / version

        if not package_dir.exists():
            print(f"Skipping {name}@{version}: package directory not found")
            continue

        files, evidence = collect_evidence(package_dir)
        prompt = f"""
You are the analysis engine for Authtics Advisories, a security advisory project.

Analyze ONE npm package version using only the supplied evidence. Do not execute code.
Do not assume that suspicious-looking code is malicious. Distinguish legitimate
functionality, dangerous functionality, and actual evidence of malicious intent.
The result is a DRAFT for a human security reviewer. It must never claim that the
package is confirmed malicious solely because an AI suspects it.

Package: {name}@{version}
Published: {package.get('published', 'unknown')}

Return JSON with exactly these fields:
- verdict: one of "no_obvious_issue", "potential_finding", "insufficient_evidence"
- confidence: number from 0 to 1
- summary: concise explanation
- suspicious_behaviors: array of concrete observed behaviors
- evidence: array of objects with "file" and "reason"
- reviewer_notes: array of questions or checks for the human reviewer
- draft_title: proposed advisory title, or empty string if no potential finding

IMPORTANT: Never invent files, behavior, vulnerabilities, CVEs, package ownership,
or intent. If the supplied evidence is incomplete, say so.

FILE INVENTORY:
{json.dumps(files, indent=2)}

SELECTED FILE CONTENT:
{json.dumps(evidence, indent=2)}
"""

        print(f"Analyzing {name}@{version} with {MODEL}...")
        raw = call_gemini(prompt)
        result = parse_json(raw)

        result["package"] = name
        result["version"] = version
        result["published"] = package.get("published")
        result["status"] = "PENDING_REVIEW"
        result["model"] = MODEL

        output = findings_dir / f"{safe_name}-{version}.json"
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Gemini analysis failed: {exc}", file=sys.stderr)
        sys.exit(1)

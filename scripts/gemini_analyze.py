#!/usr/bin/env python3
"""Run the Gemini security analyzer for a configured package ecosystem."""

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from scripts.ecosystem import get_ecosystem

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
PACKAGE_ROOT = Path(os.environ.get("AUTHTICS_PACKAGE_ROOT", "/tmp/authtics-packages/extracted"))
FINDINGS_ROOT = Path("findings")
REPORT_ROOT = Path("reports")
SCAN_STATE = Path("metadata/scan-state.json")
MAX_FILE_CHARS = 12000
MAX_TOTAL_CHARS = 120000
MAX_RETRIES = 5
RATE_LIMIT_MAX_RETRIES = 3
REQUEST_DELAY_SECONDS = 1
SEVERITIES = {"critical", "high", "medium", "low", "n/a"}
ECOSYSTEM_NAME = os.environ.get("AUTHTICS_ECOSYSTEM", "npm")
ECOSYSTEM = get_ecosystem(ECOSYSTEM_NAME)

ANALYSIS_SYSTEM_INSTRUCTION = """
You are the strict JSON security-analysis engine for Authtics Advisories.
Your output is machine-consumed. Follow the requested output schema exactly.

NON-NEGOTIABLE OUTPUT RULES:
1. Return EXACTLY ONE JSON OBJECT.
2. NEVER return a JSON array at the top level.
3. NEVER return Markdown, code fences, prose, explanations, or multiple JSON values outside the object.
4. Use only the fields defined by the schema. Do not add extra fields.
5. Every required field must be present, even when its value is empty.
6. The response must be valid JSON that can be parsed directly by json.loads().
7. The result is a draft for human review. Never claim confirmed malicious intent solely from suspicion.
8. Analyze only the exact package version and supplied evidence. Do not import historical vulnerabilities from other versions without evidence they still apply.

OBFUSCATION AND SUSPICIOUS-DYNAMIC-BEHAVIOR GUIDANCE:
- Flag eval(), Function(), dynamic require/import, runtime-generated code, encoded strings,
  Base64/hex payloads, runtime decryption, or similar techniques when they materially hinder
  security analysis.
- Do NOT treat ordinary minification, bundling, transpilation, or generated files as malicious
  by themselves.
- If suspicious behavior is present but the final intent or payload cannot be established, it
  may still be a potential_finding for human review.
- Explain uncertainty clearly. Never claim a hidden payload is malicious without evidence showing
  harmful behavior.
"""

ANALYSIS_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "verdict": {"type": "STRING", "enum": ["no_obvious_issue", "potential_finding", "insufficient_evidence"]},
        "severity": {"type": "STRING", "enum": ["critical", "high", "medium", "low", "n/a"]},
        "confidence": {"type": "NUMBER", "minimum": 0, "maximum": 1},
        "summary": {"type": "STRING"},
        "suspicious_behaviors": {"type": "ARRAY", "items": {"type": "STRING"}},
        "evidence": {"type": "ARRAY", "items": {"type": "OBJECT", "properties": {
            "file": {"type": "STRING"}, "reason": {"type": "STRING"}}, "required": ["file", "reason"]}},
        "reviewer_notes": {"type": "ARRAY", "items": {"type": "STRING"}},
        "draft_title": {"type": "STRING"},
    },
    "required": ["verdict", "severity", "confidence", "summary", "suspicious_behaviors", "evidence", "reviewer_notes", "draft_title"],
}


def collect_evidence(package_dir):
    files = []
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(package_dir).as_posix()
        if rel.startswith(".git/"):
            continue
        if path.suffix.lower() in ECOSYSTEM.source_extensions or path.name in {
            ECOSYSTEM.package_manifest,
            *ECOSYSTEM.install_script_names,
            "index.js", "index.mjs", "index.py", "cli.js", "cli.py",
        }:
            files.append(path)
    evidence = []
    total = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS] + "\n[truncated]"
        if total + len(text) > MAX_TOTAL_CHARS:
            break
        evidence.append((path.relative_to(package_dir).as_posix(), text))
        total += len(text)
    return files, evidence


def call_gemini(prompt):
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured")
    body = {"systemInstruction": {"parts": [{"text": ANALYSIS_SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json", "responseSchema": ANALYSIS_RESPONSE_SCHEMA}}
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(API_URL, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-goog-api-key": key, "User-Agent": "Authtics/0.1.0"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                data = json.load(response)
            time.sleep(REQUEST_DELAY_SECONDS)
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code == 429:
                if attempt > RATE_LIMIT_MAX_RETRIES:
                    raise
                retry_after = exc.headers.get("Retry-After")
                delay = int(retry_after) if retry_after and retry_after.isdigit() else min(5 * (2 ** (attempt - 1)), 60)
                print(f"Gemini returned HTTP 429; retrying in {delay}s (attempt {attempt}/{RATE_LIMIT_MAX_RETRIES})")
                time.sleep(delay)
                continue
            if exc.code not in {500, 502, 503, 504} or attempt == MAX_RETRIES:
                raise
            delay = min(5 * (2 ** (attempt - 1)), 60)
            print(f"Gemini returned HTTP {exc.code}; retrying in {delay}s (attempt {attempt}/{MAX_RETRIES})")
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == MAX_RETRIES:
                raise
            delay = min(5 * (2 ** (attempt - 1)), 60)
            print(f"Gemini request failed; retrying in {delay}s (attempt {attempt}/{MAX_RETRIES}): {exc}")
            time.sleep(delay)
    raise RuntimeError(f"Gemini request failed after retries: {last_error}")


def parse_result(raw, package):
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Gemini response must be a JSON object")
    required = set(ANALYSIS_RESPONSE_SCHEMA["required"])
    if set(result) != required:
        raise ValueError(f"Gemini response fields mismatch: expected {sorted(required)}, got {sorted(result)}")
    if result["verdict"] not in {"no_obvious_issue", "potential_finding", "insufficient_evidence"}:
        raise ValueError("Invalid verdict")
    if result["severity"] not in SEVERITIES:
        raise ValueError("Invalid severity")
    if not isinstance(result["confidence"], (int, float)) or not 0 <= result["confidence"] <= 1:
        raise ValueError("Invalid confidence")
    for field in ("summary", "draft_title"):
        if not isinstance(result[field], str):
            raise ValueError(f"Invalid {field}")
    for field in ("suspicious_behaviors", "evidence", "reviewer_notes"):
        if not isinstance(result[field], list):
            raise ValueError(f"Invalid {field}")
    for item in result["evidence"]:
        if not isinstance(item, dict) or set(item) != {"file", "reason"}:
            raise ValueError("Invalid evidence item")
    return result


def metadata_path():
    if ECOSYSTEM.key == "npm":
        return Path("metadata/recent-packages.json")
    return Path(f"metadata/{ECOSYSTEM.key}-recent-packages.json")


def failed_result(package, reason):
    return {"package": package["name"], "version": package["version"], "verdict": "insufficient_evidence", "severity": "n/a", "confidence": 0.0,
            "summary": reason, "suspicious_behaviors": [], "evidence": [], "reviewer_notes": [reason], "draft_title": ""}


def next_advisory_id():
    """Return the next globally unused AUTH advisory ID for the current year."""
    year = datetime.now(timezone.utc).year
    maximum = 0
    pattern = re.compile(rf"^AUTH-{year}-(\d{{5}})\.json$")
    if FINDINGS_ROOT.exists():
        for path in FINDINGS_ROOT.rglob(f"AUTH-{year}-*.json"):
            match = pattern.match(path.name)
            if match:
                maximum = max(maximum, int(match.group(1)))
    return f"AUTH-{year}-{maximum + 1:05d}"


def write_outputs(results):
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    FINDINGS_ROOT.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    report_path = REPORT_ROOT / f"authtics-report-{now.strftime('%Y-%m-%dT%H-%M-%SZ')}.md"
    advisory_files = []
    lines = [f"# Authtics {ECOSYSTEM.display_name} Security Scan", "", f"Generated: {now.isoformat()}", ""]
    omitted = []
    for result in results:
        if result["severity"] == "n/a":
            omitted.append(result)
            continue
        advisory_id = next_advisory_id()
        package = result["package"]
        version = result["version"]
        ref = (f"https://www.npmjs.com/package/{package}/v/{version}" if ECOSYSTEM.key == "npm"
               else f"https://pypi.org/project/{re.sub(r'[-_.]+', '-', package).lower()}/{version}/")
        advisory = {
            "schema_version": "1.0", "id": advisory_id, "published": now.isoformat(), "modified": now.isoformat(),
            "summary": result["draft_title"] or result["summary"], "details": result["summary"], "severity": result["severity"],
            "affected": [{"package": {"ecosystem": ECOSYSTEM.advisory_ecosystem, "name": package}, "versions": [version]}],
            "references": [{"type": "PACKAGE", "url": ref}],
            "database_specific": {"source": "Authtics Advisories", "model": MODEL, "confidence": result["confidence"],
                "review": {"status": "PENDING", "human_review_required": True},
                "suspicious_behaviors": result["suspicious_behaviors"], "evidence": result["evidence"], "reviewer_notes": result["reviewer_notes"]},
        }
        path = FINDINGS_ROOT / ECOSYSTEM.key / package / f"{advisory_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(advisory, indent=2) + "\n", encoding="utf-8")
        advisory_files.append(str(path))
        lines.extend([f"### {advisory['summary']}", f"- **Advisory:** `{advisory_id}`", f"- **Package:** `{package}@{version}`",
                      f"- **Severity:** `{result['severity']}`", f"- **Confidence:** `{result['confidence']}`", "- **Review:** `PENDING`", "",
                      result["summary"], ""])
        if result.get("evidence"):
            lines.append("**Evidence:**")
            lines.extend(f"- `{item['file']}` — {item['reason']}" for item in result["evidence"])
            lines.append("")
        if result.get("reviewer_notes"):
            lines.append("**Reviewer notes:**")
            lines.extend(f"- {note}" for note in result["reviewer_notes"])
            lines.append("")
    if omitted:
        lines.extend(["## Omitted Results", "", f"{len(omitted)} result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.", ""])
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {report_path}")
    print(f"Wrote {len(advisory_files)} advisory file(s) under findings/{ECOSYSTEM.key}/")
    return advisory_files


def main():
    metadata = metadata_path()
    if not metadata.exists():
        raise FileNotFoundError(f"Missing metadata file: {metadata}")
    metadata_data = json.loads(metadata.read_text(encoding="utf-8"))
    if isinstance(metadata_data, list):
        packages = metadata_data
    elif isinstance(metadata_data, dict) and isinstance(metadata_data.get("packages"), list):
        packages = metadata_data["packages"]
    else:
        raise RuntimeError(f"{metadata} must contain a JSON array or an object with a 'packages' array")

    all_results = []
    for package in packages:
        name = package["name"]
        version = package["version"]
        package_dir = PACKAGE_ROOT / name / version
        print(f"Analyzing {name}@{version} with {MODEL}...", flush=True)
        try:
            _, evidence = collect_evidence(package_dir)
            prompt = f"Analyze the exact {ECOSYSTEM.display_name} package {name}@{version}.\n\n"
            prompt += "Do not execute package code. Analyze only the supplied static evidence.\n\n"
            if evidence:
                for rel, text in evidence:
                    prompt += f"FILE: {rel}\n{text}\n\n"
            else:
                prompt += "No supported source files were available for analysis.\n"
            result = parse_result(call_gemini(prompt), package)
        except Exception as exc:
            print(f"Analysis failed for {name}@{version}: {exc}", flush=True)
            result = failed_result(package, f"Analysis failed: {exc}")
        result["package"] = name
        result["version"] = version
        all_results.append(result)

    write_outputs(all_results)


if __name__ == "__main__":
    main()

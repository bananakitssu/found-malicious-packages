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
        try:
            size = path.stat().st_size
        except OSError:
            continue
        files.append({"path": rel, "size": size})

    extensions = set(ECOSYSTEM.source_extensions)
    extensions.update({".yml", ".yaml"})
    interesting_names = {
        ECOSYSTEM.package_manifest,
        *ECOSYSTEM.install_script_names,
        "index.js", "index.mjs", "index.py", "cli.js", "cli.py",
    }
    preferred = [item for item in files if Path(item["path"]).name in interesting_names or Path(item["path"]).suffix.lower() in extensions]

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
        "systemInstruction": {"parts": [{"text": ANALYSIS_SYSTEM_INSTRUCTION}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json", "responseSchema": ANALYSIS_RESPONSE_SCHEMA},
    }
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(
            API_URL, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-goog-api-key": api_key, "User-Agent": "Authtics/0.1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                data = json.load(response)
            time.sleep(REQUEST_DELAY_SECONDS)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                if attempt >= RATE_LIMIT_MAX_RETRIES:
                    raise RuntimeError(f"Gemini rate limit persisted after {RATE_LIMIT_MAX_RETRIES} attempts") from exc
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    delay = max(1, float(retry_after)) if retry_after else min(60, 2 ** (attempt - 1) * 5)
                except (TypeError, ValueError):
                    delay = min(60, 2 ** (attempt - 1) * 5)
                print(f"Gemini returned HTTP 429; retrying in {delay:g}s (attempt {attempt}/{RATE_LIMIT_MAX_RETRIES})", flush=True)
                time.sleep(delay)
                continue
            if exc.code not in {500, 502, 503, 504} or attempt == MAX_RETRIES:
                raise
            delay = min(60, 2 ** (attempt - 1) * 5)
            print(f"Gemini returned HTTP {exc.code}; retrying in {delay}s (attempt {attempt}/{MAX_RETRIES})", flush=True)
            time.sleep(delay)
        except urllib.error.URLError as exc:
            if attempt == MAX_RETRIES:
                raise
            delay = min(60, 2 ** (attempt - 1) * 5)
            print(f"Gemini network error: {exc}; retrying in {delay}s (attempt {attempt}/{MAX_RETRIES})", flush=True)
            time.sleep(delay)
    else:
        raise RuntimeError("Gemini request exhausted all retries")
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Unexpected Gemini response: {json.dumps(data)[:4000]}") from exc


def parse_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        raise


def validate_result(result):
    if not isinstance(result, dict):
        raise RuntimeError(f"Unexpected Gemini analysis shape: expected JSON object, got {type(result).__name__}")
    required = {"verdict", "severity", "confidence", "summary", "suspicious_behaviors", "evidence", "reviewer_notes", "draft_title"}
    missing = sorted(required - result.keys())
    if missing:
        raise RuntimeError(f"Gemini analysis missing required fields: {', '.join(missing)}")
    if result["verdict"] not in {"no_obvious_issue", "potential_finding", "insufficient_evidence"}:
        raise RuntimeError(f"Invalid Gemini verdict: {result['verdict']!r}")
    if result["severity"] not in SEVERITIES:
        raise RuntimeError(f"Invalid Gemini severity: {result['severity']!r}")
    if not isinstance(result["confidence"], (int, float)) or isinstance(result["confidence"], bool) or not 0 <= result["confidence"] <= 1:
        raise RuntimeError("Gemini confidence must be a number between 0 and 1")
    for field in ("summary", "draft_title"):
        if not isinstance(result[field], str):
            raise RuntimeError(f"Gemini field {field!r} must be a string")
    for field in ("suspicious_behaviors", "reviewer_notes", "evidence"):
        if not isinstance(result[field], list):
            raise RuntimeError(f"Gemini field {field!r} must be an array")
    for index, item in enumerate(result["evidence"]):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str) or not isinstance(item.get("reason"), str):
            raise RuntimeError(f"Gemini evidence[{index}] must contain string 'file' and 'reason' fields")
    if result["verdict"] in {"no_obvious_issue", "insufficient_evidence"} and result["severity"] != "n/a":
        raise RuntimeError(f"A {result['verdict']} result must have severity n/a")
    if result["verdict"] == "potential_finding" and result["severity"] == "n/a":
        raise RuntimeError("A potential_finding result must have a real severity")
    return result


def failed_result(package, error):
    return {"package": package["name"], "version": package["version"], "published": package.get("published"),
            "status": "ANALYSIS_FAILED", "verdict": "insufficient_evidence", "severity": "n/a", "confidence": 0,
            "summary": "Gemini analysis could not be completed. This is not a security finding.",
            "suspicious_behaviors": [], "evidence": [], "reviewer_notes": [f"Analysis engine error: {error}"],
            "draft_title": "", "model": MODEL, "review": {"status": "PENDING"}}


def next_advisory_id():
    year = datetime.now(timezone.utc).year
    maximum = 0
    pattern = re.compile(rf"^AUTH-{year}-(\d{{5}})\.json$")
    if FINDINGS_ROOT.exists():
        for path in FINDINGS_ROOT.rglob(f"AUTH-{year}-*.json"):
            match = pattern.match(path.name)
            if match:
                maximum = max(maximum, int(match.group(1)))
    return f"AUTH-{year}-{maximum + 1:05d}"


def package_path(name):
    return FINDINGS_ROOT / ECOSYSTEM.key / Path(*name.split("/"))


def package_reference(name, version):
    if ECOSYSTEM.key == "npm":
        return f"https://www.npmjs.com/package/{name}/v/{version}"
    if ECOSYSTEM.key == "pypi":
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        return f"https://pypi.org/project/{normalized}/{version}/"
    raise ValueError(f"Unsupported ecosystem: {ECOSYSTEM.key}")


def build_advisory(result, advisory_id, timestamp):
    package = result["package"]
    version = result["version"]
    details = result["summary"]
    if result.get("suspicious_behaviors"):
        details += "\n\nObserved behaviors:\n" + "\n".join(f"- {item}" for item in result["suspicious_behaviors"])
    if result.get("evidence"):
        details += "\n\nEvidence:\n" + "\n".join(f"- `{item['file']}` — {item['reason']}" for item in result["evidence"])
    return {
        "schema_version": "1.0", "id": advisory_id, "published": timestamp, "modified": timestamp,
        "summary": result["draft_title"] or f"Potential malicious or dangerous behavior in {package} ({ECOSYSTEM.display_name})",
        "details": details, "severity": result["severity"],
        "affected": [{"package": {"ecosystem": ECOSYSTEM.advisory_ecosystem, "name": package}, "versions": [version]}],
        "references": [{"type": "PACKAGE", "url": package_reference(package, version)}],
        "database_specific": {"source": "Authtics Advisories", "model": MODEL, "confidence": result["confidence"],
                              "review": {"status": "PENDING", "human_review_required": True}},
    }


def metadata_path():
    # Keep the established npm metadata filename for compatibility; ecosystem-specific
    # workflows use their own filename so they can run independently.
    if ECOSYSTEM.key == "npm":
        return Path("metadata/recent-packages.json")
    return Path(f"metadata/{ECOSYSTEM.key}-recent-packages.json")


def write_report(all_results, timestamp):
    actionable = [r for r in all_results if r.get("severity") != "n/a" and r.get("status") == "PENDING_REVIEW"]
    omitted = [r for r in all_results if r not in actionable]
    if not actionable:
        print("No actionable findings. All results are severity n/a; no report or advisory files will be committed.")
        return []

    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_ROOT / f"authtics-report-{timestamp.replace(':', '-').replace('+', '-')}.md"
    lines = [f"# Authtics {ECOSYSTEM.display_name} Security Scan", "", f"Generated: {timestamp}", f"Model: `{MODEL}`", "", "## Findings", ""]
    advisory_files = []
    for result in actionable:
        advisory_id = next_advisory_id()
        advisory = build_advisory(result, advisory_id, timestamp)
        directory = package_path(result["package"])
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{advisory_id}.json"
        path.write_text(json.dumps(advisory, indent=2) + "\n", encoding="utf-8")
        advisory_files.append(str(path))
        lines.extend([f"### {advisory['summary']}", f"- **Advisory:** `{advisory_id}`", f"- **Package:** `{result['package']}@{result['version']}`",
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
        raise RuntimeError(f"{metadata} does not exist")
    packages = json.loads(metadata.read_text(encoding="utf-8"))
    if not isinstance(packages, list):
        raise RuntimeError(f"{metadata} must contain a JSON array")
    all_results = []
    for package in packages:
        name, version = package["name"], package["version"]
        package_dir = PACKAGE_ROOT / name / version
        if not package_dir.exists():
            print(f"Skipping {name}@{version}: package directory not found", flush=True)
            all_results.append(failed_result(package, "package directory not found"))
            continue
        files, evidence = collect_evidence(package_dir)
        prompt = f"""
Analyze the exact {ECOSYSTEM.display_name} package version below using only the supplied evidence.
Do not execute code. Distinguish legitimate functionality, dangerous functionality, and actual evidence of malicious intent.
The result is a DRAFT for a human security reviewer.

Package: {name}@{version}
Published: {package.get('published', 'unknown')}
Ecosystem: {ECOSYSTEM.display_name}

Return exactly one JSON object matching the supplied response schema. Do not return an array.

Severity guidance:
- critical: strong evidence of severe malicious behavior or remote code execution with major impact
- high: serious security or malicious behavior with substantial impact
- medium: meaningful security risk with limited scope or stronger mitigating factors
- low: minor or lower-impact suspicious/security behavior
- n/a: no actionable finding or insufficient evidence

Historical issues must not be applied to this exact version without evidence that they still exist.
Never invent files, behavior, vulnerabilities, CVEs, package ownership, or intent.
Do not claim a package is safe or free of security issues.
If the evidence does not establish an actionable finding, use verdict "no_obvious_issue" or "insufficient_evidence" and severity "n/a".
If verdict is "potential_finding", severity MUST be critical/high/medium/low.

OBFUSCATION AND SUSPICIOUS-DYNAMIC-BEHAVIOR GUIDANCE:
- Flag eval(), Function(), dynamic imports, runtime-generated code, encoded strings,
  Base64/hex payloads, runtime decryption, or similar techniques when they materially hinder
  security analysis. For Python, also consider exec(), eval(), dynamic import mechanisms,
  subprocess usage, shell execution, and suspicious package-install hooks.
- Do NOT treat ordinary minification, bundling, transpilation, generated files, packaging metadata,
  or normal build/install configuration as malicious by themselves.
- If suspicious behavior is present but the final intent or payload cannot be established, it
  may still be a potential_finding for human review.
- Explain uncertainty clearly. Never claim a hidden payload is malicious without evidence showing harmful behavior.

FILE INVENTORY:
{json.dumps(files, indent=2)}

SELECTED FILE CONTENT:
{json.dumps(evidence, indent=2)}
"""
        print(f"Analyzing {name}@{version} with {MODEL}...", flush=True)
        try:
            result = validate_result(parse_json(call_gemini(prompt)))
            result.update({"package": name, "version": version, "published": package.get("published"), "status": "PENDING_REVIEW", "model": MODEL, "review": {"status": "PENDING"}})
        except Exception as exc:
            print(f"Analysis failed for {name}@{version}: {exc}", flush=True)
            result = failed_result(package, exc)
        all_results.append(result)

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    advisory_files = write_report(all_results, timestamp)
    SCAN_STATE.parent.mkdir(parents=True, exist_ok=True)
    SCAN_STATE.write_text(json.dumps({"last_scan": timestamp, "ecosystem": ECOSYSTEM.key, "model": MODEL,
                                      "packages_scanned": len(packages), "advisories_written": len(advisory_files)}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

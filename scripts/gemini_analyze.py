#!/usr/bin/env python3
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
PACKAGE_ROOT = Path(os.environ.get("AUTHTICS_PACKAGE_ROOT", "/tmp/authtics-packages/extracted"))
FINDINGS_ROOT = Path("findings")
REPORT_ROOT = Path("reports")
SCAN_STATE = Path("metadata/scan-state.json")
MAX_FILE_CHARS = 12000
MAX_TOTAL_CHARS = 120000
MAX_RETRIES = 5
SEVERITIES = {"critical", "high", "medium", "low", "n/a"}


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

    extensions = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".sh", ".bash", ".py", ".rb", ".php", ".ps1", ".yml", ".yaml"}
    interesting_names = {"package.json", "install.js", "postinstall.js", "preinstall.js", "index.js", "index.mjs", "cli.js"}
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
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(
            API_URL,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-goog-api-key": api_key, "User-Agent": "Authtics/0.1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                data = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == MAX_RETRIES:
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
    if result["verdict"] == "no_obvious_issue" and result["severity"] != "n/a":
        raise RuntimeError("A no_obvious_issue result must have severity n/a")
    if result["verdict"] == "insufficient_evidence" and result["severity"] != "n/a":
        raise RuntimeError("An insufficient_evidence result must have severity n/a")
    if result["verdict"] == "potential_finding" and result["severity"] == "n/a":
        raise RuntimeError("A potential_finding result must have a real severity")
    return result


def failed_result(package, error):
    return {
        "package": package["name"], "version": package["version"], "published": package.get("published"),
        "status": "ANALYSIS_FAILED", "verdict": "insufficient_evidence", "severity": "n/a", "confidence": 0,
        "summary": "Gemini analysis could not be completed. This is not a security finding.",
        "suspicious_behaviors": [], "evidence": [], "reviewer_notes": [f"Analysis engine error: {error}"],
        "draft_title": "", "model": MODEL, "review": {"status": "PENDING"},
    }


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
    return FINDINGS_ROOT / "npm" / Path(*name.split("/"))


def build_advisory(result, advisory_id, timestamp):
    package = result["package"]
    version = result["version"]
    details = result["summary"]
    if result.get("suspicious_behaviors"):
        details += "\n\nObserved behaviors:\n" + "\n".join(f"- {item}" for item in result["suspicious_behaviors"])
    if result.get("evidence"):
        details += "\n\nEvidence:\n" + "\n".join(f"- `{item['file']}` — {item['reason']}" for item in result["evidence"])
    return {
        "schema_version": "1.0",
        "id": advisory_id,
        "published": timestamp,
        "modified": timestamp,
        "summary": result["draft_title"] or f"Potential malicious or dangerous behavior in {package} (npm)",
        "details": details,
        "severity": result["severity"],
        "affected": [{"package": {"ecosystem": "npm", "name": package}, "versions": [version]}],
        "references": [{"type": "PACKAGE", "url": f"https://www.npmjs.com/package/{package}/v/{version}"}],
        "database_specific": {
            "source": "Authtics Advisories",
            "model": MODEL,
            "confidence": result["confidence"],
            "review": {"status": "PENDING", "human_review_required": True},
        },
    }


def main():
    metadata_path = Path("metadata/recent-packages.json")
    if not metadata_path.exists():
        raise RuntimeError("metadata/recent-packages.json does not exist")
    packages = json.loads(metadata_path.read_text())
    all_results = []

    for package in packages:
        name = package["name"]
        version = package["version"]
        package_dir = PACKAGE_ROOT / name / version
        if not package_dir.exists():
            print(f"Skipping {name}@{version}: package directory not found", flush=True)
            all_results.append(failed_result(package, "package directory not found"))
            continue
        files, evidence = collect_evidence(package_dir)
        prompt = f"""
You are the analysis engine for Authtics Advisories, a security advisory project.

Analyze ONE exact npm package version using only the supplied evidence. Do not execute code.
Distinguish legitimate functionality, dangerous functionality, and actual evidence of malicious intent.
The result is a DRAFT for a human security reviewer and must never claim confirmed maliciousness solely because AI suspects it.

Package: {name}@{version}
Published: {package.get('published', 'unknown')}

Return JSON with exactly these fields:
- verdict: one of "no_obvious_issue", "potential_finding", "insufficient_evidence"
- severity: one of "critical", "high", "medium", "low", "n/a"
- confidence: number from 0 to 1
- summary: concise explanation based only on observed evidence
- suspicious_behaviors: array of concrete observed behaviors
- evidence: array of objects with "file" and "reason"
- reviewer_notes: array of questions or checks for the human reviewer
- draft_title: proposed advisory title, or empty string when severity is n/a

Severity guidance:
- critical: strong evidence of severe malicious behavior or remote code execution with major impact
- high: serious security or malicious behavior with substantial impact
- medium: meaningful security risk with limited scope or stronger mitigating factors
- low: minor or lower-impact suspicious/security behavior
- n/a: no actionable finding or insufficient evidence

IMPORTANT: Historical issues must not be applied to this exact version without evidence that they still exist.
Never invent files, behavior, vulnerabilities, CVEs, package ownership, or intent.
Do not claim a package is safe or free of security issues.
If the evidence does not establish an actionable finding, use verdict "no_obvious_issue" or "insufficient_evidence" and severity "n/a".
If verdict is "potential_finding", severity MUST be critical/high/medium/low.

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
            print(f"Gemini analysis failed for {name}@{version}: {exc}", file=sys.stderr, flush=True)
            result = failed_result(package, str(exc))
        all_results.append(result)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings = [r for r in all_results if r.get("severity") != "n/a" and r.get("status") == "PENDING_REVIEW"]
    omitted = [r for r in all_results if r not in findings]

    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    FINDINGS_ROOT.mkdir(parents=True, exist_ok=True)
    Path("metadata").mkdir(parents=True, exist_ok=True)
    state = {"generated": timestamp, "model": MODEL, "packages_analyzed": len(all_results), "findings_count": len(findings), "omitted_n_a": len(omitted)}
    SCAN_STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    if not findings:
        print("No actionable findings. All results are severity n/a; no report or advisory files will be committed.")
        return

    advisory_records = []
    for result in findings:
        advisory_id = next_advisory_id()
        advisory = build_advisory(result, advisory_id, timestamp)
        destination = package_path(result["package"]) / f"{advisory_id}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(advisory, indent=2) + "\n", encoding="utf-8")
        result["advisory_id"] = advisory_id
        result["advisory_path"] = destination.as_posix()
        advisory_records.append(result)

    report_path = REPORT_ROOT / f"authtics-report-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')}.md"
    lines = [
        "# Authtics Advisories — Package Scan Report", "", f"**Generated:** {timestamp}", f"**Model:** `{MODEL}`",
        f"**Packages analyzed:** {len(all_results)}", f"**Actionable findings:** {len(findings)}", "",
        "> AI-generated draft. Every advisory requires human review before publication.", "",
    ]
    for index, result in enumerate(advisory_records, 1):
        lines += [
            "---", "", f"## {index}. `{result['package']}@{result['version']}`", "",
            f"- **Advisory:** `{result['advisory_id']}`", f"- **Severity:** `{result['severity']}`",
            f"- **Confidence:** {result['confidence']}", "- **Review:** `PENDING`", "",
            "### Summary", "", result["summary"], "", "### Evidence", "",
        ]
        if result["evidence"]:
            lines += [f"- `{item['file']}` — {item['reason']}" for item in result["evidence"]]
        else:
            lines.append("- None reported.")
        lines += ["", "### Reviewer Notes", ""]
        lines += [f"- {item}" for item in (result.get("reviewer_notes") or ["None."])]
        lines += [""]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {report_path}")
    print(f"Wrote {len(findings)} advisory file(s) under findings/npm/")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Gemini analysis failed: {exc}", file=sys.stderr)
        sys.exit(1)

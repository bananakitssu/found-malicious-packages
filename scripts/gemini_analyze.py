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
MAX_FILE_CHARS = 12000
MAX_TOTAL_CHARS = 120000
MAX_RETRIES = 5


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

    for attempt in range(1, MAX_RETRIES + 1):
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


def failed_result(package, error):
    return {
        "package": package["name"],
        "version": package["version"],
        "published": package.get("published"),
        "status": "ANALYSIS_FAILED",
        "verdict": "insufficient_evidence",
        "confidence": 0,
        "summary": "Gemini analysis could not be completed. This is not a security finding.",
        "suspicious_behaviors": [],
        "evidence": [],
        "reviewer_notes": [f"Analysis engine error: {error}"],
        "draft_title": "",
        "model": MODEL,
        "review": {"status": "PENDING"},
    }


def main():
    metadata_path = Path("metadata/recent-packages.json")
    if not metadata_path.exists():
        raise RuntimeError("metadata/recent-packages.json does not exist")

    packages = json.loads(metadata_path.read_text())
    results = []

    for package in packages:
        name = package["name"]
        version = package["version"]
        package_dir = PACKAGE_ROOT / name / version

        if not package_dir.exists():
            print(f"Skipping {name}@{version}: package directory not found", flush=True)
            results.append(failed_result(package, "package directory not found"))
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
- summary: concise explanation based only on observed evidence
- suspicious_behaviors: array of concrete observed behaviors; do not say "none" unless the inspected evidence supports that conclusion
- evidence: array of objects with "file" and "reason"
- reviewer_notes: array of questions or checks for the human reviewer
- draft_title: proposed advisory title, or empty string if no potential finding

IMPORTANT: Never invent files, behavior, vulnerabilities, CVEs, package ownership,
or intent. Do not claim a package is safe, secure, benign, or free of security issues.
Do not claim that a behavior is absent unless the supplied evidence actually establishes
that absence. If the supplied evidence is incomplete, say so. Historical issues must
not be applied to this exact version without evidence that they still exist.

FILE INVENTORY:
{json.dumps(files, indent=2)}

SELECTED FILE CONTENT:
{json.dumps(evidence, indent=2)}
"""

        print(f"Analyzing {name}@{version} with {MODEL}...", flush=True)
        try:
            result = parse_json(call_gemini(prompt))
            result["package"] = name
            result["version"] = version
            result["published"] = package.get("published")
            result["status"] = "PENDING_REVIEW"
            result["model"] = MODEL
            result["review"] = {"status": "PENDING"}
        except Exception as exc:
            print(f"Gemini analysis failed for {name}@{version}: {exc}", file=sys.stderr, flush=True)
            result = failed_result(package, str(exc))

        results.append(result)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"authtics-report-{timestamp}.md"

    findings_dir = Path("findings")
    findings_dir.mkdir(parents=True, exist_ok=True)
    findings_path = findings_dir / f"authtics-findings-{timestamp}.json"
    findings_payload = {
        "schema_version": "1.0",
        "generated": timestamp,
        "model": MODEL,
        "status": "PENDING_REVIEW",
        "human_review_required": True,
        "review": {"status": "PENDING"},
        "packages_analyzed": len(results),
        "results": results,
    }
    findings_path.write_text(json.dumps(findings_payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Authtics Advisories — Package Scan Report",
        "",
        f"**Generated:** {timestamp}",
        f"**Model:** `{MODEL}`",
        f"**Packages analyzed:** {len(results)}",
        "",
        "> This report contains AI-generated draft analysis only. A human reviewer must verify any potential finding before publication.",
        "",
    ]

    for index, result in enumerate(results, 1):
        package_ref = f"{result['package']}@{result['version']}"
        lines.extend([
            "---",
            "",
            f"## {index}. `{package_ref}`",
            "",
            f"- **Published:** {result.get('published', 'unknown')}",
            f"- **Status:** `{result.get('status', 'unknown')}`",
            f"- **Verdict:** `{result.get('verdict', 'unknown')}`",
            f"- **Confidence:** {result.get('confidence', 0)}",
            f"- **Review:** `{result.get('review', {}).get('status', 'PENDING')}`",
            "",
            "### Summary",
            "",
            str(result.get("summary", "")),
            "",
        ])

        behaviors = result.get("suspicious_behaviors") or []
        lines.append("### Observed Behaviors")
        lines.append("")
        if behaviors:
            lines.extend(f"- {item}" for item in behaviors)
        else:
            lines.append("- None reported.")
        lines.append("")

        evidence_items = result.get("evidence") or []
        lines.append("### Evidence")
        lines.append("")
        if evidence_items:
            for item in evidence_items:
                lines.append(f"- `{item.get('file', 'unknown')}` — {item.get('reason', '')}")
        else:
            lines.append("- None reported.")
        lines.append("")

        notes = result.get("reviewer_notes") or []
        lines.append("### Reviewer Notes")
        lines.append("")
        if notes:
            lines.extend(f"- {item}" for item in notes)
        else:
            lines.append("- None.")
        lines.append("")

        title = result.get("draft_title") or ""
        if title:
            lines.extend(["### Draft Advisory Title", "", title, ""])

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {report_path}")
    print(f"Wrote {findings_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Gemini analysis failed: {exc}", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Reconcile Gemini proposals with existing Authtics Advisories."""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ECOSYSTEM = os.environ.get("AUTHTICS_ECOSYSTEM", "npm").lower()
ROOT = Path("findings") / ECOSYSTEM
REPORT_ROOT = Path("reports")
SCAN_RESULTS = Path("metadata/analysis-results.json")
ADVISORY_ECOSYSTEM = "npm" if ECOSYSTEM == "npm" else "PyPI"


def tracked_advisories():
    if not ROOT.exists():
        return []
    result = subprocess.run(
        ["git", "ls-files", str(ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        Path(line) for line in result.stdout.splitlines()
        if Path(line).name.startswith("AUTH-") and Path(line).suffix == ".json"
    ]


def generated_advisories():
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", str(ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        Path(line[3:]) for line in result.stdout.splitlines()
        if line.startswith("?? ")
        and Path(line[3:]).name.startswith("AUTH-")
        and Path(line[3:]).suffix == ".json"
    ]


def affected_package(data, name):
    for affected in data.get("affected", []):
        package = affected.get("package", {}) if isinstance(affected, dict) else {}
        if package.get("name") == name and package.get("ecosystem") == ADVISORY_ECOSYSTEM:
            return affected
    return None


def find_advisory_by_id(advisory_id, package_name, tracked):
    if not advisory_id:
        return None
    matches = []
    for path in tracked:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("id") == advisory_id and affected_package(data, package_name) is not None:
            matches.append((path, data))
    if len(matches) != 1:
        return None
    return matches[0]


def merge_unique(old, new, key):
    merged = list(old or [])
    seen = {key(item) for item in merged}
    changed = False
    for item in new or []:
        item_key = key(item)
        if item_key in seen:
            continue
        merged.append(item)
        seen.add(item_key)
        changed = True
    return merged, changed


def mark_review_pending(data):
    database_specific = data.setdefault("database_specific", {})
    current = database_specific.get("review", {})
    if current and (current.get("status") != "PENDING" or current.get("reviewed_by") or current.get("reviewed_at")):
        history = database_specific.setdefault("review_history", [])
        snapshot = dict(current)
        if snapshot not in history:
            history.append(snapshot)
    database_specific["review"] = {
        "status": "PENDING",
        "human_review_required": True,
    }
    database_specific["human_review_required"] = True


def add_version_detail(affected, version, status, statement):
    details = affected.setdefault("version_details", [])
    for item in details:
        if item.get("version") == version and item.get("status") == status:
            if statement and statement not in item.get("statement", ""):
                item["statement"] = (item.get("statement", "").rstrip() + "\n\nUpdate from a later scan: " + statement).strip()
                return True
            return False
    details.append({
        "version": version,
        "status": status,
        "statement": statement or "No version-specific statement was supplied.",
    })
    details.sort(key=lambda item: (item.get("version", ""), item.get("status", "")))
    return True


def merge(existing, candidate, version):
    merged = json.loads(json.dumps(existing))
    changed = False
    name = candidate["affected"][0]["package"]["name"]
    target = affected_package(merged, name)
    if target is None:
        return merged, False

    patched_versions = target.setdefault("patched_versions", [])
    if version in patched_versions:
        patched_versions.remove(version)
        target["version_details"] = [
            item for item in target.get("version_details", [])
            if not (item.get("version") == version and item.get("status") == "patched")
        ]
        changed = True
    versions = target.setdefault("versions", [])
    if version not in versions:
        versions.append(version)
        versions.sort()
        changed = True
    detail = candidate["affected"][0].get("version_details", [{}])[0]
    if add_version_detail(target, version, "affected", detail.get("statement", candidate.get("details", ""))):
        changed = True

    references, ref_changed = merge_unique(
        merged.get("references", []),
        candidate.get("references", []),
        lambda item: (item.get("type"), item.get("url")),
    )
    if ref_changed:
        merged["references"] = references
        changed = True

    existing_db = merged.setdefault("database_specific", {})
    candidate_db = candidate.get("database_specific", {})
    for field, key in [
        ("suspicious_behaviors", lambda item: item),
        ("evidence", lambda item: (item.get("file"), item.get("reason"))),
        ("reviewer_notes", lambda item: item),
        ("cwe_ids", lambda item: item),
        ("cwe_notes", lambda item: item),
    ]:
        values, value_changed = merge_unique(existing_db.get(field, []), candidate_db.get(field, []), key)
        if value_changed:
            existing_db[field] = values
            changed = True

    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if rank.get(candidate.get("severity"), 0) > rank.get(merged.get("severity"), 0):
        merged["severity"] = candidate["severity"]
        changed = True

    confidence = candidate_db.get("confidence")
    old_confidence = existing_db.get("confidence")
    if isinstance(confidence, (int, float)) and (
        not isinstance(old_confidence, (int, float)) or confidence > old_confidence
    ):
        existing_db["confidence"] = confidence
        changed = True

    if changed:
        merged["modified"] = datetime.now(timezone.utc).isoformat()
        existing_db.setdefault("intent_assessment", "undetermined")
        mark_review_pending(merged)
    return merged, changed


def propose_patch(existing, version, result):
    proposed = json.loads(json.dumps(existing))
    name = result["package"]
    affected = affected_package(proposed, name)
    if affected is None:
        return proposed, False, "The selected advisory does not cover this package."
    versions = affected.setdefault("versions", [])
    patched = affected.setdefault("patched_versions", [])
    if version in versions:
        return proposed, False, "The release is already listed as affected; refusing to mark it patched."
    detail_changed = add_version_detail(
        affected,
        version,
        "patched",
        result.get("version_statement", ""),
    )
    changed = False
    if version not in patched:
        patched.append(version)
        patched.sort()
        changed = True
    if detail_changed:
        changed = True
    if changed:
        notes = proposed.setdefault("database_specific", {}).setdefault("reviewer_notes", [])
        note = f"Automated scan proposes {version} as patched for this advisory. This is a proposal only and requires human review."
        if note not in notes:
            notes.append(note)
        proposed["modified"] = datetime.now(timezone.utc).isoformat()
        mark_review_pending(proposed)
    return proposed, changed, "Patch proposal recorded for human review."


def rewrite_latest_report(changes):
    reports = sorted(REPORT_ROOT.glob("authtics-report-*.md"))
    if not reports:
        return
    report = reports[-1]
    if not changes:
        report.unlink(missing_ok=True)
        print("No advisory changes; removed the generated scan report.")
        return

    lines = [
        f"# Authtics {ADVISORY_ECOSYSTEM} Security Scan",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    for change in changes:
        lines.extend([
            f"### {change['id']}: {change['type'].upper()}",
            f"- Advisory: {change['id']}",
            f"- Package: {change['package']}@{change['version']}",
            f"- Change: {change['type']}",
            f"- Review: PENDING",
            "",
            change.get("note", ""),
            "",
        ])
    report.write_text("\n".join(lines), encoding="utf-8")


def main():
    tracked = tracked_advisories()
    changes = []

    for path in generated_advisories():
        candidate = json.loads(path.read_text(encoding="utf-8"))
        affected_items = candidate.get("affected", [])
        if not affected_items:
            continue
        package_name = affected_items[0].get("package", {}).get("name")
        versions = affected_items[0].get("versions", [])
        if not package_name or not versions:
            continue
        version = versions[0]
        database_specific = candidate.setdefault("database_specific", {})
        reconciliation = database_specific.pop("reconciliation", {})
        match = None
        if reconciliation.get("decision") == "same_vulnerability":
            match = find_advisory_by_id(reconciliation.get("advisory_id"), package_name, tracked)

        if match is None:
            path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
            continue

        existing_path, existing = match
        merged, changed = merge(existing, candidate, version)
        path.unlink(missing_ok=True)
        if changed:
            existing_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
            changes.append({
                "type": "updated",
                "id": existing.get("id", existing_path.stem),
                "package": package_name,
                "version": version,
                "note": reconciliation.get("reason", "Same vulnerability; exact release added for human review."),
            })
            print(f"Updated {existing.get('id', existing_path.stem)} with {package_name}@{version}")
        else:
            print(f"No changes for matched advisory {existing.get('id', existing_path.stem)}.")

    if SCAN_RESULTS.exists():
        try:
            results = json.loads(SCAN_RESULTS.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Could not read analysis results for patched-version review: {exc}") from exc
        for result in results:
            if result.get("version_assessment") != "patched":
                continue
            match_info = result.get("advisory_match", {})
            if match_info.get("decision") != "same_vulnerability" or not match_info.get("advisory_id"):
                print(f"Skipping patched-version proposal for {result.get('package')}@{result.get('version')}: no explicit advisory match.")
                continue
            match = find_advisory_by_id(match_info["advisory_id"], result.get("package"), tracked)
            if match is None:
                print(f"Skipping patched-version proposal for {result.get('package')}@{result.get('version')}: advisory ID was not found for this package.")
                continue
            path, existing = match
            updated, changed, note = propose_patch(existing, result["version"], result)
            if changed:
                path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
                changes.append({
                    "type": "patch-proposed",
                    "id": existing.get("id", path.stem),
                    "package": result["package"],
                    "version": result["version"],
                    "note": note,
                })
                print(f"Proposed {result['version']} as patched in {existing.get('id', path.stem)}; human review required.")
            else:
                print(f"No patched-version update for {existing.get('id', path.stem)}: {note}")

    for path in generated_advisories():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        affected_items = data.get("affected", [])
        if not affected_items:
            continue
        package_name = affected_items[0].get("package", {}).get("name", "unknown")
        version = (affected_items[0].get("versions") or ["unknown"])[0]
        changes.append({
            "type": "new",
            "id": data.get("id", path.stem),
            "package": package_name,
            "version": version,
            "note": "New advisory draft. Human review required.",
        })

    rewrite_latest_report(changes)
    print(f"Reconciliation complete: {len(changes)} advisory change(s).")


if __name__ == "__main__":
    main()

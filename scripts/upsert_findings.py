#!/usr/bin/env python3
"""Reconcile newly generated Authtics findings with existing advisories."""

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ECOSYSTEM = os.environ.get("AUTHTICS_ECOSYSTEM", "npm").lower()
ROOT = Path("findings") / ECOSYSTEM
REPORT_ROOT = Path("reports")


def tracked_advisories():
    if not ROOT.exists():
        return []
    result = subprocess.run(
        ["git", "ls-files", str(ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = []
    for line in result.stdout.splitlines():
        path = Path(line)
        if path.name.startswith("AUTH-") and path.suffix == ".json":
            paths.append(path)
    return paths


def generated_advisories():
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", str(ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = []
    for line in result.stdout.splitlines():
        if not line.startswith("?? "):
            continue
        path = Path(line[3:])
        if path.name.startswith("AUTH-") and path.suffix == ".json":
            paths.append(path)
    return paths


def ecosystem_name():
    return "npm" if ECOSYSTEM == "npm" else "PyPI"


def package_matches(data, name):
    for affected in data.get("affected", []):
        package = affected.get("package", {}) if isinstance(affected, dict) else {}
        if package.get("name") == name and package.get("ecosystem") == ecosystem_name():
            return True
    return False


def package_advisories(name, tracked):
    found = []
    for path in tracked:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if package_matches(data, name):
            found.append((path, data))
    return found


def tokens(value):
    return set(re.findall(r"[a-z0-9]+", str(value).lower()))


def similarity(existing, candidate):
    def text(data):
        db = data.get("database_specific", {})
        return " ".join([
            data.get("summary", ""),
            data.get("details", ""),
            " ".join(db.get("suspicious_behaviors", [])),
        ])

    left = tokens(text(existing))
    right = tokens(text(candidate))
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def find_match(name, version, candidate, tracked):
    advisories = package_advisories(name, tracked)
    exact = []

    for path, data in advisories:
        for affected in data.get("affected", []):
            package = affected.get("package", {}) if isinstance(affected, dict) else {}
            if (
                package.get("name") == name
                and package.get("ecosystem") == ecosystem_name()
                and version in affected.get("versions", [])
            ):
                exact.append((path, data))
                break

    if len(exact) == 1:
        return exact[0]

    candidates = exact if exact else advisories
    if not candidates:
        return None

    scored = sorted(
        ((similarity(data, candidate), path, data) for path, data in candidates),
        key=lambda item: item[0],
        reverse=True,
    )
    if not scored or scored[0][0] < 0.50:
        return None

    second = scored[1][0] if len(scored) > 1 else 0.0
    if len(scored) > 1 and scored[0][0] - second < 0.10:
        return None
    return scored[0][1], scored[0][2]


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


def merge(existing, candidate, version):
    merged = json.loads(json.dumps(existing))
    changed = False
    name = candidate["affected"][0]["package"]["name"]

    target_affected = None
    for affected in merged.get("affected", []):
        package = affected.get("package", {})
        if package.get("name") == name and package.get("ecosystem") == ecosystem_name():
            target_affected = affected
            break

    if target_affected is None:
        merged.setdefault("affected", []).append(candidate["affected"][0])
        changed = True
    elif version not in target_affected.setdefault("versions", []):
        target_affected["versions"] = sorted(set(target_affected["versions"] + [version]))
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

    behaviors, behavior_changed = merge_unique(
        existing_db.get("suspicious_behaviors", []),
        candidate_db.get("suspicious_behaviors", []),
        lambda item: item,
    )
    if behavior_changed:
        existing_db["suspicious_behaviors"] = behaviors
        changed = True

    evidence, evidence_changed = merge_unique(
        existing_db.get("evidence", []),
        candidate_db.get("evidence", []),
        lambda item: (item.get("file"), item.get("reason")),
    )
    if evidence_changed:
        existing_db["evidence"] = evidence
        changed = True

    notes, notes_changed = merge_unique(
        existing_db.get("reviewer_notes", []),
        candidate_db.get("reviewer_notes", []),
        lambda item: item,
    )
    if notes_changed:
        existing_db["reviewer_notes"] = notes
        changed = True

    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if rank.get(candidate.get("severity"), 0) > rank.get(merged.get("severity"), 0):
        merged["severity"] = candidate["severity"]
        changed = True

    candidate_confidence = candidate_db.get("confidence")
    existing_confidence = existing_db.get("confidence")
    if isinstance(candidate_confidence, (int, float)) and (
        not isinstance(existing_confidence, (int, float))
        or candidate_confidence > existing_confidence
    ):
        existing_db["confidence"] = candidate_confidence
        changed = True

    if changed:
        merged["modified"] = datetime.now(timezone.utc).isoformat()
        existing_db["review"] = {
            "status": "PENDING",
            "human_review_required": True,
        }
        merged["database_specific"] = existing_db

    return merged, changed


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
        f"# Authtics {ecosystem_name()} Security Scan",
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
            "",
        ])
    report.write_text("\n".join(lines), encoding="utf-8")


def main():
    tracked = tracked_advisories()
    generated = generated_advisories()
    changes = []

    for path in generated:
        candidate = json.loads(path.read_text(encoding="utf-8"))
        affected = candidate.get("affected", [])
        if not affected:
            continue
        package = affected[0].get("package", {}).get("name")
        versions = affected[0].get("versions", [])
        if not package or not versions:
            continue

        version = versions[0]
        match = find_match(package, version, candidate, tracked)
        if match is None:
            continue

        existing_path, existing = match
        merged, changed = merge(existing, candidate, version)
        path.unlink(missing_ok=True)

        if changed:
            existing_path.write_text(
                json.dumps(merged, indent=2) + "\n",
                encoding="utf-8",
            )
            changes.append({
                "type": "updated",
                "id": existing.get("id", existing_path.stem),
                "package": package,
                "version": version,
            })
            print(f"Updated {existing.get('id', existing_path.stem)} with {package}@{version}")
        else:
            print(f"No changes for existing advisory {existing.get('id', existing_path.stem)}; duplicate removed.")

    for path in generated_advisories():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        affected = data.get("affected", [])
        if not affected:
            continue
        package = affected[0].get("package", {}).get("name", "unknown")
        version = (affected[0].get("versions") or ["unknown"])[0]
        changes.append({
            "type": "new",
            "id": data.get("id", path.stem),
            "package": package,
            "version": version,
        })

    rewrite_latest_report(changes)
    print(f"Reconciliation complete: {len(changes)} advisory change(s).")


if __name__ == "__main__":
    main()

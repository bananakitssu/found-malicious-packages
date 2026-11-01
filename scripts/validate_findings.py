#!/usr/bin/env python3
"""Validate Authtics Advisory schema 1.1 and its human-review state."""

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.ecosystem import ECOSYSTEMS

ALLOWED_REVIEW = {"PENDING", "APPROVED", "REJECTED", "NEEDS_EDIT"}
SEVERITIES = {"critical", "high", "medium", "low"}
CWE_RE = re.compile(r"^CWE-[0-9]+$")
MAX_CWE_IDS = 5
CWE_STATUSES = {"AI_PROPOSED", "UNAVAILABLE", "VERIFIED"}
VERSION_STATUSES = {"affected", "patched"}


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def validate(path):
    errors = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{path}: invalid JSON: {exc}"]

    if data.get("schema_version") != "1.1":
        errors.append(f"{path}: schema_version must be '1.1'")
    if not nonempty(data.get("id")) or not data.get("id", "").startswith("AUTH-"):
        errors.append(f"{path}: id must be an AUTH-* advisory ID")
    if data.get("severity") not in SEVERITIES:
        errors.append(f"{path}: severity must be critical/high/medium/low")
    if not nonempty(data.get("summary")):
        errors.append(f"{path}: summary is required")
    if not isinstance(data.get("details"), str):
        errors.append(f"{path}: details must be a string")

    supported = {config.advisory_ecosystem for config in ECOSYSTEMS.values()}
    affected = data.get("affected")
    if not isinstance(affected, list) or not affected:
        errors.append(f"{path}: affected must be a non-empty array")
        affected = []
    for index, item in enumerate(affected):
        package = item.get("package") if isinstance(item, dict) else None
        if not isinstance(package, dict) or not nonempty(package.get("ecosystem")) or not nonempty(package.get("name")):
            errors.append(f"{path}: affected[{index}] must identify an ecosystem and package name")
        elif package["ecosystem"] not in supported:
            errors.append(f"{path}: affected[{index}] uses unsupported ecosystem {package['ecosystem']!r}")

        versions = item.get("versions") if isinstance(item, dict) else None
        patched = item.get("patched_versions") if isinstance(item, dict) else None
        details = item.get("version_details") if isinstance(item, dict) else None
        if not isinstance(versions, list) or not versions or any(not nonempty(v) for v in versions):
            errors.append(f"{path}: affected[{index}].versions must be a non-empty array of exact version strings")
            versions = []
        if len(versions) != len(set(versions)):
            errors.append(f"{path}: affected[{index}].versions contains duplicates")
        if not isinstance(patched, list) or any(not nonempty(v) for v in patched):
            errors.append(f"{path}: affected[{index}].patched_versions must be an array of exact version strings")
            patched = []
        if len(patched) != len(set(patched)):
            errors.append(f"{path}: affected[{index}].patched_versions contains duplicates")
        overlap = set(versions) & set(patched)
        if overlap:
            errors.append(f"{path}: versions cannot be both affected and patched: {sorted(overlap)}")
        if not isinstance(details, list):
            errors.append(f"{path}: affected[{index}].version_details must be an array")
            details = []
        seen_details = set()
        for version in versions:
            if (version, "affected") not in {(d.get("version"), d.get("status")) for d in details if isinstance(d, dict)}:
                errors.append(f"{path}: affected version {version} is missing its own affected version_details statement")
        for version in patched:
            if (version, "patched") not in {(d.get("version"), d.get("status")) for d in details if isinstance(d, dict)}:
                errors.append(f"{path}: patched version {version} is missing its own patched version_details statement")
        for detail_index, detail in enumerate(details):
            if not isinstance(detail, dict):
                errors.append(f"{path}: affected[{index}].version_details[{detail_index}] must be an object")
                continue
            version = detail.get("version")
            status = detail.get("status")
            statement = detail.get("statement")
            if not nonempty(version) or status not in VERSION_STATUSES or not nonempty(statement):
                errors.append(f"{path}: affected[{index}].version_details[{detail_index}] needs version, affected/patched status, and statement")
                continue
            key = (version, status)
            if key in seen_details:
                errors.append(f"{path}: affected[{index}].version_details has a duplicate version/status entry")
            seen_details.add(key)
            if status == "affected" and version not in versions:
                errors.append(f"{path}: version detail marks {version} affected but it is not in versions")
            if status == "patched" and version not in patched:
                errors.append(f"{path}: version detail marks {version} patched but it is not in patched_versions")

    references = data.get("references")
    if not isinstance(references, list):
        errors.append(f"{path}: references must be an array")
    else:
        for index, reference in enumerate(references):
            if not isinstance(reference, dict) or not nonempty(reference.get("type")) or not nonempty(reference.get("url")):
                errors.append(f"{path}: references[{index}] must include type and url")

    database_specific = data.get("database_specific")
    if not isinstance(database_specific, dict):
        errors.append(f"{path}: database_specific object is required")
        return errors
    if database_specific.get("intent_assessment") != "undetermined":
        errors.append(f"{path}: database_specific.intent_assessment must be 'undetermined'")

    cwe_ids = database_specific.get("cwe_ids")
    if cwe_ids is not None:
        if not isinstance(cwe_ids, list):
            errors.append(f"{path}: database_specific.cwe_ids must be an array")
        else:
            if len(cwe_ids) > MAX_CWE_IDS:
                errors.append(f"{path}: database_specific.cwe_ids may contain at most {MAX_CWE_IDS} IDs")
            if len(cwe_ids) != len(set(cwe_ids)):
                errors.append(f"{path}: database_specific.cwe_ids must not contain duplicates")
            for cwe_id in cwe_ids:
                if not isinstance(cwe_id, str) or not CWE_RE.fullmatch(cwe_id):
                    errors.append(f"{path}: invalid CWE ID: {cwe_id!r}")

    cwe_notes = database_specific.get("cwe_notes")
    if cwe_notes is not None and (
        not isinstance(cwe_notes, list) or any(not isinstance(note, str) for note in cwe_notes)
    ):
        errors.append(f"{path}: database_specific.cwe_notes must be an array of strings")

    cwe_status = database_specific.get("cwe_status")
    if cwe_status is not None and cwe_status not in CWE_STATUSES:
        errors.append(f"{path}: invalid database_specific.cwe_status: {cwe_status!r}")
    if cwe_status == "VERIFIED" and database_specific.get("review", {}).get("status") != "APPROVED":
        errors.append(f"{path}: VERIFIED CWE classifications require an approved advisory review")

    review = database_specific.get("review")
    if not isinstance(review, dict):
        errors.append(f"{path}: database_specific.review object is required")
        return errors
    status = review.get("status")
    if status not in ALLOWED_REVIEW:
        errors.append(f"{path}: invalid review.status: {status!r}")
    elif status == "PENDING":
        if database_specific.get("human_review_required") is not True or review.get("human_review_required") is not True:
            errors.append(f"{path}: pending changes must require human review")
    elif status == "APPROVED":
        if database_specific.get("human_review_required") is not False or review.get("human_review_required") is not False:
            errors.append(f"{path}: approved advisories must have human_review_required=false")
        reviewer = review.get("reviewed_by")
        reviewed_at = review.get("reviewed_at")
        if bool(reviewer) != bool(reviewed_at):
            errors.append(f"{path}: reviewed_by and reviewed_at must either both be present or both be absent")
    else:
        if database_specific.get("human_review_required") is not True:
            errors.append(f"{path}: rejected or needs-edit advisories must remain gated for human review")
        if not nonempty(review.get("notes")):
            errors.append(f"{path}: notes are required for {status}")

    return errors


def main():
    files = [pathlib.Path(arg) for arg in sys.argv[1:]]
    if not files:
        print("No findings files supplied; nothing to validate.")
        return 0
    errors = []
    for path in files:
        errors.extend(validate(path))
    if errors:
        print("Authtics advisory validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"Authtics advisory validation passed for {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

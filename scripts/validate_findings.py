#!/usr/bin/env python3
"""Validate OSV-style Authtics advisory review state before merge."""

import json
import pathlib
import sys

ALLOWED = {"PENDING", "APPROVED", "REJECTED", "NEEDS_EDIT"}
SEVERITIES = {"critical", "high", "medium", "low"}


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def validate(path):
    errors = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{path}: invalid JSON: {exc}"]

    if data.get("schema_version") != "1.0":
        errors.append(f"{path}: schema_version must be '1.0'")
    if not nonempty(data.get("id")) or not data.get("id", "").startswith("AUTH-"):
        errors.append(f"{path}: id must be an AUTH-* advisory ID")
    if data.get("severity") not in SEVERITIES:
        errors.append(f"{path}: actionable advisory severity must be critical/high/medium/low")
    if not nonempty(data.get("summary")):
        errors.append(f"{path}: summary is required")
    if not isinstance(data.get("details"), str):
        errors.append(f"{path}: details must be a string")

    affected = data.get("affected")
    if not isinstance(affected, list) or not affected:
        errors.append(f"{path}: affected must be a non-empty array")
    else:
        for index, item in enumerate(affected):
            package = item.get("package") if isinstance(item, dict) else None
            if not isinstance(package, dict) or package.get("ecosystem") != "npm" or not nonempty(package.get("name")):
                errors.append(f"{path}: affected[{index}] must identify an npm package")
            if not isinstance(item.get("versions"), list) or not item["versions"]:
                errors.append(f"{path}: affected[{index}].versions must be a non-empty array")

    database_specific = data.get("database_specific")
    if not isinstance(database_specific, dict):
        errors.append(f"{path}: database_specific object is required")
        return errors

    review = database_specific.get("review")
    if not isinstance(review, dict):
        errors.append(f"{path}: database_specific.review object is required")
        return errors

    status = review.get("status")
    if status not in ALLOWED:
        errors.append(f"{path}: invalid review.status: {status!r}")
        return errors

    if status == "PENDING":
        errors.append(f"{path}: human review is still pending")
    elif status in {"APPROVED", "REJECTED", "NEEDS_EDIT"}:
        if not nonempty(review.get("reviewed_by")):
            errors.append(f"{path}: reviewed_by is required for {status}")
        if not nonempty(review.get("reviewed_at")):
            errors.append(f"{path}: reviewed_at is required for {status}")
    if status in {"REJECTED", "NEEDS_EDIT"} and not nonempty(review.get("notes")):
        errors.append(f"{path}: notes are required for {status}")

    if database_specific.get("human_review_required") is not True:
        errors.append(f"{path}: human_review_required must remain true until publication tooling clears it")

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

#!/usr/bin/env python3
"""Validate Authtics findings review state before a pull request can merge."""

import json
import pathlib
import sys

ALLOWED = {"PENDING", "APPROVED", "REJECTED", "NEEDS_EDIT"}


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
    if data.get("status") != "PENDING_REVIEW":
        errors.append(f"{path}: top-level status must be PENDING_REVIEW")
    if data.get("human_review_required") is not True:
        errors.append(f"{path}: human_review_required must be true")

    review = data.get("review")
    if not isinstance(review, dict):
        errors.append(f"{path}: missing top-level review object")
    else:
        status = review.get("status")
        if status not in ALLOWED:
            errors.append(f"{path}: invalid top-level review.status: {status!r}")

    results = data.get("results")
    if not isinstance(results, list):
        return errors + [f"{path}: results must be an array"]

    for index, result in enumerate(results):
        label = f"{path}: results[{index}]"
        if not isinstance(result, dict):
            errors.append(f"{label} must be an object")
            continue
        result_review = result.get("review")
        if not isinstance(result_review, dict):
            errors.append(f"{label}: missing review object")
            continue
        status = result_review.get("status")
        if status not in ALLOWED:
            errors.append(f"{label}: invalid review.status: {status!r}")
            continue
        if status in {"APPROVED", "REJECTED", "NEEDS_EDIT"}:
            if not nonempty(result_review.get("reviewed_by")):
                errors.append(f"{label}: reviewed_by is required for {status}")
            if not nonempty(result_review.get("reviewed_at")):
                errors.append(f"{label}: reviewed_at is required for {status}")
        if status in {"REJECTED", "NEEDS_EDIT"} and not nonempty(result_review.get("notes")):
            errors.append(f"{label}: notes are required for {status}")

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
        print("Authtics findings validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"Authtics findings validation passed for {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

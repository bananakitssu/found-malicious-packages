import json
import tempfile
import unittest
from pathlib import Path

from scripts.upsert_findings import merge, propose_patch
from scripts.validate_findings import validate


def advisory():
    return {
        "schema_version": "1.1",
        "id": "AUTH-2026-00001",
        "published": "2026-09-01T00:00:00Z",
        "modified": "2026-09-01T00:00:00Z",
        "summary": "A vulnerability in demo-package",
        "details": "The package has a specific vulnerability.",
        "severity": "high",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "demo-package"},
            "versions": ["1.0.0"],
            "patched_versions": [],
            "version_details": [{
                "version": "1.0.0",
                "status": "affected",
                "statement": "Version 1.0.0 contains the vulnerable behavior."
            }]
        }],
        "references": [],
        "database_specific": {
            "intent_assessment": "undetermined",
            "human_review_required": False,
            "review": {
                "status": "APPROVED",
                "human_review_required": False,
                "reviewed_by": "maintainer",
                "reviewed_at": "2026-09-02T00:00:00Z"
            },
            "suspicious_behaviors": [],
            "evidence": [],
            "reviewer_notes": []
        }
    }


class AdvisoryPipelineTests(unittest.TestCase):
    def test_same_vulnerability_adds_exact_affected_release_and_reopens_review(self):
        existing = advisory()
        candidate = {
            "affected": [{
                "package": {"ecosystem": "npm", "name": "demo-package"},
                "versions": ["1.1.0"],
                "version_details": [{
                    "version": "1.1.0",
                    "status": "affected",
                    "statement": "Version 1.1.0 still contains the same vulnerable behavior."
                }]
            }],
            "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
            "database_specific": {
                "suspicious_behaviors": ["The same vulnerable behavior"],
                "evidence": [{"file": "src/index.js", "reason": "The vulnerable function remains present."}],
                "reviewer_notes": []
            },
            "severity": "high"
        }

        merged, changed = merge(existing, candidate, "1.1.0")

        self.assertTrue(changed)
        self.assertEqual(merged["id"], "AUTH-2026-00001")
        self.assertEqual(merged["published"], existing["published"])
        affected = merged["affected"][0]
        self.assertEqual(affected["versions"], ["1.0.0", "1.1.0"])
        self.assertIn(
            ("1.1.0", "affected"),
            {(item["version"], item["status"]) for item in affected["version_details"]}
        )
        database_specific = merged["database_specific"]
        self.assertEqual(database_specific["review"]["status"], "PENDING")
        self.assertIs(database_specific["review"]["human_review_required"], True)
        self.assertIs(database_specific["human_review_required"], True)
        self.assertEqual(database_specific["review_history"][0]["status"], "APPROVED")

    def test_clean_exact_release_proposes_patched_version_for_review(self):
        existing = advisory()
        result = {
            "package": "demo-package",
            "version": "1.1.0",
            "version_statement": "Version 1.1.0 removes the vulnerable code path."
        }

        updated, changed, note = propose_patch(existing, "1.1.0", result)

        self.assertTrue(changed)
        self.assertIn("1.1.0", updated["affected"][0]["patched_versions"])
        self.assertIn(
            ("1.1.0", "patched"),
            {(item["version"], item["status"]) for item in updated["affected"][0]["version_details"]}
        )
        self.assertEqual(updated["database_specific"]["review"]["status"], "PENDING")
        self.assertIs(updated["database_specific"]["human_review_required"], True)
        self.assertIn("human review", note.lower())

    def test_affected_release_cannot_be_marked_patched(self):
        existing = advisory()
        updated, changed, note = propose_patch(existing, "1.0.0", {
            "package": "demo-package",
            "version": "1.0.0",
            "version_statement": "No issue found."
        })

        self.assertFalse(changed)
        self.assertNotIn("1.0.0", updated["affected"][0]["patched_versions"])
        self.assertIn("already listed as affected", note)

    def test_validator_rejects_version_without_own_statement(self):
        data = advisory()
        data["affected"][0]["version_details"] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "advisory.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            errors = validate(path)

        self.assertTrue(any("missing its own affected version_details statement" in error for error in errors))

    def test_validator_accepts_complete_schema_1_1_record(self):
        data = advisory()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "advisory.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            errors = validate(path)

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()

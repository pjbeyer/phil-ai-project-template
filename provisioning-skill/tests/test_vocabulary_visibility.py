"""FR-030 vocabulary registry + visibility/coding-agent-plugin propagation tests.

Deterministic coverage for the Phase-11 field change: the canonical registry is
the single source of truth; new manifest records require project_kind/visibility;
existing (legacy) records parse forward-compatibly; bootstrap and render matrices
honor coding-agent-plugin.
"""
from __future__ import annotations

import unittest

from scripts import vocabulary
from scripts.bootstrap_issues import desired_issues
from scripts.manifest import (
    DEFAULT_VISIBILITY,
    PROJECT_KIND_VALUES,
    VISIBILITY_VALUES,
    ManifestError,
    validate_new_record,
    validate_records,
)


class VocabularyRegistryTests(unittest.TestCase):
    def test_registry_is_the_single_source_of_truth(self) -> None:
        # manifest.py re-exports the registry values rather than re-declaring them.
        self.assertEqual(PROJECT_KIND_VALUES, vocabulary.PROJECT_KIND_VALUES)
        self.assertEqual(VISIBILITY_VALUES, vocabulary.VISIBILITY_VALUES)
        self.assertEqual(DEFAULT_VISIBILITY, vocabulary.DEFAULT_VISIBILITY)

    def test_project_kind_gains_coding_agent_plugin(self) -> None:
        self.assertIn("coding-agent-plugin", PROJECT_KIND_VALUES)
        self.assertEqual(
            PROJECT_KIND_VALUES,
            {"generic", "macos-cli", "homebrew-tap", "coding-agent-plugin"},
        )

    def test_visibility_axis_is_explicit_and_never_derived(self) -> None:
        self.assertEqual(
            VISIBILITY_VALUES, {"personal-only", "work-internal", "open-source"}
        )
        self.assertEqual(DEFAULT_VISIBILITY, "personal-only")


class ManifestFieldChangeTests(unittest.TestCase):
    def _new_record(self, **overrides):
        record = {
            "path": "/synthetic/projects/demo",
            "prefix": "demo",
            "database": "demo_database",
            "owner": "personal",
            "project_kind": "generic",
            "visibility": "personal-only",
            "profile": "default",
            "expected_remote": "origin",
            "expected_backup": True,
            "expected_sync": "manual-dolt-remote",
            "owning_jobs": [
                "Hermes: Beads health review",
                "Hermes: compliance audit",
                "Hermes: Beads Dolt maintenance",
                "Hermes: Beads Dolt integrity review",
            ],
            "remote_health": "required",
            "restore_tier": "rotating",
        }
        record.update(overrides)
        return record

    def test_new_record_requires_project_kind_and_visibility(self) -> None:
        validate_new_record(self._new_record())
        for missing in ("project_kind", "visibility"):
            record = self._new_record()
            record.pop(missing)
            with self.subTest(missing=missing), self.assertRaises(ManifestError):
                validate_new_record(record)

    def test_new_record_rejects_unrecognized_kind_and_visibility(self) -> None:
        for field, bad in (("project_kind", "not-a-kind"), ("visibility", "not-a-visibility")):
            with self.subTest(field=field), self.assertRaises(ManifestError):
                validate_new_record(self._new_record(**{field: bad}))

    def test_legacy_record_without_new_fields_parses_forward_compatibly(self) -> None:
        legacy = self._new_record()
        legacy.pop("project_kind")
        legacy.pop("visibility")
        # validate_records accepts legacy (field-absent) records.
        validate_records([legacy])

    def test_legacy_record_with_unrecognized_value_fails_closed(self) -> None:
        bad = self._new_record()
        bad["visibility"] = "not-a-visibility"
        with self.assertRaises(ManifestError):
            validate_records([bad])


class BootstrapAndRenderMatrixTests(unittest.TestCase):
    def test_coding_agent_plugin_bootstrap_marker(self) -> None:
        issues = desired_issues("coding-agent-plugin")
        markers = [marker for marker, _ in issues]
        self.assertIn("scope-readme", markers)
        self.assertIn("first-speckit-spec", markers)
        self.assertIn("coding-agent-plugin-skeleton", markers)
        # generic baseline carries no OS-specific CI marker.
        self.assertNotIn("macos-cli-real-tests", markers)
        self.assertNotIn("homebrew-first-package", markers)


if __name__ == "__main__":
    unittest.main(verbosity=2)

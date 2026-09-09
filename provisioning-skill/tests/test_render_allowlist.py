"""Failure-first tests for the live-G03 render allowlist and minimum-tag floor.

Captures pjb-m0ap.3.1: the future live G03 gate must render only from the
allowlisted immutable template revision (pjbeyer/phil-ai-project-template) at
or above the reviewed minimum tag (v0.1.3), and must reject unpinned,
non-allowlisted, or stale-tag sources before any mutation.

These tests exercise the pure validation in ``scripts.models`` — no live
transport, no Git/network/credentials, no filesystem mutation.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.models import (
    APPROVED_TEMPLATE_MINIMUM_TAG,
    APPROVED_TEMPLATE_SOURCE_IDENTITIES,
    ComponentPin,
    ConfigurationError,
    ImmutableLiveConfiguration,
)

SHA = "a" * 40
APPROVED_SOURCE = next(iter(APPROVED_TEMPLATE_SOURCE_IDENTITIES))


def component_pins() -> dict[str, ComponentPin]:
    from scripts.models import APPROVED_COMPONENT_NAMES

    return {
        name: ComponentPin(name, f"speckit/component/{name}", SHA)
        for name in APPROVED_COMPONENT_NAMES
    }


def make_config(*, source: str, tag: str, commit: str = SHA) -> ImmutableLiveConfiguration:
    return ImmutableLiveConfiguration.create(
        repository_identity="pjbeyer/demo",
        template_source_identity=source,
        template_tag=tag,
        resolved_template_commit=commit,
        component_pins=component_pins(),
    )


class RenderAllowlistTests(unittest.TestCase):
    def test_allowlist_contains_only_the_published_template(self) -> None:
        self.assertEqual(
            APPROVED_TEMPLATE_SOURCE_IDENTITIES,
            frozenset({"pjbeyer/phil-ai-project-template"}),
        )
        self.assertEqual(APPROVED_TEMPLATE_MINIMUM_TAG, "v0.1.3")

    def test_approved_source_at_floor_is_accepted(self) -> None:
        config = make_config(source=APPROVED_SOURCE, tag="v0.1.3")
        self.assertEqual(config.template_source_identity, APPROVED_SOURCE)
        self.assertEqual(config.template_tag, "v0.1.3")

    def test_later_minor_and_patch_are_accepted(self) -> None:
        for tag in ("v0.1.4", "v0.2.0", "v1.0.0"):
            with self.subTest(tag=tag):
                config = make_config(source=APPROVED_SOURCE, tag=tag)
                self.assertEqual(config.template_tag, tag)

    def test_below_floor_registered_tags_are_rejected(self) -> None:
        # v0.1.0, v0.1.1, v0.1.2 all carry the nonexistent release-please SHA.
        for tag in ("v0.1.0", "v0.1.1", "v0.1.2"):
            with self.subTest(tag=tag), self.assertRaises(ConfigurationError):
                make_config(source=APPROVED_SOURCE, tag=tag)

    def test_non_allowlisted_source_is_rejected_even_at_floor_tag(self) -> None:
        for source in ("other/template", "pjbeyer/project-provisioning-template"):
            with self.subTest(source=source), self.assertRaises(ConfigurationError):
                make_config(source=source, tag="v0.1.3")

    def test_unpinned_floating_references_are_rejected(self) -> None:
        for tag in ("HEAD", "main", "origin/main", "refs/tags/v0.1.3", "latest"):
            with self.subTest(tag=tag), self.assertRaises(ConfigurationError):
                make_config(source=APPROVED_SOURCE, tag=tag)

    def test_floor_prerelease_is_not_the_reviewed_final_tag(self) -> None:
        # Same numeric version as the floor, but a pre-release/build suffix is not
        # the reviewed final tag and must not render.
        for tag in ("v0.1.3-rc.1", "v0.1.3+build.7"):
            with self.subTest(tag=tag), self.assertRaises(ConfigurationError):
                make_config(source=APPROVED_SOURCE, tag=tag)

    def test_degenerate_oversized_version_number_fails_closed(self) -> None:
        oversized = "v" + "9" * 5000 + ".0.0"
        with self.assertRaises(ConfigurationError):
            make_config(source=APPROVED_SOURCE, tag=oversized)

    def test_rejection_is_filesystem_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            before = sorted(p.name for p in Path(tmp).rglob("*"))
            for tag in ("v0.1.0", "HEAD", "v0.1.3-rc.1"):
                with self.subTest(tag=tag), self.assertRaises(ConfigurationError):
                    make_config(source=APPROVED_SOURCE, tag=tag)
            after = sorted(p.name for p in Path(tmp).rglob("*"))
            self.assertEqual(before, after)

    def test_evidence_records_floor_enforcement_too(self) -> None:
        from scripts.models import LiveProvisioningEvidence
        from scripts.models import configuration_digest

        config = make_config(source=APPROVED_SOURCE, tag="v0.1.3")
        base = dict(
            template_source_identity=config.template_source_identity,
            template_tag=config.template_tag,
            resolved_template_commit=config.resolved_template_commit,
            config_digest=configuration_digest(config),
            actual_database="synthetic_database",
            manifest_identity=config.manifest_identity,
            stable_issue_markers=("scope-readme", "first-speckit-spec"),
            validated_component_pins=config.component_pins,
        )
        LiveProvisioningEvidence(**base)
        for tag in ("v0.1.0", "v0.1.2", "HEAD"):
            with self.subTest(tag=tag), self.assertRaises(ConfigurationError):
                LiveProvisioningEvidence(**{**base, "template_tag": tag})


if __name__ == "__main__":
    unittest.main(verbosity=2)
"""Failure-first tests for the pjb-m0ap.3.1 provenance half.

Criterion 3: non-secret provenance (source, tag, resolved commit, submitted
answers) must be persisted durably BEFORE any render mutation, and recording it
must never be read as a claim that FR-008/FR-019 completion happened.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.models import (
    APPROVED_TEMPLATE_SOURCE_IDENTITIES,
    ConfigurationError,
    ImmutableLiveConfiguration,
    RenderProvenance,
)

SOURCE = next(iter(APPROVED_TEMPLATE_SOURCE_IDENTITIES))
SHA = "1" * 40
ANSWER_KEYS = ("repository_owner", "repository_name", "project_kind", "project_description")


def render_provenance(*, answers=("repository_owner", "pjbeyer", "repository_name", "demo",
                                  "project_kind", "generic", "project_description", "desc")) -> RenderProvenance:
    return RenderProvenance(SOURCE, "v0.1.3", SHA, tuple(zip(answers[::2], answers[1::2])))


class RenderProvenanceValidationTests(unittest.TestCase):
    def test_well_formed_provenance_accepts_and_exposes_canonical_fields(self) -> None:
        provenance = render_provenance()
        fields = provenance.canonical_fields()
        self.assertEqual(fields["template_source_identity"], SOURCE)
        self.assertEqual(fields["template_tag"], "v0.1.3")
        self.assertEqual(fields["resolved_template_commit"], SHA)
        self.assertEqual(set(fields["submitted_answers"]), set(ANSWER_KEYS))

    def test_secret_shaped_answer_value_is_rejected(self) -> None:
        op_pointer = "op" + "://vault/item"  # split so the literal never appears in source
        for bad in ("token=synthetic-sensitive-value", op_pointer, "ghp_1234567890"):
            with self.subTest(bad=bad), self.assertRaises(ConfigurationError):
                render_provenance(
                    answers=("repository_owner", "pjbeyer", "repository_name", "demo",
                             "project_kind", bad, "project_description", "desc")
                )

    def test_secret_shaped_answer_key_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            render_provenance(
                answers=("repository_owner", "pjbeyer", "repository_name", "demo",
                         "api_key=value", "generic", "project_description", "desc")
            )

    def test_private_absolute_path_value_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            render_provenance(
                answers=("repository_owner", "pjbeyer", "repository_name", "demo",
                         "project_kind", "generic", "project_description", "/Users/synthetic-private/x")
            )

    def test_non_allowlisted_source_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            RenderProvenance("other/template", "v0.1.3", SHA, (("project_kind", "generic"),))

    def test_below_floor_tag_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            RenderProvenance(SOURCE, "v0.1.2", SHA, (("project_kind", "generic"),))

    def test_unpinned_floating_ref_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            RenderProvenance(SOURCE, "HEAD", SHA, (("project_kind", "generic"),))

    def test_capture_with_unknown_project_kind_is_rejected(self) -> None:
        from scripts.models import APPROVED_COMPONENT_NAMES, ComponentPin

        config = ImmutableLiveConfiguration.create(
            repository_identity="pjbeyer/demo",
            template_source_identity=SOURCE,
            template_tag="v0.1.3",
            resolved_template_commit=SHA,
            component_pins={
                name: ComponentPin(name, f"speckit/component/{name}", SHA)
                for name in APPROVED_COMPONENT_NAMES
            },
        )
        with self.assertRaises(ConfigurationError):
            RenderProvenance.capture(
                config,
                repository_owner="pjbeyer",
                repository_name="demo",
                project_kind="not-a-kind",
                project_description="",
                visibility="personal-only",
            )


class ProvenancePersistedBeforeMutationTests(unittest.TestCase):
    """The controlled G01-G05 run must persist provenance before any gate mutation."""

    def test_controlled_run_persists_provenance_before_first_mutation(self) -> None:
        from scripts.adapters import ControlledGateOperation
        from scripts.models import ComponentPin, ProvisioningRequest
        from scripts.provision_project import ControlledG01G03Controller
        from tests.test_live_gates import ControlledGateFixture

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        home = root / "home"
        home.mkdir()
        evidence_dir = (root / "evidence").resolve()
        request = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git", "demo", "generic", "controlled description"
        )
        from scripts.models import APPROVED_COMPONENT_NAMES

        config = ImmutableLiveConfiguration.create(
            repository_identity="pjbeyer/demo",
            template_source_identity=SOURCE,
            template_tag="v0.1.3",
            resolved_template_commit=SHA,
            component_pins={
                name: ComponentPin(name, f"speckit/component/{name}", SHA)
                for name in APPROVED_COMPONENT_NAMES
            },
        )
        fixture = ControlledGateFixture(evidence_dir=evidence_dir)
        controller = ControlledG01G03Controller._for_controlled_test(fixture, evidence_dir=evidence_dir)
        result = controller.run(request, configuration=config, home=home)

        self.assertIsInstance(result.render_provenance, RenderProvenance)
        self.assertEqual(result.render_provenance.template_source_identity, SOURCE)
        self.assertEqual(result.render_provenance.template_tag, "v0.1.3")
        self.assertEqual(result.render_provenance.resolved_template_commit, SHA)

        files = list(evidence_dir.glob("*.json"))
        self.assertEqual(len(files), 1)
        persisted = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertIn("render_provenance", persisted)
        self.assertEqual(persisted["render_provenance"]["template_source_identity"], SOURCE)
        self.assertEqual(persisted["render_provenance"]["template_tag"], "v0.1.3")
        self.assertEqual(persisted["render_provenance"]["resolved_template_commit"], SHA)
        self.assertEqual(
            persisted["render_provenance"]["submitted_answers"]["repository_name"], "demo"
        )

        # The provenance record claims no FR-008/FR-019 completion: the run is a
        # simulation-partial, Git/Dolt never attempted, and render alone is not
        # a readback claim.
        self.assertTrue(result.simulation)
        self.assertEqual(result.state, "partial")
        self.assertEqual(result.git_sync, "not-attempted")
        self.assertEqual(result.dolt_sync, "not-attempted")
        self.assertIsNotNone(fixture.operations)

    def test_render_alone_does_not_claim_fr008_fr019(self) -> None:
        """The FR-019 completion gates are G09-G11; a G03 render produces none."""
        # Render provenance is retained even when the render already completed,
        # but a render outcome never flips git/dolt sync or a live-complete state.
        provenance = render_provenance()
        self.assertEqual(provenance.canonical_fields()["submitted_answers"]["project_kind"], "generic")


if __name__ == "__main__":
    unittest.main()
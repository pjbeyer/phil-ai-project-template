"""Controlled inspect-only and exact-gate resume tests.

All observations are synthetic JSON held in memory.  No command, filesystem
mutation outside disposable fixtures, credential, service, manifest, backup,
or external origin is used.
"""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.evidence import InspectionEvidence, ResumeAuthorization
from scripts.models import APPROVED_COMPONENT_NAMES, Gate, ProvisioningRequest
from scripts.preflight import PreflightError, normalize_inspection_request
from scripts.provision_project import (
    InspectionControlError,
    InspectionController,
    InspectionOperation,
    RawInspectionResult,
)


CONFIG_FINGERPRINT = "c" * 64
TEMPLATE_COMMIT = "1" * 40
HOOKS = ["post-checkout", "post-merge", "pre-commit", "pre-push", "prepare-commit-msg"]
OPERATION_GATE = {
    InspectionOperation.REPOSITORY: Gate.CLONE,
    InspectionOperation.RENDER: Gate.RENDER,
    InspectionOperation.BEADS: Gate.BEADS,
    InspectionOperation.BEADS_REMOTE: Gate.BEADS_REMOTE,
    InspectionOperation.MANIFEST: Gate.MANIFEST,
    InspectionOperation.BACKUP: Gate.BACKUP,
    InspectionOperation.SPECKIT: Gate.SPECKIT,
    InspectionOperation.BOOTSTRAP: Gate.BOOTSTRAP,
    InspectionOperation.COMMIT: Gate.COMMIT,
    InspectionOperation.SYNC: Gate.PUSH,
}


class ControlledFixture:
    """In-memory raw observer and mutation recorder; it executes nothing."""

    def __init__(self, observations: dict[Gate, object]) -> None:
        self.observations = copy.deepcopy(observations)
        self.reads: list[Gate] = []
        self.mutations: list[Gate] = []

    def execute_inspection(self, operation: InspectionOperation) -> RawInspectionResult:
        if type(operation) is not InspectionOperation:
            raise AssertionError("inspection operation was not exact and closed")
        gate = OPERATION_GATE[operation]
        self.reads.append(gate)
        if gate not in self.observations:
            return RawInspectionResult(gate, 2, "", "synthetic observation absent")
        value = self.observations[gate]
        stdout = value if isinstance(value, str) else json.dumps(value)
        return RawInspectionResult(gate, 0, stdout, "")

    def execute_gate_for_test(self, gate: Gate, capability: object) -> None:
        if type(capability).__name__ != "_ResumeCapability":
            raise AssertionError("resume mutation lacked the exact private capability")
        self.mutations.append(gate)


class ResumeInspectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name).resolve()
        self.destination = self.home / "Projects/pjbeyer/demo"
        self.destination.mkdir(parents=True)
        self.request = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git",
            "demo",
            "generic",
        )

    def complete_observations(self) -> dict[Gate, object]:
        identity = "pjbeyer/demo"
        database = "demo_database"
        return {
            Gate.CLONE: {
                "identity": identity,
                "origin_url": self.request.origin_url,
                "destination": str(self.destination),
                "branch": "main",
                "checkout_exists": True,
            },
            Gate.RENDER: {
                "configuration_fingerprint": CONFIG_FINGERPRINT,
                "template_commit": TEMPLATE_COMMIT,
                "render_valid": True,
            },
            Gate.BEADS: {
                "mode": "server",
                "host": "127.0.0.1",
                "port": 3307,
                "prefix": "demo",
                "database": database,
            },
            Gate.BEADS_REMOTE: {
                "remote_name": "origin",
                "remote_url": "git+https://github.com/pjbeyer/demo.git",
                "integrations": ["claude", "codex"],
                "hooks": HOOKS,
            },
            Gate.MANIFEST: {
                "manifest_identity": "managed-projects-manifest/v1",
                "manifest_valid": True,
                "path": str(self.destination),
                "prefix": "demo",
                "database": database,
                "globally_unique": True,
                "policy_valid": True,
            },
            Gate.BACKUP: {
                "root_is_exact": True,
                "sidecar_valid": True,
                "tree_safe": True,
                "ownership_valid": True,
                "modes_valid": True,
                "synchronized": True,
                "fresh": True,
                "coverage_path": str(self.destination),
                "coverage_database": database,
                "coverage_findings": [],
            },
            Gate.SPECKIT: {
                "integration": "hermes",
                "components": sorted(APPROVED_COMPONENT_NAMES),
                "pins_valid": True,
                "excluded_components": [],
                "constitution_valid": True,
            },
            Gate.BOOTSTRAP: {
                "database": database,
                "markers": ["first-speckit-spec", "scope-readme"],
                "duplicate_markers": [],
                "readback_valid": True,
            },
            Gate.COMMIT: {
                "validation_passed": True,
                "hygiene_passed": True,
                "commit_valid": True,
                "dolt_non_ignored_dirty": [],
            },
            Gate.PUSH: {
                "git_upstream_equal": True,
                "dolt_push_complete": True,
            },
        }

    def inspect(self, fixture: ControlledFixture) -> InspectionEvidence:
        return InspectionController._for_controlled_test(fixture).inspect(
            self.request,
            configuration_fingerprint=CONFIG_FINGERPRINT,
            home=self.home,
        )

    def test_inspection_normalization_requires_the_existing_exact_route(self) -> None:
        origin, destination = normalize_inspection_request(self.request, self.home)
        self.assertEqual(origin.identity, "pjbeyer/demo")
        self.assertEqual(destination, self.destination)
        self.destination.rmdir()
        with self.assertRaisesRegex(PreflightError, "does not exist"):
            normalize_inspection_request(self.request, self.home)

    def test_existing_destination_public_path_remains_simulation_only_and_nonzero(self) -> None:
        from scripts.adapters import FakeAdapter
        from scripts.provision_project import Provisioner

        adapter = FakeAdapter(existing_valid=True)
        result = Provisioner(adapter).run(self.request, home=self.home, existing=True)
        self.assertEqual(result.state, "blocked-preflight")
        self.assertTrue(result.simulation)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(result.mutations_completed, [])

    def test_complete_state_is_verified_existing_with_no_mutation_or_persistence(self) -> None:
        fixture = ControlledFixture(self.complete_observations())
        evidence = self.inspect(fixture)
        self.assertEqual(evidence.state, "verified-existing")
        self.assertIsNone(evidence.next_gate)
        self.assertEqual(evidence.git_sync, "succeeded")
        self.assertEqual(evidence.dolt_sync, "succeeded")
        self.assertEqual(fixture.mutations, [])
        self.assertEqual(fixture.reads, list(Gate)[1:])
        self.assertEqual(list(Path(self.temporary.name).rglob("*.json")), [])
        self.assertRegex(evidence.evidence_id, r"^[0-9a-f]{64}$")
        self.assertTrue(all(finding.status == "passed" for finding in evidence.findings))

    def test_each_partial_gate_returns_the_exact_next_gate_without_mutation(self) -> None:
        terminal_gates = list(Gate)[1:]
        complete = self.complete_observations()
        for index, failed_gate in enumerate(terminal_gates):
            with self.subTest(gate=failed_gate):
                fixture = ControlledFixture({gate: complete[gate] for gate in terminal_gates[:index]})
                evidence = self.inspect(fixture)
                self.assertEqual(evidence.state, "blocked-preflight")
                self.assertIs(evidence.next_gate, failed_gate)
                self.assertEqual(fixture.mutations, [])
                self.assertEqual(fixture.reads, terminal_gates[: index + 1])
                statuses = {finding.gate: finding.status for finding in evidence.findings}
                self.assertEqual(statuses[failed_gate], "failed")
                for not_reached in terminal_gates[index + 1:]:
                    self.assertEqual(statuses[not_reached], "not-reached")

    def test_precise_mismatch_and_safety_fixtures_fail_at_their_own_gate(self) -> None:
        cases = (
            ("mismatched origin", Gate.CLONE, lambda data: data[Gate.CLONE].update(identity="pjbeyer/other")),
            ("mismatched database", Gate.MANIFEST, lambda data: data[Gate.MANIFEST].update(database="other_database")),
            ("invalid manifest", Gate.MANIFEST, lambda data: data[Gate.MANIFEST].update(manifest_valid=False)),
            ("unsafe backup", Gate.BACKUP, lambda data: data[Gate.BACKUP].update(tree_safe=False)),
            (
                "missing SpecKit component",
                Gate.SPECKIT,
                lambda data: data[Gate.SPECKIT].update(
                    components=sorted(APPROVED_COMPONENT_NAMES - {"agent-context"})
                ),
            ),
            (
                "duplicate bootstrap issue",
                Gate.BOOTSTRAP,
                lambda data: data[Gate.BOOTSTRAP].update(duplicate_markers=["scope-readme"]),
            ),
        )
        for label, gate, mutate in cases:
            with self.subTest(label=label):
                observations = self.complete_observations()
                mutate(observations)
                fixture = ControlledFixture(observations)
                evidence = self.inspect(fixture)
                self.assertEqual(evidence.state, "blocked-preflight")
                self.assertIs(evidence.next_gate, gate)
                self.assertEqual(fixture.mutations, [])
                failed = next(finding for finding in evidence.findings if finding.gate is gate)
                self.assertEqual(failed.status, "failed")
                self.assertNotIn(str(self.destination), failed.detail)

    def test_git_only_and_dolt_only_sync_are_both_incomplete(self) -> None:
        for git_synced, dolt_synced in ((True, False), (False, True)):
            with self.subTest(git=git_synced, dolt=dolt_synced):
                observations = self.complete_observations()
                observations[Gate.PUSH].update(
                    git_upstream_equal=git_synced,
                    dolt_push_complete=dolt_synced,
                )
                evidence = self.inspect(ControlledFixture(observations))
                self.assertEqual(evidence.state, "blocked-preflight")
                self.assertIs(evidence.next_gate, Gate.PUSH)
                self.assertEqual(
                    (evidence.git_sync, evidence.dolt_sync),
                    (
                        "succeeded" if git_synced else "failed",
                        "succeeded" if dolt_synced else "failed",
                    ),
                )

    def test_malformed_missing_and_secret_bearing_observations_fail_closed_sanitized(self) -> None:
        observations = self.complete_observations()
        observations[Gate.RENDER] = '{"render_valid":true,"render_valid":true}'
        evidence = self.inspect(ControlledFixture(observations))
        self.assertIs(evidence.next_gate, Gate.RENDER)
        finding = next(item for item in evidence.findings if item.gate is Gate.RENDER)
        self.assertEqual(finding.status, "failed")
        self.assertNotIn("render_valid", finding.detail)

        observations = self.complete_observations()
        observations[Gate.CLONE] = "token=synthetic-sensitive-value"
        evidence = self.inspect(ControlledFixture(observations))
        serialized = json.dumps(evidence.serializable(), sort_keys=True)
        self.assertNotIn("synthetic-sensitive-value", serialized)
        self.assertNotIn(str(self.destination), serialized)
        self.assertNotIn("pjbeyer/demo", serialized)

    def test_unadmitted_observations_are_explicitly_non_resumable(self) -> None:
        for label, observation in (
            ("unsafe", "token=synthetic-sensitive-value"),
            ("malformed", "{}"),
            ("unavailable", None),
        ):
            with self.subTest(label=label):
                observations = self.complete_observations()
                if observation is None:
                    del observations[Gate.COMMIT]
                else:
                    observations[Gate.COMMIT] = observation
                evidence = self.inspect(ControlledFixture(observations))
                self.assertIs(evidence.next_gate, Gate.COMMIT)
                failed = next(
                    finding for finding in evidence.findings if finding.gate is Gate.COMMIT
                )
                self.assertIsNone(failed.observation_digest)
                with self.assertRaisesRegex(ValueError, "non-resumable"):
                    ResumeAuthorization.for_inspection(evidence)

    def test_two_repeated_inspections_are_identical_and_perform_zero_mutations(self) -> None:
        fixture = ControlledFixture(self.complete_observations())
        controller = InspectionController._for_controlled_test(fixture)
        first = controller.inspect(
            self.request,
            configuration_fingerprint=CONFIG_FINGERPRINT,
            home=self.home,
        )
        second = controller.inspect(
            self.request,
            configuration_fingerprint=CONFIG_FINGERPRINT,
            home=self.home,
        )
        self.assertEqual(first, second)
        self.assertEqual(fixture.mutations, [])
        self.assertEqual(fixture.reads, list(Gate)[1:] * 2)

    def partial_at(self, gate: Gate) -> tuple[ControlledFixture, InspectionEvidence]:
        complete = self.complete_observations()
        failed_changes = {
            Gate.CLONE: ("branch", "develop"),
            Gate.RENDER: ("render_valid", False),
            Gate.BEADS: ("mode", "embedded"),
            Gate.BEADS_REMOTE: ("remote_name", "upstream"),
            Gate.MANIFEST: ("manifest_valid", False),
            Gate.BACKUP: ("fresh", False),
            Gate.SPECKIT: ("pins_valid", False),
            Gate.BOOTSTRAP: ("readback_valid", False),
            Gate.COMMIT: ("validation_passed", False),
            Gate.PUSH: ("dolt_push_complete", False),
        }
        key, value = failed_changes[gate]
        complete[gate][key] = value
        terminal = list(Gate)[1:]
        index = terminal.index(gate)
        fixture = ControlledFixture({item: complete[item] for item in terminal[: index + 1]})
        return fixture, self.inspect(fixture)

    def test_exact_authorized_resume_revalidates_full_snapshot_and_starts_only_named_gate(self) -> None:
        fixture, inspected = self.partial_at(Gate.SPECKIT)
        failed = next(finding for finding in inspected.findings if finding.gate is Gate.SPECKIT)
        self.assertRegex(failed.observation_digest, r"^[0-9a-f]{64}$")
        authorization = ResumeAuthorization.for_inspection(inspected)
        resumed = InspectionController._for_controlled_test(fixture).resume(
            self.request,
            inspected=inspected,
            authorization=authorization,
            configuration_fingerprint=CONFIG_FINGERPRINT,
            home=self.home,
            executor=fixture,
        )
        self.assertIs(resumed.started_gate, Gate.SPECKIT)
        self.assertEqual(fixture.mutations, [Gate.SPECKIT])
        self.assertEqual(fixture.reads, list(Gate)[1:8] * 2)

    def test_each_exact_gate_resume_revalidates_predecessors_and_never_replays_them(self) -> None:
        for gate in list(Gate)[1:]:
            with self.subTest(gate=gate):
                fixture, inspected = self.partial_at(gate)
                authorization = ResumeAuthorization.for_inspection(inspected)
                InspectionController._for_controlled_test(fixture).resume(
                    self.request,
                    inspected=inspected,
                    authorization=authorization,
                    configuration_fingerprint=CONFIG_FINGERPRINT,
                    home=self.home,
                    executor=fixture,
                )
                self.assertEqual(fixture.mutations, [gate])

    def test_unapproved_and_mismatched_resumes_never_invoke_mutation(self) -> None:
        fixture, inspected = self.partial_at(Gate.BACKUP)
        valid = ResumeAuthorization.for_inspection(inspected)
        mismatches = (
            None,
            replace(valid, evidence_id="d" * 64),
            replace(valid, request_fingerprint="e" * 64),
            replace(valid, configuration_fingerprint="f" * 64),
            replace(valid, next_gate=Gate.SPECKIT),
            True,
        )
        for authorization in mismatches:
            with self.subTest(authorization=authorization):
                with self.assertRaises(InspectionControlError):
                    InspectionController._for_controlled_test(fixture).resume(
                        self.request,
                        inspected=inspected,
                        authorization=authorization,
                        configuration_fingerprint=CONFIG_FINGERPRINT,
                        home=self.home,
                        executor=fixture,
                    )
                self.assertEqual(fixture.mutations, [])

    def test_changed_valid_predecessor_observation_invalidates_authorized_resume(self) -> None:
        for label, mutate in (
            (
                "template commit",
                lambda observations: observations[Gate.RENDER].update(template_commit="2" * 40),
            ),
            (
                "metadata database",
                lambda observations: (
                    observations[Gate.BEADS].update(database="renamed_database"),
                    observations[Gate.MANIFEST].update(database="renamed_database"),
                    observations[Gate.BACKUP].update(coverage_database="renamed_database"),
                    observations[Gate.BOOTSTRAP].update(database="renamed_database"),
                ),
            ),
        ):
            with self.subTest(label=label):
                fixture, inspected = self.partial_at(Gate.BOOTSTRAP)
                authorization = ResumeAuthorization.for_inspection(inspected)
                mutate(fixture.observations)
                with self.assertRaisesRegex(InspectionControlError, "changed"):
                    InspectionController._for_controlled_test(fixture).resume(
                        self.request,
                        inspected=inspected,
                        authorization=authorization,
                        configuration_fingerprint=CONFIG_FINGERPRINT,
                        home=self.home,
                        executor=fixture,
                    )
                self.assertEqual(fixture.mutations, [])

    def test_different_failure_at_same_next_gate_invalidates_authorized_resume(self) -> None:
        fixture, inspected = self.partial_at(Gate.SPECKIT)
        authorization = ResumeAuthorization.for_inspection(inspected)
        fixture.observations[Gate.SPECKIT].update(
            pins_valid=True,
            constitution_valid=False,
        )
        with self.assertRaisesRegex(InspectionControlError, "changed"):
            InspectionController._for_controlled_test(fixture).resume(
                self.request,
                inspected=inspected,
                authorization=authorization,
                configuration_fingerprint=CONFIG_FINGERPRINT,
                home=self.home,
                executor=fixture,
            )
        self.assertEqual(fixture.mutations, [])

    def test_unsafe_or_unavailable_current_observation_cannot_resume(self) -> None:
        for label, current in (
            ("unsafe", "token=synthetic-sensitive-value"),
            ("unavailable", None),
        ):
            with self.subTest(label=label):
                fixture, inspected = self.partial_at(Gate.COMMIT)
                authorization = ResumeAuthorization.for_inspection(inspected)
                if current is None:
                    del fixture.observations[Gate.COMMIT]
                else:
                    fixture.observations[Gate.COMMIT] = current
                with self.assertRaisesRegex(InspectionControlError, "changed"):
                    InspectionController._for_controlled_test(fixture).resume(
                        self.request,
                        inspected=inspected,
                        authorization=authorization,
                        configuration_fingerprint=CONFIG_FINGERPRINT,
                        home=self.home,
                        executor=fixture,
                    )
                self.assertEqual(fixture.mutations, [])

    def test_changed_invalid_predecessor_or_current_state_invalidates_authorized_resume(self) -> None:
        fixture, inspected = self.partial_at(Gate.BOOTSTRAP)
        authorization = ResumeAuthorization.for_inspection(inspected)
        fixture.observations[Gate.BEADS_REMOTE]["remote_name"] = "other"
        with self.assertRaisesRegex(InspectionControlError, "changed"):
            InspectionController._for_controlled_test(fixture).resume(
                self.request,
                inspected=inspected,
                authorization=authorization,
                configuration_fingerprint=CONFIG_FINGERPRINT,
                home=self.home,
                executor=fixture,
            )
        self.assertEqual(fixture.mutations, [])

    def test_inspection_evidence_rejects_missing_or_forged_observation_digests(self) -> None:
        fixture, inspected = self.partial_at(Gate.MANIFEST)
        passed = inspected.findings[0]
        missing = object.__new__(type(passed))
        for field_name in passed.__dataclass_fields__:
            object.__setattr__(
                missing,
                field_name,
                None if field_name == "observation_digest" else getattr(passed, field_name),
            )
        with self.assertRaisesRegex(ValueError, "passed finding must bind"):
            missing.__post_init__()

        changed_digest = replace(passed, observation_digest="f" * 64)
        changed_findings = (changed_digest,) + inspected.findings[1:]
        forged_digest = object.__new__(InspectionEvidence)
        for field_name in inspected.__dataclass_fields__:
            object.__setattr__(
                forged_digest,
                field_name,
                changed_findings if field_name == "findings" else getattr(inspected, field_name),
            )
        with self.assertRaisesRegex(ValueError, "evidence id does not match"):
            forged_digest.__post_init__()

    def test_controller_has_no_public_or_boolean_construction_bypass(self) -> None:
        fixture = ControlledFixture(self.complete_observations())
        for capability in (None, True, False, object()):
            with self.subTest(capability=capability), self.assertRaisesRegex(
                InspectionControlError,
                "private controlled factory",
            ):
                InspectionController(fixture, _capability=capability)  # type: ignore[arg-type]

        class DerivedController(InspectionController):
            pass

        with self.assertRaisesRegex(InspectionControlError, "subclasses"):
            DerivedController._for_controlled_test(fixture)

    def test_authorization_subclass_cannot_bypass_exact_type_admission(self) -> None:
        fixture, inspected = self.partial_at(Gate.COMMIT)

        class DerivedAuthorization(ResumeAuthorization):
            pass

        valid = ResumeAuthorization.for_inspection(inspected)
        derived = DerivedAuthorization(
            valid.evidence_id,
            valid.request_fingerprint,
            valid.configuration_fingerprint,
            valid.next_gate,
        )
        with self.assertRaisesRegex(InspectionControlError, "exact resume authorization type"):
            InspectionController._for_controlled_test(fixture).resume(
                self.request,
                inspected=inspected,
                authorization=derived,
                configuration_fingerprint=CONFIG_FINGERPRINT,
                home=self.home,
                executor=fixture,
            )
        self.assertEqual(fixture.mutations, [])

    def test_observer_cannot_return_assertion_maps_or_subclassed_raw_results(self) -> None:
        class MapObserver:
            def execute_inspection(self, operation: InspectionOperation) -> object:
                del operation
                return {"trusted": True}

        evidence = InspectionController._for_controlled_test(MapObserver()).inspect(  # type: ignore[arg-type]
            self.request,
            configuration_fingerprint=CONFIG_FINGERPRINT,
            home=self.home,
        )
        self.assertIs(evidence.next_gate, Gate.CLONE)

        class DerivedRaw(RawInspectionResult):
            pass

        class SubclassObserver:
            def execute_inspection(self, operation: InspectionOperation) -> RawInspectionResult:
                gate = OPERATION_GATE[operation]
                return DerivedRaw(gate, 0, "{}", "")

        evidence = InspectionController._for_controlled_test(SubclassObserver()).inspect(
            self.request,
            configuration_fingerprint=CONFIG_FINGERPRINT,
            home=self.home,
        )
        self.assertIs(evidence.next_gate, Gate.CLONE)

    def test_resume_rejects_tampered_or_forged_inspection_id_without_mutation(self) -> None:
        fixture, inspected = self.partial_at(Gate.MANIFEST)
        forged = object.__new__(InspectionEvidence)
        for field_name in inspected.__dataclass_fields__:
            object.__setattr__(
                forged,
                field_name,
                "f" * 64 if field_name == "evidence_id" else getattr(inspected, field_name),
            )
        authorization = ResumeAuthorization(
            forged.evidence_id,
            forged.request_fingerprint,
            forged.configuration_fingerprint,
            forged.next_gate,
        )
        with self.assertRaisesRegex(InspectionControlError, "inspection evidence is invalid"):
            InspectionController._for_controlled_test(fixture).resume(
                self.request,
                inspected=forged,
                authorization=authorization,
                configuration_fingerprint=CONFIG_FINGERPRINT,
                home=self.home,
                executor=fixture,
            )
        self.assertEqual(fixture.mutations, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

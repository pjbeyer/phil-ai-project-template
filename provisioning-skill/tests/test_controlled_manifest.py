"""Failure-first tests for the isolated controlled-G06 manifest controller.

All filesystem state is synthetic and confined to ``TemporaryDirectory``.  The
controller has no subprocess, network, credential, service, public-CLI, G07, or
``LiveAdapter`` path.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.adapters as adapters
import scripts.controlled_manifest as controlled_manifest
import scripts.provision_project as provision_project
from scripts.controlled_manifest import (
    ControlledManifestController,
    ControlledManifestError,
    ControlledManifestRequest,
)
from scripts.manifest import AppendResult, append_record


REQUIRED_JOBS = [
    "Hermes: Beads health review",
    "Hermes: compliance audit",
    "Hermes: Beads Dolt maintenance",
    "Hermes: Beads Dolt integrity review",
]


def manifest_record(path: Path, prefix: str, database: str) -> dict[str, object]:
    return {
        "path": str(path),
        "prefix": prefix,
        "database": database,
        "owner": "personal",
        "project_kind": "generic",
        "visibility": "personal-only",
        "profile": "default",
        "expected_remote": "origin",
        "expected_backup": True,
        "expected_sync": "manual-dolt-remote",
        "owning_jobs": list(REQUIRED_JOBS),
        "remote_health": "required",
        "restore_tier": "rotating",
    }


class ControlledManifestTests(unittest.TestCase):
    def make_case(
        self,
        *,
        records: list[dict[str, object]] | None = None,
        raw: bytes | None = None,
    ) -> tuple[
        Path,
        Path,
        Path,
        Path,
        ControlledManifestRequest,
        ControlledManifestController,
    ]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        evidence = root / "evidence"
        evidence.mkdir(mode=0o700)
        destination = root / "repository"
        destination.mkdir(mode=0o700)
        manifest = root / "manifest.json"
        if raw is None:
            raw = json.dumps({"repositories": records or []}).encode("utf-8")
        manifest.write_bytes(raw)
        request = ControlledManifestRequest(destination, "demo", "demo_database")
        controller = ControlledManifestController._for_controlled_test(fixture_root=root)
        return root, evidence, destination, manifest, request, controller

    @staticmethod
    def evidence_payloads(directory: Path) -> list[dict[str, object]]:
        return [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(directory.glob("*.json"))
        ]

    def assert_partial_attempt_without_completion(self, directory: Path) -> dict[str, object]:
        payloads = self.evidence_payloads(directory)
        self.assertEqual(len(payloads), 1)
        payload = payloads[0]
        self.assertEqual(payload["state"], "partial")
        self.assertEqual(payload["failed_gate"], "G06")
        self.assertEqual(payload["mutation_attempts"], ["G06:controlled-manifest-append"])
        self.assertEqual(payload["mutations_completed"], [])
        self.assertIn("blocked", str(payload["next_action"]).lower())
        self.assertIn("deferred", str(payload["next_action"]).lower())
        return payload

    def test_factory_is_private_exact_and_rejects_nonfixture_paths(self) -> None:
        root, evidence, _, manifest, _, _ = self.make_case()
        with self.assertRaisesRegex(ControlledManifestError, "private controlled-test factory"):
            ControlledManifestController(fixture_root=root)

        class Subclass(ControlledManifestController):
            pass

        with self.assertRaisesRegex(ControlledManifestError, "subclasses"):
            Subclass._for_controlled_test(fixture_root=root)

        outside = root.parent / f"{root.name}-outside.json"
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        outside.write_text('{"repositories": []}', encoding="utf-8")
        for supplied_root in (root / "missing", manifest, outside.parent / "absent-root"):
            with self.subTest(root=supplied_root), self.assertRaises(ControlledManifestError):
                ControlledManifestController._for_controlled_test(fixture_root=supplied_root)

        evidence.rename(root / "saved-evidence")
        evidence.symlink_to(root / "saved-evidence", target_is_directory=True)
        with self.assertRaises(ControlledManifestError):
            ControlledManifestController._for_controlled_test(fixture_root=root)

    def test_success_is_exact_persisted_and_defers_coverage_without_execution(self) -> None:
        baseline_root, evidence, destination, manifest, request, controller = self.make_case()
        baseline = manifest_record(baseline_root / "legacy", "legacy", "legacy_database")
        manifest.write_text(json.dumps({"repositories": [baseline]}), encoding="utf-8")
        candidate = manifest_record(destination, request.prefix, request.metadata_database)

        controller.reserve(request)
        result = controller.append(candidate)

        committed = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(committed["repositories"], [baseline, candidate])
        self.assertEqual(result.state, "partial")
        self.assertIsNone(result.failed_gate)
        self.assertEqual(result.mutation_attempts, ["G06:controlled-manifest-append"])
        self.assertEqual(result.mutations_completed, result.mutation_attempts)
        self.assertEqual([(item.gate.value, item.status) for item in result.gates], [("G06", "passed")])
        self.assertIn("blocked", result.next_action.lower())
        self.assertIn("deferred", result.next_action.lower())
        self.assertIn("not executed", result.next_action.lower())
        payloads = self.evidence_payloads(evidence)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["mutations_completed"], ["G06:controlled-manifest-append"])
        self.assertEqual(payloads[0]["destination"], "[REDACTED]")

    def test_reservation_is_required_and_does_not_touch_manifest(self) -> None:
        _, evidence, destination, manifest, request, controller = self.make_case()
        before = manifest.read_bytes()
        with self.assertRaisesRegex(ControlledManifestError, "reservation is required"):
            controller.append(manifest_record(destination, request.prefix, request.metadata_database))
        self.assertEqual(manifest.read_bytes(), before)
        self.assertEqual(self.evidence_payloads(evidence), [])

    def test_reservation_rejects_each_existing_tuple_conflict(self) -> None:
        for field in ("path", "prefix", "database"):
            with self.subTest(field=field):
                root, evidence, destination, manifest, request, controller = self.make_case()
                existing = manifest_record(root / "other", "other", "other_database")
                existing[field] = {
                    "path": str(destination),
                    "prefix": request.prefix,
                    "database": request.metadata_database,
                }[field]
                manifest.write_text(json.dumps({"repositories": [existing]}), encoding="utf-8")
                before = manifest.read_bytes()
                with self.assertRaisesRegex(ControlledManifestError, "conflict"):
                    controller.reserve(request)
                self.assertEqual(manifest.read_bytes(), before)
                self.assertEqual(self.evidence_payloads(evidence), [])

    def test_conflicting_append_race_is_partial_and_candidate_is_not_written(self) -> None:
        root, evidence, destination, manifest, request, controller = self.make_case()
        candidate = manifest_record(destination, request.prefix, request.metadata_database)
        racer = manifest_record(destination, "racer", "racer_database")
        controller.reserve(request)
        real_append = append_record

        def race_then_append(path: Path, snapshot: dict[str, object]) -> AppendResult:
            real_append(path, racer)
            return real_append(path, snapshot)

        with patch("scripts.controlled_manifest.append_record", side_effect=race_then_append):
            with self.assertRaisesRegex(ControlledManifestError, "compare-and-append"):
                controller.append(candidate)

        self.assertEqual(json.loads(manifest.read_text())["repositories"], [racer])
        self.assertNotIn(candidate, json.loads(manifest.read_text())["repositories"])
        self.assert_partial_attempt_without_completion(evidence)
        self.assertEqual(root / "manifest.json", manifest)

    def test_reservation_rejects_malformed_manifest_byte_identically(self) -> None:
        cases = (
            b"not-json",
            b'{"repositories": [], "repositories": []}',
            b'{"repositories": [{"path": "/broken"}]}',
        )
        for raw in cases:
            with self.subTest(raw=raw):
                _, evidence, _, manifest, request, controller = self.make_case(raw=raw)
                with self.assertRaisesRegex(ControlledManifestError, "reservation"):
                    controller.reserve(request)
                self.assertEqual(manifest.read_bytes(), raw)
                self.assertEqual(self.evidence_payloads(evidence), [])

    def test_invalid_or_mutated_candidate_is_rejected_and_cannot_retry(self) -> None:
        _, evidence, destination, manifest, request, controller = self.make_case()
        candidate = manifest_record(destination, request.prefix, request.metadata_database)
        controller.reserve(request)
        candidate["database"] = "changed_after_reservation"

        with self.assertRaisesRegex(ControlledManifestError, "authoritative tuple"):
            controller.append(candidate)
        self.assertEqual(json.loads(manifest.read_text())["repositories"], [])
        payloads = self.evidence_payloads(evidence)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["mutation_attempts"], [])
        with self.assertRaisesRegex(ControlledManifestError, "retry is forbidden"):
            controller.append(manifest_record(destination, request.prefix, request.metadata_database))

    def test_candidate_is_defensively_snapshotted_against_caller_mutation(self) -> None:
        _, evidence, destination, manifest, request, controller = self.make_case()
        candidate = manifest_record(destination, request.prefix, request.metadata_database)
        expected = json.loads(json.dumps(candidate))
        controller.reserve(request)
        real_append = append_record

        def mutate_caller(path: Path, snapshot: dict[str, object]) -> AppendResult:
            candidate["owner"] = "changed-by-caller"
            jobs = candidate["owning_jobs"]
            assert isinstance(jobs, list)
            jobs.clear()
            return real_append(path, snapshot)

        with patch("scripts.controlled_manifest.append_record", side_effect=mutate_caller):
            controller.append(candidate)

        self.assertEqual(json.loads(manifest.read_text())["repositories"], [expected])
        self.assertEqual(
            self.evidence_payloads(evidence)[0]["mutations_completed"],
            ["G06:controlled-manifest-append"],
        )

    def test_exact_builtin_candidate_shape_is_required(self) -> None:
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        for mutation in ("mapping-subclass", "list-subclass", "bool-subclass-shape"):
            with self.subTest(mutation=mutation):
                _, evidence, destination, manifest, request, controller = self.make_case()
                ordinary = manifest_record(destination, request.prefix, request.metadata_database)
                if mutation == "mapping-subclass":
                    candidate: object = DictSubclass(ordinary)
                elif mutation == "list-subclass":
                    ordinary["owning_jobs"] = ListSubclass(REQUIRED_JOBS)
                    candidate = ordinary
                else:
                    ordinary["expected_backup"] = 1
                    candidate = ordinary
                controller.reserve(request)
                with self.assertRaisesRegex(ControlledManifestError, "exact controlled shape"):
                    controller.append(candidate)  # type: ignore[arg-type]
                self.assertEqual(json.loads(manifest.read_text())["repositories"], [])
                self.assertEqual(self.evidence_payloads(evidence)[0]["mutations_completed"], [])

    def test_fabricated_append_results_are_rejected_without_completion(self) -> None:
        for case in (
            "wrong-type",
            "extra-record",
            "bad-digest",
            "noncanonical-raw",
            "valid-but-not-written",
        ):
            with self.subTest(case=case):
                root, evidence, destination, manifest, request, controller = self.make_case()
                candidate = manifest_record(destination, request.prefix, request.metadata_database)
                controller.reserve(request)
                exact_manifest = {"repositories": [candidate]}
                canonical = (json.dumps(exact_manifest, indent=2, sort_keys=False) + "\n").encode()
                if case == "wrong-type":
                    returned: object = object()
                elif case == "extra-record":
                    extra = manifest_record(root / "extra", "extra", "extra_database")
                    wrong = {"repositories": [candidate, extra]}
                    raw = (json.dumps(wrong, indent=2, sort_keys=False) + "\n").encode()
                    returned = AppendResult(wrong, candidate, hashlib.sha256(raw).hexdigest(), raw)
                elif case == "bad-digest":
                    returned = AppendResult(exact_manifest, candidate, "0" * 64, canonical)
                elif case == "noncanonical-raw":
                    raw = json.dumps(exact_manifest, separators=(",", ":")).encode()
                    returned = AppendResult(
                        exact_manifest,
                        candidate,
                        hashlib.sha256(raw).hexdigest(),
                        raw,
                    )
                else:
                    returned = AppendResult(
                        exact_manifest,
                        candidate,
                        hashlib.sha256(canonical).hexdigest(),
                        canonical,
                    )
                expected_error = "binding" if case == "valid-but-not-written" else "append result"
                with patch("scripts.controlled_manifest.append_record", return_value=returned):
                    with self.assertRaisesRegex(ControlledManifestError, expected_error):
                        controller.append(candidate)
                self.assertEqual(json.loads(manifest.read_text())["repositories"], [])
                self.assert_partial_attempt_without_completion(evidence)

    def test_manifest_leaf_replacement_before_append_refuses_write_and_completion(self) -> None:
        _, evidence, destination, manifest, request, controller = self.make_case()
        candidate = manifest_record(destination, request.prefix, request.metadata_database)
        controller.reserve(request)
        replacement_raw = b'{"repositories": [], "replacement": true}'
        replacement = manifest.with_name("replacement.json")
        replacement.write_bytes(replacement_raw)
        replacement.replace(manifest)

        with self.assertRaisesRegex(ControlledManifestError, "binding"):
            controller.append(candidate)

        self.assertEqual(manifest.read_bytes(), replacement_raw)
        self.assert_partial_attempt_without_completion(evidence)

    def test_manifest_leaf_replacement_immediately_before_completion_is_preserved(self) -> None:
        _, evidence, destination, manifest, request, controller = self.make_case()
        candidate = manifest_record(destination, request.prefix, request.metadata_database)
        controller.reserve(request)
        replacement_raw = b'{"repositories": [], "replacement": "late"}'

        def replace_before_completion() -> None:
            replacement = manifest.with_name("late-replacement.json")
            replacement.write_bytes(replacement_raw)
            replacement.replace(manifest)

        with patch.object(
            controller,
            "_before_completion_for_controlled_test",
            side_effect=replace_before_completion,
        ):
            with self.assertRaisesRegex(ControlledManifestError, "binding"):
                controller.append(candidate)

        self.assertEqual(manifest.read_bytes(), replacement_raw)
        self.assert_partial_attempt_without_completion(evidence)

    def test_evidence_leaf_swap_never_writes_replacement(self) -> None:
        root, evidence, destination, manifest, request, controller = self.make_case()
        candidate = manifest_record(destination, request.prefix, request.metadata_database)
        controller.reserve(request)
        original_evidence = root / "evidence-original"
        real_append = append_record

        def swap_evidence_then_append(path: Path, snapshot: dict[str, object]) -> AppendResult:
            evidence.rename(original_evidence)
            evidence.mkdir(mode=0o700)
            return real_append(path, snapshot)

        with patch("scripts.controlled_manifest.append_record", side_effect=swap_evidence_then_append):
            with self.assertRaisesRegex(ControlledManifestError, "binding"):
                controller.append(candidate)

        self.assertEqual(list(evidence.iterdir()), [])
        original_payloads = self.evidence_payloads(original_evidence)
        self.assertEqual(len(original_payloads), 1)
        self.assertEqual(original_payloads[0]["mutation_attempts"], ["G06:controlled-manifest-append"])
        self.assertEqual(original_payloads[0]["mutations_completed"], [])
        self.assertEqual(json.loads(manifest.read_text())["repositories"], [candidate])

    def test_success_and_failure_are_both_single_use_without_retry(self) -> None:
        _, _, destination, _, request, controller = self.make_case()
        candidate = manifest_record(destination, request.prefix, request.metadata_database)
        controller.reserve(request)
        controller.append(candidate)
        with self.assertRaisesRegex(ControlledManifestError, "retry is forbidden"):
            controller.append(candidate)
        with self.assertRaisesRegex(ControlledManifestError, "single-use"):
            controller.reserve(request)

        _, _, other_destination, _, other_request, failed = self.make_case()
        invalid = manifest_record(other_destination, other_request.prefix, "wrong")
        failed.reserve(other_request)
        with self.assertRaises(ControlledManifestError):
            failed.append(invalid)
        with self.assertRaisesRegex(ControlledManifestError, "retry is forbidden"):
            failed.append(
                manifest_record(
                    other_destination,
                    other_request.prefix,
                    other_request.metadata_database,
                )
            )

    def test_controller_has_no_live_adapter_public_cli_subprocess_or_network_wiring(self) -> None:
        source = inspect.getsource(controlled_manifest)
        lowered = source.lower()
        self.assertNotIn("liveadapter", lowered)
        self.assertNotIn("subprocess", lowered)
        self.assertNotIn("socket", lowered)
        self.assertNotIn("urllib", lowered)
        self.assertNotIn("coverage_script", lowered)
        self.assertNotIn("controlled_manifest", inspect.getsource(adapters))
        public_source = inspect.getsource(provision_project)
        self.assertNotIn("controlled_manifest", public_source)
        self.assertNotIn('add_argument("--live"', public_source)
        self.assertIn("Provisioner(FakeAdapter())", public_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Failure-first tests for the private controlled-G07 fixture controller.

Every state transition is synthetic and confined to ``TemporaryDirectory``.
The controller never reaches the quarantined adapter, public CLI, external
commands, services, credentials, origins, or an executable coverage script.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import inspect
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts._controlled_g07 as controlled_g07
import scripts.adapters as adapters
import scripts.provision_project as provision_project
from scripts._controlled_g07 import (
    ControlledG07Error,
    ControlledG07Request,
    _ControlledG07Controller,
    _controlled_g07_for_test,
)
from scripts.models import Gate, GateResult, ProvisioningEvidence
from scripts.controlled_manifest import (
    ControlledManifestController,
    ControlledManifestRequest,
)


REQUIRED_JOBS = [
    "Hermes: Beads health review",
    "Hermes: compliance audit",
    "Hermes: Beads Dolt maintenance",
    "Hermes: Beads Dolt integrity review",
]
G06_ATTEMPT = "G06:controlled-manifest-append"
G07_INIT = "G07:controlled-backup-init"
G07_SYNC = "G07:controlled-backup-sync"


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


class ControlledG07Tests(unittest.TestCase):
    def make_case(self) -> dict[str, object]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        evidence = root / "evidence"
        evidence.mkdir(mode=0o700)
        destination = root / "repository"
        beads = destination / ".beads"
        beads.mkdir(parents=True, mode=0o700)
        beads.chmod(0o700)
        metadata = beads / "metadata.json"
        metadata.write_text(
            json.dumps(
                {
                    "dolt_mode": "server",
                    "dolt_server_port": 3307,
                    "dolt_database": "demo_database",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        metadata.chmod(0o600)
        manifest = root / "manifest.json"
        manifest.write_text('{"repositories": []}', encoding="utf-8")
        manifest_request = ControlledManifestRequest(
            destination,
            "demo",
            "demo_database",
        )
        manifest_controller = ControlledManifestController._for_controlled_test(
            fixture_root=root
        )
        manifest_controller.reserve(manifest_request)
        g06_evidence = manifest_controller.append(
            manifest_record(destination, "demo", "demo_database")
        )
        g06_path = evidence / (
            f"{g06_evidence.request_fingerprint}-{g06_evidence.run_id}.json"
        )
        request = ControlledG07Request(destination, "demo", "demo_database")
        controller = _controlled_g07_for_test(
            fixture_root=root,
            request=request,
            g06_evidence=g06_evidence,
        )
        return {
            "temporary": temporary,
            "root": root,
            "evidence": evidence,
            "destination": destination,
            "beads": beads,
            "metadata": metadata,
            "manifest": manifest,
            "g06_evidence": g06_evidence,
            "g06_path": g06_path,
            "request": request,
            "controller": controller,
        }

    @staticmethod
    def payloads(evidence: Path) -> list[dict[str, object]]:
        return [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(evidence.glob("*.json"))
        ]

    def g07_payload(self, case: dict[str, object]) -> dict[str, object]:
        evidence = case["evidence"]
        g06 = case["g06_evidence"]
        assert isinstance(evidence, Path)
        payloads = self.payloads(evidence)
        matches = [
            item
            for item in payloads
            if item.get("run_id") not in {None, g06.run_id}
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def assert_g07_failure(
        self,
        case: dict[str, object],
        *,
        attempts: list[str],
        completed: list[str],
        g06_proven: bool = True,
    ) -> dict[str, object]:
        payload = self.g07_payload(case)
        self.assertEqual(payload["state"], "partial")
        self.assertEqual(payload["failed_gate"], "G07")
        self.assertEqual(payload["mutation_attempts"], [G06_ATTEMPT, *attempts])
        self.assertEqual(payload["mutations_completed"], [G06_ATTEMPT, *completed])
        gates = payload["gates"]
        expected_g06_status = "passed" if g06_proven else "failed"
        self.assertEqual(
            [(item["gate"], item["status"]) for item in gates],
            [("G06", expected_g06_status), ("G07", "failed")],
        )
        self.assertIn("partial", str(payload["next_action"]).lower())
        self.assertIn("inspection", str(payload["next_action"]).lower())
        return payload

    def test_factory_is_private_exact_single_use_and_disposable_only(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        g06 = case["g06_evidence"]
        assert isinstance(root, Path)
        with self.assertRaisesRegex(ControlledG07Error, "private controlled-test factory"):
            _ControlledG07Controller(
                fixture_root=root,
                request=request,
                g06_evidence=g06,
            )

        class Subclass(_ControlledG07Controller):
            pass

        with self.assertRaisesRegex(ControlledG07Error, "subclasses"):
            Subclass._for_controlled_test(
                fixture_root=root,
                request=request,
                g06_evidence=g06,
            )

        outside = root.parent / f"unsafe-{root.name}-outside"
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        outside.mkdir()
        outside_request = ControlledG07Request(
            outside / "repository", "demo", "demo_database"
        )
        with self.assertRaisesRegex(ControlledG07Error, "disposable temporary fixture"):
            _controlled_g07_for_test(
                fixture_root=outside,
                request=outside_request,
                g06_evidence=g06,
            )

        controller = case["controller"]
        controller.run()
        with self.assertRaisesRegex(ControlledG07Error, "single-use"):
            controller.run()

    def test_success_is_descriptor_validated_and_never_changes_g06_artifacts(self) -> None:
        case = self.make_case()
        manifest = case["manifest"]
        g06_path = case["g06_path"]
        controller = case["controller"]
        assert isinstance(manifest, Path)
        assert isinstance(g06_path, Path)
        before_manifest = manifest.read_bytes()
        before_g06 = g06_path.read_bytes()

        result = controller.run()

        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(g06_path.read_bytes(), before_g06)
        self.assertEqual(result.state, "partial")
        self.assertIsNone(result.failed_gate)
        self.assertEqual(
            [(item.gate.value, item.status) for item in result.gates],
            [("G06", "passed"), ("G07", "passed")],
        )
        self.assertEqual(
            result.mutation_attempts,
            [G06_ATTEMPT, G07_INIT, G07_SYNC],
        )
        self.assertEqual(result.mutations_completed, result.mutation_attempts)
        self.assertIn("G08", result.next_action)
        backup = case["beads"] / "backup"
        self.assertEqual(stat_mode(backup), 0o700)
        self.assertEqual(stat_mode(backup / "snapshot.json"), 0o600)
        self.assertEqual(stat_mode(case["beads"] / "dolt-backup.json"), 0o600)
        self.assertEqual(
            json.loads((backup / "snapshot.json").read_text(encoding="utf-8")),
            {
                "database": "demo_database",
                "fresh": True,
                "identity": "controlled-g07-snapshot/v1",
                "synchronized": True,
            },
        )
        payload = self.g07_payload(case)
        self.assertEqual(payload["failed_gate"], None)
        self.assertEqual(
            [(item["gate"], item["status"]) for item in payload["gates"]],
            [("G06", "passed"), ("G07", "passed")],
        )

    def test_beads_symlink_escape_fails_before_mutation_and_records_partial(self) -> None:
        case = self.make_case()
        beads = case["beads"]
        root = case["root"]
        controller = case["controller"]
        assert isinstance(beads, Path)
        assert isinstance(root, Path)
        external = root / "external-beads"
        external.mkdir()
        beads.rename(root / "saved-beads")
        beads.symlink_to(external, target_is_directory=True)

        with self.assertRaisesRegex(ControlledG07Error, "descriptor session"):
            controller.run()

        self.assertEqual(list(external.iterdir()), [])
        self.assert_g07_failure(case, attempts=[], completed=[], g06_proven=False)

    def test_existing_broken_sidecar_fails_before_mutation(self) -> None:
        case = self.make_case()
        beads = case["beads"]
        root = case["root"]
        controller = case["controller"]
        assert isinstance(beads, Path)
        assert isinstance(root, Path)
        (beads / "dolt-backup.json").symlink_to(root / "missing-sidecar")

        with self.assertRaisesRegex(ControlledG07Error, "existing backup state"):
            controller.run()

        self.assertFalse((beads / "backup").exists())
        self.assert_g07_failure(case, attempts=[], completed=[])

    def test_g06_append_and_evidence_survive_later_sync_failure(self) -> None:
        case = self.make_case()
        manifest = case["manifest"]
        g06_path = case["g06_path"]
        controller = case["controller"]
        assert isinstance(manifest, Path)
        assert isinstance(g06_path, Path)
        before_manifest = manifest.read_bytes()
        before_g06 = g06_path.read_bytes()

        with patch.object(
            controller,
            "_synchronize_for_controlled_test",
            side_effect=ControlledG07Error("controlled synchronization failure"),
        ):
            with self.assertRaisesRegex(ControlledG07Error, "synchronization failure"):
                controller.run()

        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(g06_path.read_bytes(), before_g06)
        backup = case["beads"] / "backup"
        self.assertTrue(backup.is_dir())
        self.assertFalse((backup / "snapshot.json").exists())
        payload = self.assert_g07_failure(
            case,
            attempts=[G07_INIT, G07_SYNC],
            completed=[G07_INIT],
        )
        self.assertIn("synchronization failure", payload["gates"][1]["detail"])
        with self.assertRaisesRegex(ControlledG07Error, "single-use"):
            controller.run()

    def test_g07_rejects_forged_g06_enrollment_evidence_before_mutation(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        g06 = case["g06_evidence"]
        beads = case["beads"]
        assert isinstance(root, Path)
        assert isinstance(request, ControlledG07Request)
        assert isinstance(g06, ProvisioningEvidence)
        assert isinstance(beads, Path)
        forged = deepcopy(g06)
        forged.gates = [GateResult(Gate.MANIFEST, "passed", "forged")]
        with self.assertRaisesRegex(ControlledG07Error, "completed descriptor-bound"):
            _controlled_g07_for_test(
                fixture_root=root,
                request=request,
                g06_evidence=forged,
            )

        self.assertFalse((beads / "backup").exists())

    def test_g07_rejects_foreign_g06_authority_with_same_database_before_mutation(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        g06 = case["g06_evidence"]
        beads = case["beads"]
        assert isinstance(root, Path)
        assert isinstance(request, ControlledG07Request)
        assert isinstance(g06, ProvisioningEvidence)
        assert isinstance(beads, Path)
        foreign_destination = root / "foreign-repository"
        foreign_destination.mkdir(mode=0o700)
        foreign = ControlledG07Request(foreign_destination, "other", request.database)

        with self.assertRaisesRegex(ControlledG07Error, "exact completed enrollment"):
            _controlled_g07_for_test(
                fixture_root=root,
                request=foreign,
                g06_evidence=g06,
            )

        self.assertFalse((beads / "backup").exists())

    def test_g07_rejects_coordinated_foreign_manifest_and_evidence_before_mutation(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        g06 = case["g06_evidence"]
        manifest = case["manifest"]
        g06_path = case["g06_path"]
        beads = case["beads"]
        assert isinstance(root, Path)
        assert isinstance(request, ControlledG07Request)
        assert isinstance(g06, ProvisioningEvidence)
        assert isinstance(manifest, Path)
        assert isinstance(g06_path, Path)
        assert isinstance(beads, Path)
        foreign_destination = root / "foreign-repository"
        foreign_beads = foreign_destination / ".beads"
        foreign_beads.mkdir(parents=True, mode=0o700)
        (foreign_beads / "metadata.json").write_text(
            json.dumps(
                {
                    "dolt_mode": "server",
                    "dolt_server_port": 3307,
                    "dolt_database": request.database,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        (foreign_beads / "metadata.json").chmod(0o600)
        foreign = ControlledG07Request(foreign_destination, "other", request.database)
        manifest.write_text(
            json.dumps(
                {"repositories": [manifest_record(foreign_destination, "other", request.database)]}
            ),
            encoding="utf-8",
        )
        foreign_evidence = deepcopy(g06)
        foreign_evidence.request_fingerprint = ControlledManifestController._fingerprint(
            foreign.exact_tuple()
        )
        g06_path.write_text(
            json.dumps(foreign_evidence.serializable(), sort_keys=True), encoding="utf-8"
        )

        with self.assertRaisesRegex(
            ControlledG07Error, "completed descriptor-bound|exact completed enrollment"
        ):
            _controlled_g07_for_test(
                fixture_root=root,
                request=foreign,
                g06_evidence=g06,
            )

        self.assertFalse((foreign_beads / "backup").exists())
        self.assertFalse((beads / "backup").exists())

    def test_g07_rejects_replaced_empty_manifest_before_mutation(self) -> None:
        case = self.make_case()
        manifest = case["manifest"]
        root = case["root"]
        request = case["request"]
        g06 = case["g06_evidence"]
        beads = case["beads"]
        assert isinstance(manifest, Path)
        assert isinstance(root, Path)
        assert isinstance(request, ControlledG07Request)
        assert isinstance(g06, ProvisioningEvidence)
        assert isinstance(beads, Path)
        manifest.write_text('{"repositories": []}', encoding="utf-8")

        with self.assertRaisesRegex(ControlledG07Error, "exact completed enrollment"):
            _controlled_g07_for_test(
                fixture_root=root,
                request=request,
                g06_evidence=g06,
            )

        self.assertFalse((beads / "backup").exists())

    def test_g07_rejects_replaced_failed_g06_evidence_before_mutation(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        g06 = case["g06_evidence"]
        g06_path = case["g06_path"]
        beads = case["beads"]
        assert isinstance(root, Path)
        assert isinstance(request, ControlledG07Request)
        assert isinstance(g06, ProvisioningEvidence)
        assert isinstance(g06_path, Path)
        assert isinstance(beads, Path)
        replaced = g06.serializable()
        replaced["failed_gate"] = "G06"
        replaced["gates"] = [{"gate": "G06", "status": "failed", "detail": "failed"}]
        g06_path.write_text(json.dumps(replaced, sort_keys=True), encoding="utf-8")

        with self.assertRaisesRegex(ControlledG07Error, "exact completed enrollment"):
            _controlled_g07_for_test(
                fixture_root=root,
                request=request,
                g06_evidence=g06,
            )

        self.assertFalse((beads / "backup").exists())

    def test_g07_rejects_missing_manifest_enrollment_before_mutation(self) -> None:
        case = self.make_case()
        manifest = case["manifest"]
        beads = case["beads"]
        controller = case["controller"]
        assert isinstance(manifest, Path)
        assert isinstance(beads, Path)
        manifest.write_text('{"repositories": []}', encoding="utf-8")

        with self.assertRaisesRegex(ControlledG07Error, "predecessor binding|exact completed enrollment"):
            controller.run()

        self.assertFalse((beads / "backup").exists())
        payload = self.assert_g07_failure(
            case, attempts=[], completed=[], g06_proven=False
        )
        self.assertIn("not proven", payload["gates"][0]["detail"])

    def test_backup_leaf_replacement_after_init_blocks_sync(self) -> None:
        case = self.make_case()
        root = case["root"]
        beads = case["beads"]
        controller = case["controller"]
        assert isinstance(root, Path)
        assert isinstance(beads, Path)
        external = root / "outside-backup"
        external.mkdir(mode=0o700)

        def replace_backup() -> None:
            backup = beads / "backup"
            backup.rename(beads / "saved-backup")
            backup.symlink_to(external, target_is_directory=True)

        with patch.object(
            controller,
            "_after_initialize_for_controlled_test",
            side_effect=replace_backup,
        ):
            with self.assertRaisesRegex(ControlledG07Error, "binding"):
                controller.run()

        self.assertEqual(list(external.iterdir()), [])
        self.assert_g07_failure(
            case,
            attempts=[G07_INIT],
            completed=[G07_INIT],
        )

    def test_sidecar_change_after_sync_is_partial_and_blocks_readback(self) -> None:
        case = self.make_case()
        beads = case["beads"]
        controller = case["controller"]
        assert isinstance(beads, Path)

        def corrupt_sidecar() -> None:
            sidecar = beads / "dolt-backup.json"
            sidecar.write_text("[]\n", encoding="utf-8")
            sidecar.chmod(0o600)

        with patch.object(
            controller,
            "_after_synchronize_for_controlled_test",
            side_effect=corrupt_sidecar,
        ):
            with self.assertRaisesRegex(ControlledG07Error, "binding"):
                controller.run()

        self.assert_g07_failure(
            case,
            attempts=[G07_INIT, G07_SYNC],
            completed=[G07_INIT, G07_SYNC],
        )

    def test_snapshot_symlink_swap_before_terminal_confirmation_is_partial(self) -> None:
        case = self.make_case()
        root = case["root"]
        beads = case["beads"]
        controller = case["controller"]
        assert isinstance(root, Path)
        assert isinstance(beads, Path)
        outside = root / "outside-snapshot"
        outside.write_text("outside\n", encoding="utf-8")

        def swap_snapshot() -> None:
            snapshot = beads / "backup" / "snapshot.json"
            snapshot.unlink()
            snapshot.symlink_to(outside)

        with patch.object(
            controller,
            "_before_terminal_confirmation_for_controlled_test",
            side_effect=swap_snapshot,
        ):
            with self.assertRaisesRegex(ControlledG07Error, "binding"):
                controller.run()

        self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
        self.assert_g07_failure(
            case,
            attempts=[G07_INIT, G07_SYNC],
            completed=[G07_INIT, G07_SYNC],
        )

    def test_g06_evidence_leaf_replacement_is_not_overwritten(self) -> None:
        case = self.make_case()
        g06_path = case["g06_path"]
        controller = case["controller"]
        assert isinstance(g06_path, Path)
        decoy = b'{"decoy":true}\n'

        def replace_g06_evidence() -> None:
            g06_path.rename(g06_path.with_suffix(".saved"))
            g06_path.write_bytes(decoy)

        with patch.object(
            controller,
            "_after_initialize_for_controlled_test",
            side_effect=replace_g06_evidence,
        ):
            with self.assertRaisesRegex(ControlledG07Error, "binding"):
                controller.run()

        self.assertEqual(g06_path.read_bytes(), decoy)
        payload = self.assert_g07_failure(
            case,
            attempts=[G07_INIT],
            completed=[G07_INIT],
        )
        self.assertEqual(payload["gates"][0]["status"], "passed")

    def test_manifest_replacement_is_never_modified_by_failure_handling(self) -> None:
        case = self.make_case()
        manifest = case["manifest"]
        controller = case["controller"]
        assert isinstance(manifest, Path)
        replacement = b'{"repositories":[],"replacement":true}\n'

        def replace_manifest() -> None:
            other = manifest.with_name("replacement.json")
            other.write_bytes(replacement)
            other.replace(manifest)

        with patch.object(
            controller,
            "_after_initialize_for_controlled_test",
            side_effect=replace_manifest,
        ):
            with self.assertRaisesRegex(ControlledG07Error, "binding"):
                controller.run()

        self.assertEqual(manifest.read_bytes(), replacement)
        self.assert_g07_failure(
            case,
            attempts=[G07_INIT],
            completed=[G07_INIT],
        )

    def test_no_live_cli_external_command_or_coverage_script_wiring(self) -> None:
        source = inspect.getsource(controlled_g07)
        lowered = source.lower()
        tree = ast.parse(source)
        forbidden_roots = {
            "asyncio",
            "boto3",
            "botocore",
            "git",
            "http",
            "requests",
            "shlex",
            "socket",
            "subprocess",
            "urllib",
        }
        imports: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr)
        self.assertTrue(imports.isdisjoint(forbidden_roots))
        self.assertTrue(
            calls.isdisjoint(
                {
                    "Popen",
                    "call",
                    "check_call",
                    "check_output",
                    "create_connection",
                    "request",
                    "run",
                    "system",
                    "urlopen",
                }
            )
        )
        self.assertNotIn("liveadapter", lowered)
        self.assertNotIn("coverage_script", lowered)
        forbidden_words = {
            "bd",
            "beads",
            "copier",
            "dolt",
            "git",
            "specify",
            "speckit",
        }
        string_literals = {
            node.value.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        command_like_literals = {
            literal
            for literal in string_literals
            if literal.strip()
            and literal.split(maxsplit=1)[0] in forbidden_words
            and " " in literal
            and not literal.startswith("controlled ")
        }
        self.assertEqual(command_like_literals, set())
        # Live execution was approved 2026-09-13 and the coarse quarantine lifted;
        # per-run mutation is still bound to sealed authorization, and the public
        # CLI remains simulation-only (no --live selector below).
        self.assertTrue(adapters._LIVE_EXECUTION_AVAILABLE)
        self.assertNotIn("_controlled_g07", inspect.getsource(adapters))
        public_source = inspect.getsource(provision_project)
        self.assertNotIn("_controlled_g07", public_source)
        self.assertNotIn('add_argument("--live"', public_source)
        self.assertIn("Provisioner(FakeAdapter())", public_source)


def stat_mode(path: Path) -> int:
    return path.stat(follow_symlinks=False).st_mode & 0o7777


if __name__ == "__main__":
    unittest.main(verbosity=2)

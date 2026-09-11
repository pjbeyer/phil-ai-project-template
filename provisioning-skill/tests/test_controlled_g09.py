"""Failure-first tests for the private controlled-G09 bootstrap controller.

Every state transition is synthetic and confined to ``TemporaryDirectory``. The
controller never reaches the quarantined adapter, public CLI, external commands,
services, credentials, origins, or an executable coverage script.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts._controlled_g09 import (
    ControlledG09Error,
    ControlledG09Request,
    _ControlledG09Controller,
    _controlled_g09_for_test,
)
from scripts._controlled_g07 import (
    _controlled_g07_for_test,
)
from scripts.controlled_manifest import (
    ControlledManifestController,
    ControlledManifestRequest,
)
from scripts.models import Gate, GateResult, ProvisioningEvidence

REQUIRED_JOBS = [
    "Hermes: Beads health review",
    "Hermes: compliance audit",
    "Hermes: Beads Dolt maintenance",
    "Hermes: Beads Dolt integrity review",
]
G06_ATTEMPT = "G06:controlled-manifest-append"
G07_INIT = "G07:controlled-backup-init"
G07_SYNC = "G07:controlled-backup-sync"
G09_ATTEMPT = "G09:controlled-bootstrap"

MARKERS = (
    ("scope-readme", "Define initial project scope and README"),
    ("first-speckit-spec", "Create the first SpecKit feature specification"),
)


def stat_mode(path: Path) -> int:
    import stat
    return stat.S_IMODE(path.lstat().st_mode)


def manifest_record(path: Path, prefix: str, database: str) -> dict[str, object]:
    return {
        "path": str(path),
        "prefix": prefix,
        "database": database,
        "owner": "personal",
        "profile": "default",
        "expected_remote": "origin",
        "expected_backup": True,
        "expected_sync": "manual-dolt-remote",
        "owning_jobs": list(REQUIRED_JOBS),
        "remote_health": "required",
        "restore_tier": "rotating",
    }


class ControlledG09Tests(unittest.TestCase):
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

        # G06 chain.
        manifest_controller = ControlledManifestController._for_controlled_test(
            fixture_root=root
        )
        manifest_controller.reserve(
            ControlledManifestRequest(destination, "demo", "demo_database")
        )
        g06_evidence = manifest_controller.append(
            manifest_record(destination, "demo", "demo_database")
        )

        # G07 chain (runs to completion, producing backup/sidecar/snapshot).
        g07_request = scripts_ctrl_g07_request(destination)
        g07_controller = _controlled_g07_for_test(
            fixture_root=root,
            request=g07_request,
            g06_evidence=g06_evidence,
        )
        g07_evidence = g07_controller.run()

        # G09 chain.
        request = ControlledG09Request(destination, "demo", "demo_database", MARKERS)
        controller = _controlled_g09_for_test(
            fixture_root=root,
            request=request,
            g07_evidence=g07_evidence,
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
            "g07_evidence": g07_evidence,
            "request": request,
            "controller": controller,
        }


def scripts_ctrl_g07_request(destination: Path):
    from scripts._controlled_g07 import ControlledG07Request
    return ControlledG07Request(destination, "demo", "demo_database")


class ControlledG09SuccessTests(ControlledG09Tests):
    def test_factory_is_private_exact_single_use_and_disposable_only(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        g07 = case["g07_evidence"]
        assert isinstance(root, Path)
        with self.assertRaisesRegex(ControlledG09Error, "private controlled-test factory"):
            _ControlledG09Controller(
                fixture_root=root,
                request=request,
                g07_evidence=g07,
            )

        class Subclass(_ControlledG09Controller):
            pass

        with self.assertRaisesRegex(ControlledG09Error, "subclasses"):
            Subclass._for_controlled_test(
                fixture_root=root,
                request=request,
                g07_evidence=g07,
            )

        outside = root.parent / f"unsafe-{root.name}-outside"
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        outside.mkdir()
        with self.assertRaisesRegex(ControlledG09Error, "disposable temporary fixture"):
            _controlled_g09_for_test(
                fixture_root=outside,
                request=ControlledG09Request(
                    outside / "repository", "demo", "demo_database", MARKERS
                ),
                g07_evidence=g07,
            )

        controller = case["controller"]
        controller.run()
        with self.assertRaisesRegex(ControlledG09Error, "single-use"):
            controller.run()

    def test_success_writes_bootstrap_and_preserves_g06_g07(self) -> None:
        case = self.make_case()
        manifest = case["manifest"]
        controller = case["controller"]
        beads = case["beads"]
        assert isinstance(manifest, Path)
        assert isinstance(beads, Path)
        before_manifest = manifest.read_bytes()

        result = controller.run()

        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(result.state, "partial")
        self.assertIsNone(result.failed_gate)
        self.assertEqual(
            result.mutation_attempts, [G06_ATTEMPT, G07_INIT, G07_SYNC, G09_ATTEMPT]
        )
        self.assertEqual(result.mutations_completed, result.mutation_attempts)
        # G08 (SpecKit) must never be claimed passed — it is skipped with a fence.
        gate_map = {item.gate.value: item.status for item in result.gates}
        self.assertEqual(gate_map[Gate.SPECKIT.value], "skipped")
        self.assertEqual(gate_map[Gate.BOOTSTRAP.value], "passed")
        self.assertNotIn("passed", {k: v for k, v in gate_map.items() if k == "G08"})
        # The bootstrap ledger must be a real, read-back file.
        ledger = json.loads((beads / "bootstrap.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["database"], "demo_database")
        self.assertEqual(ledger["identity"], "controlled-g09-bootstrap/v1")
        self.assertEqual(
            [m["marker"] for m in ledger["markers"]],
            ["scope-readme", "first-speckit-spec"],
        )
        self.assertEqual(stat_mode(beads / "bootstrap.json"), 0o600)

    def test_g08_is_never_passed_in_any_evidence(self) -> None:
        case = self.make_case()
        controller = case["controller"]
        result = controller.run()
        for item in result.gates:
            self.assertNotEqual(
                (item.gate, item.status),
                (Gate.SPECKIT, "passed"),
                "live G08 must never be asserted by controlled G09",
            )

    def test_forged_g07_evidence_fails_before_mutation(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        beads = case["beads"]
        assert isinstance(beads, Path)
        # A forged G07 evidence object (wrong database) must be rejected up front.
        with self.assertRaises(ControlledG09Error):
            _controlled_g09_for_test(
                fixture_root=root,
                request=ControlledG09Request(
                    request.destination, "demo", "forged_database", MARKERS
                ),
                g07_evidence=case["g07_evidence"],
            )
        self.assertFalse((beads / "bootstrap.json").exists(), "no mutation on rejection")


if __name__ == "__main__":
    unittest.main()
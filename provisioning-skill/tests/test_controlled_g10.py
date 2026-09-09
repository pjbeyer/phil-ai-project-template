"""Failure-first tests for the private controlled-G10 commit controller.

Every state transition is synthetic and confined to ``TemporaryDirectory``. The
controller never reaches the quarantined adapter, public CLI, external commands,
services, credentials, origins, or an executable coverage script.
"""

from __future__ import annotations

import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from scripts._controlled_g09 import ControlledG09Request, _controlled_g09_for_test
from scripts._controlled_g07 import _controlled_g07_for_test
from scripts._controlled_g10 import (
    ControlledG10Error,
    ControlledG10Request,
    _ControlledG10Controller,
    _controlled_g10_for_test,
)
from scripts.controlled_manifest import (
    ControlledManifestController,
    ControlledManifestRequest,
)
from scripts.models import Gate

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
G10_ATTEMPT = "G10:controlled-commit"

MARKERS = (
    ("scope-readme", "Define initial project scope and README"),
    ("first-speckit-spec", "Create the first SpecKit feature specification"),
)


def stat_mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def manifest_record(path: Path, prefix: str, database: str) -> dict[str, object]:
    return {
        "path": str(path),
        "prefix": prefix,
        "database": database,
        "owner": "pjbeyer",
        "profile": "default",
        "expected_remote": "origin",
        "expected_backup": True,
        "expected_sync": "manual-dolt-remote",
        "owning_jobs": list(REQUIRED_JOBS),
        "remote_health": "required",
        "restore_tier": "rotating",
    }


class ControlledG10Tests(unittest.TestCase):
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
        (beads / "metadata.json").write_text(
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
        (beads / "metadata.json").chmod(0o600)
        (root / "manifest.json").write_text('{"repositories": []}', encoding="utf-8")

        # G06 → G07 → G09 chain.
        manifest_controller = ControlledManifestController._for_controlled_test(
            fixture_root=root
        )
        manifest_controller.reserve(
            ControlledManifestRequest(destination, "demo", "demo_database")
        )
        g06_evidence = manifest_controller.append(
            manifest_record(destination, "demo", "demo_database")
        )
        from scripts._controlled_g07 import ControlledG07Request

        g07_evidence = _controlled_g07_for_test(
            fixture_root=root,
            request=ControlledG07Request(destination, "demo", "demo_database"),
            g06_evidence=g06_evidence,
        ).run()
        g09_evidence = _controlled_g09_for_test(
            fixture_root=root,
            request=ControlledG09Request(destination, "demo", "demo_database", MARKERS),
            g07_evidence=g07_evidence,
        ).run()

        # G10 requires an exact pinned .git tree.
        git = destination / ".git"
        git.mkdir(mode=0o700)
        (git / "HEAD").write_text("refs/heads/main\n", encoding="utf-8")
        (git / "HEAD").chmod(0o600)

        request = ControlledG10Request(destination, "demo", "demo_database", MARKERS)
        controller = _controlled_g10_for_test(
            fixture_root=root,
            request=request,
            g09_evidence=g09_evidence,
        )
        return {
            "temporary": temporary,
            "root": root,
            "evidence": evidence,
            "destination": destination,
            "git": git,
            "request": request,
            "controller": controller,
        }


class ControlledG10SuccessTests(ControlledG10Tests):
    def test_factory_is_private_exact_single_use(self) -> None:
        case = self.make_case()
        root = case["root"]
        request = case["request"]
        assert isinstance(root, Path)
        g09 = self._build_g09()
        with self.assertRaisesRegex(ControlledG10Error, "private controlled-test factory"):
            _ControlledG10Controller(
                fixture_root=root,
                request=request,
                g09_evidence=g09,
            )

        class Subclass(_ControlledG10Controller):
            pass

        with self.assertRaisesRegex(ControlledG10Error, "subclasses"):
            Subclass._for_controlled_test(
                fixture_root=root,
                request=request,
                g09_evidence=g09,
            )

        controller = case["controller"]
        controller.run()
        with self.assertRaisesRegex(ControlledG10Error, "single-use"):
            controller.run()

    def _build_g09(self):
        import tempfile as _tf

        tmp = _tf.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        evidence = root / "evidence"
        evidence.mkdir(mode=0o700)
        destination = root / "repository"
        beads = destination / ".beads"
        beads.mkdir(parents=True, mode=0o700)
        (beads / "metadata.json").write_text(
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
        (beads / "metadata.json").chmod(0o600)
        (root / "manifest.json").write_text('{"repositories": []}', encoding="utf-8")
        manifest_controller = ControlledManifestController._for_controlled_test(
            fixture_root=root
        )
        manifest_controller.reserve(
            ControlledManifestRequest(destination, "demo", "demo_database")
        )
        g06 = manifest_controller.append(
            manifest_record(destination, "demo", "demo_database")
        )
        from scripts._controlled_g07 import ControlledG07Request

        g07 = _controlled_g07_for_test(
            fixture_root=root,
            request=ControlledG07Request(destination, "demo", "demo_database"),
            g06_evidence=g06,
        ).run()
        return _controlled_g09_for_test(
            fixture_root=root,
            request=ControlledG09Request(destination, "demo", "demo_database", MARKERS),
            g07_evidence=g07,
        ).run()

    def test_success_writes_commit_and_preserves_chain(self) -> None:
        case = self.make_case()
        controller = case["controller"]
        git = case["git"]
        assert isinstance(git, Path)

        result = controller.run()

        self.assertEqual(result.state, "partial")
        self.assertIsNone(result.failed_gate)
        self.assertEqual(
            result.mutation_attempts,
            [G06_ATTEMPT, G07_INIT, G07_SYNC, G09_ATTEMPT, G10_ATTEMPT],
        )
        self.assertEqual(result.mutations_completed, result.mutation_attempts)
        gate_map = {item.gate.value: item.status for item in result.gates}
        self.assertEqual(gate_map[Gate.SPECKIT.value], "skipped")
        self.assertEqual(gate_map[Gate.COMMIT.value], "passed")
        commit = json.loads((git / "COMMIT_EDITMSG").read_text(encoding="utf-8"))
        self.assertEqual(commit["identity"], "controlled-g10-commit/v1")
        self.assertEqual(commit["head"], "1" * 40)
        self.assertEqual(stat_mode(git / "COMMIT_EDITMSG"), 0o600)

    def test_g08_is_never_passed(self) -> None:
        case = self.make_case()
        controller = case["controller"]
        result = controller.run()
        for item in result.gates:
            self.assertNotEqual((item.gate, item.status), (Gate.SPECKIT, "passed"))


if __name__ == "__main__":
    unittest.main()
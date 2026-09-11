"""Manifest uniqueness, atomicity, and required-field tests."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.manifest import AppendResult, ManifestError, append_record, load_manifest


def record(path: str = "/projects/demo", database: str = "demo") -> dict:
    return {
        "path": path, "prefix": database, "database": database, "owner": "personal", "profile": "default",
        "expected_remote": "origin", "expected_backup": True, "expected_sync": "manual-dolt-remote",
        "owning_jobs": [
            "Hermes: Beads health review", "Hermes: compliance audit",
            "Hermes: Beads Dolt maintenance", "Hermes: Beads Dolt integrity review",
        ], "remote_health": "required", "restore_tier": "rotating",
    }


class ManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "manifest.json"
        self.path.write_text(json.dumps({"repositories": [record()]}))

    def test_append_and_reparse(self) -> None:
        committed = append_record(self.path, record("/projects/second", "second"))
        manifest, digest = load_manifest(self.path)
        self.assertEqual(len(manifest["repositories"]), 2)
        self.assertEqual(committed.manifest, manifest)
        self.assertEqual(committed.digest, digest)
        self.assertEqual(committed.record, record("/projects/second", "second"))

    def test_locked_readback_rejects_tamper_before_return(self) -> None:
        candidate = record("/projects/second", "second")
        real_replace = os.replace

        def replace_then_tamper(source: str | Path, destination: str | Path) -> None:
            real_replace(source, destination)
            tampered = {"repositories": [record(), candidate, record("/projects/third", "third")]}
            Path(destination).write_text(json.dumps(tampered), encoding="utf-8")

        with patch("scripts.manifest.os.replace", side_effect=replace_then_tamper):
            with self.assertRaisesRegex(ManifestError, "changed during locked readback"):
                append_record(self.path, candidate)

    def test_locked_readback_is_the_exact_committed_snapshot(self) -> None:
        candidate = record("/projects/second", "second")
        committed = append_record(self.path, candidate)
        later = {"repositories": [record(), candidate, record("/projects/later", "later")]}
        self.path.write_text(json.dumps(later), encoding="utf-8")

        self.assertEqual(committed.manifest["repositories"], [record(), candidate])
        self.assertEqual(
            committed.digest,
            hashlib.sha256(committed.raw).hexdigest(),
        )
        self.assertNotEqual(committed.digest, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_concurrent_append_returns_each_exact_locked_snapshot(self) -> None:
        barrier = threading.Barrier(2)
        results: dict[str, AppendResult] = {}
        failures: list[BaseException] = []

        def append(identity: str) -> None:
            try:
                barrier.wait(timeout=2)
                results[identity] = append_record(
                    self.path,
                    record(f"/projects/{identity}", identity),
                )
            except BaseException as exc:  # preserve worker failure for the test thread
                failures.append(exc)

        threads = [threading.Thread(target=append, args=(identity,)) for identity in ("two", "three")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(set(results), {"two", "three"})
        returned_counts = sorted(
            len(result.manifest["repositories"])
            for result in results.values()
        )
        self.assertEqual(returned_counts, [2, 3])
        for identity, result in results.items():
            self.assertEqual(
                result.manifest["repositories"][-1],
                record(f"/projects/{identity}", identity),
            )

    def test_duplicate_json_members_are_rejected_at_every_object_layer_unchanged(self) -> None:
        valid = json.dumps(record())
        duplicate_cases = {
            "top-level repositories": '{"repositories": [], "repositories": []}',
            "record path": '{"repositories": [' + valid.replace(
                '"path": "/projects/demo"',
                '"path": "/projects/demo", "path": "/projects/shadow"',
            ) + "]}",
            "record database": '{"repositories": [' + valid.replace(
                '"database": "demo"',
                '"database": "demo", "database": "shadow"',
            ) + "]}",
            "record prefix": '{"repositories": [' + valid.replace(
                '"prefix": "demo"',
                '"prefix": "demo", "prefix": "shadow"',
            ) + "]}",
            "record owner": '{"repositories": [' + valid.replace(
                '"owner": "personal"',
                '"owner": "personal", "owner": "shadow"',
            ) + "]}",
        }
        candidate = record("/projects/second", "second")

        for identity, raw in duplicate_cases.items():
            with self.subTest(identity=identity):
                self.path.write_text(raw, encoding="utf-8")
                before = self.path.read_bytes()
                with self.assertRaisesRegex(ManifestError, "duplicate JSON member"):
                    load_manifest(self.path)
                with self.assertRaisesRegex(ManifestError, "duplicate JSON member"):
                    append_record(self.path, candidate)
                self.assertEqual(self.path.read_bytes(), before)

    def test_path_and_database_conflicts_stop(self) -> None:
        for duplicate in (record("/projects/demo", "other"), record("/projects/other", "demo")):
            with self.subTest(duplicate=duplicate), self.assertRaises(ManifestError):
                append_record(self.path, duplicate)

    def test_malformed_record_stops(self) -> None:
        self.path.write_text(json.dumps({"repositories": [{"path": "/broken"}]}))
        with self.assertRaises(ManifestError):
            append_record(self.path, record("/projects/second", "second"))

    def test_unknown_top_level_field_is_rejected_byte_identically(self) -> None:
        self.path.write_text(
            json.dumps({"repositories": [record()], "unexpected": "junk"}),
            encoding="utf-8",
        )
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ManifestError, "top-level fields"):
            append_record(self.path, record("/projects/second", "second"))
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)

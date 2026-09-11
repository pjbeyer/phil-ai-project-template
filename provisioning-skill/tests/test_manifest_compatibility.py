"""Legacy manifest and backup-containment compatibility tests.

Every fixture is synthetic and confined to a disposable temporary directory.
No subprocess, service, credential, repository, or production manifest is used.
Controlled G06 and G07 coverage live in focused private-controller tests and
never enable the quarantined live adapter.
"""
from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.backup import BackupError, assert_safe_backup_root
from scripts.manifest import ManifestError, append_record, load_manifest, validate_records


REQUIRED_JOBS = [
    "Hermes: Beads health review",
    "Hermes: compliance audit",
    "Hermes: Beads Dolt maintenance",
    "Hermes: Beads Dolt integrity review",
]


def manifest_record(
    identity: str,
    *,
    prefix: bool = True,
    expected_remote: str | None = "origin",
    expected_sync: str = "manual-dolt-remote",
    owning_jobs: list[str] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "path": f"/synthetic/projects/{identity}",
        "database": f"{identity}_database",
        "owner": "personal",
        "project_kind": "generic",
        "visibility": "personal-only",
        "profile": "default",
        "expected_remote": expected_remote,
        "expected_backup": True,
        "expected_sync": expected_sync,
        "owning_jobs": list(REQUIRED_JOBS if owning_jobs is None else owning_jobs),
        "remote_health": "required",
        "restore_tier": "rotating",
    }
    if prefix:
        record["prefix"] = identity
    return record


class BackupContainmentTests(unittest.TestCase):
    def test_rejects_symlinked_repository_beads_backup_or_relevant_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            for component in ("ancestor", "repository", "beads", "backup"):
                with self.subTest(component=component):
                    case = base / component
                    outside = case / "outside"
                    outside.mkdir(parents=True)
                    real_ancestor = case / "real-ancestor"
                    real_ancestor.mkdir()
                    if component == "ancestor":
                        ancestor = case / "ancestor-link"
                        ancestor.symlink_to(real_ancestor, target_is_directory=True)
                        repository = ancestor / "repository"
                        (real_ancestor / "repository" / ".beads").mkdir(parents=True)
                    else:
                        repository = case / "repository"
                        repository.mkdir()
                        if component == "repository":
                            repository.rmdir()
                            repository.symlink_to(outside, target_is_directory=True)
                        beads = repository / ".beads"
                        if component == "beads":
                            beads.symlink_to(outside, target_is_directory=True)
                        else:
                            beads.mkdir()
                            if component == "backup":
                                (beads / "backup").symlink_to(outside, target_is_directory=True)
                    backup_root = repository / ".beads" / "backup"
                    with self.assertRaisesRegex(BackupError, "symlink"):
                        assert_safe_backup_root(repository, backup_root)

    def test_rejects_symlink_above_repository_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            real_root = base / "real-root"
            repository = real_root / "projects" / "owner" / "repository"
            (repository / ".beads").mkdir(parents=True)
            alias = base / "alias"
            alias.symlink_to(real_root, target_is_directory=True)
            aliased_repository = alias / "projects" / "owner" / "repository"

            with self.assertRaisesRegex(BackupError, "symlink"):
                assert_safe_backup_root(
                    aliased_repository,
                    aliased_repository / ".beads" / "backup",
                )

    def test_macos_var_alias_is_allowed_only_as_the_platform_root_alias(self) -> None:
        repository = Path("/var") / "synthetic" / "owner" / "repository"
        backup_root = repository / ".beads" / "backup"
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=7)
        symlink = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_dev=7)

        def platform_lstat(path: Path):
            if path == Path("/var"):
                return symlink
            if path in (Path("/"), repository.parent, repository, repository / ".beads"):
                return directory
            raise FileNotFoundError(path)

        with patch("scripts.backup.sys.platform", "darwin"), patch(
            "scripts.backup.os.readlink", return_value="private/var"
        ), patch(
            "pathlib.Path.lstat", autospec=True, side_effect=platform_lstat
        ):
            assert_safe_backup_root(repository, backup_root)

        with patch("scripts.backup.sys.platform", "darwin"), patch(
            "scripts.backup.os.readlink", return_value="attacker-controlled"
        ), patch(
            "pathlib.Path.lstat", autospec=True, side_effect=platform_lstat
        ):
            with self.assertRaisesRegex(BackupError, "symlink"):
                assert_safe_backup_root(repository, backup_root)

        unsafe_alias = Path("/var") / "synthetic-link"
        unsafe_repository = unsafe_alias / "owner" / "repository"

        def unsafe_lstat(path: Path):
            if path == Path("/var") or path == unsafe_alias:
                return symlink
            if path in (Path("/"), unsafe_repository.parent, unsafe_repository, unsafe_repository / ".beads"):
                return directory
            raise FileNotFoundError(path)

        with patch("scripts.backup.sys.platform", "darwin"), patch(
            "scripts.backup.os.readlink", return_value="private/var"
        ), patch(
            "pathlib.Path.lstat", autospec=True, side_effect=unsafe_lstat
        ):
            with self.assertRaisesRegex(BackupError, "symlink"):
                assert_safe_backup_root(
                    unsafe_repository,
                    unsafe_repository / ".beads" / "backup",
                )

    def test_rejects_repository_or_beads_device_crossing(self) -> None:
        repository = Path("/safe-root") / "projects" / "repository"
        backup_root = repository / ".beads" / "backup"
        directory = stat.S_IFDIR | 0o700

        for crossing in (repository.parent, repository, repository / ".beads", backup_root):
            with self.subTest(crossing=crossing):
                def mocked_lstat(path: Path, *, crossing: Path = crossing):
                    if path == backup_root and crossing != backup_root:
                        raise FileNotFoundError(path)
                    device = 9 if path == crossing else 7
                    return SimpleNamespace(st_mode=directory, st_dev=device)

                with patch("pathlib.Path.lstat", autospec=True, side_effect=mocked_lstat):
                    with self.assertRaisesRegex(BackupError, "filesystem boundary"):
                        assert_safe_backup_root(repository, backup_root)

    def test_backup_root_and_descendants_share_one_device(self) -> None:
        from scripts.backup import validate_backup_tree

        backup_root = Path("/safe-root/repository/.beads/backup")
        child = backup_root / "snapshot.jsonl"
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=7)
        crossed_file = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=9)

        def mocked_lstat(path: Path):
            return directory if path == backup_root else crossed_file

        with patch("pathlib.Path.lstat", autospec=True, side_effect=mocked_lstat), patch(
            "scripts.backup.os.walk",
            return_value=[(str(backup_root), [], [child.name])],
        ):
            with self.assertRaisesRegex(BackupError, "filesystem boundary"):
                validate_backup_tree(backup_root)


class ManifestCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.manifest_path = Path(self.temporary.name) / "manifest.json"

    def write_manifest(self, records: list[object]) -> None:
        self.manifest_path.write_text(
            json.dumps({"repositories": records}),
            encoding="utf-8",
        )

    def test_valid_legacy_record_variants_are_accepted_together(self) -> None:
        records = [
            manifest_record("missing_prefix", prefix=False),
            manifest_record("null_remote", expected_remote=None),
            manifest_record("backup_only", expected_remote=None, expected_sync="backup-only"),
            manifest_record(
                "extra_job",
                owning_jobs=[*REQUIRED_JOBS, "Hermes: required legacy coverage"],
            ),
        ]
        self.write_manifest(records)

        manifest, digest = load_manifest(self.manifest_path)
        validate_records(manifest["repositories"])

        self.assertEqual(manifest["repositories"], records)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_legacy_records_still_reject_duplicate_canonical_path_or_database(self) -> None:
        original = manifest_record("original", prefix=False)
        duplicate_path = manifest_record("other_path", expected_remote=None)
        duplicate_path["path"] = original["path"]
        duplicate_database = manifest_record(
            "other_database", expected_remote=None, expected_sync="backup-only"
        )
        duplicate_database["database"] = original["database"]

        for duplicate in (duplicate_path, duplicate_database):
            with self.subTest(duplicate=duplicate), self.assertRaises(ManifestError):
                validate_records([original, duplicate])

    def test_legacy_paths_must_be_canonical_absolute_lexical_paths(self) -> None:
        original = manifest_record("original", prefix=False)
        aliases = (
            "/synthetic/projects/./original",
            "/synthetic/projects/alias/../original",
            "/synthetic//projects/original",
            "/synthetic/projects/original/",
            "//synthetic/projects/original",
            "/synthetic/projects\\original",
            "synthetic/projects/original",
        )

        for alias in aliases:
            noncanonical = manifest_record(f"alias-{len(alias)}", prefix=False)
            noncanonical["path"] = alias
            with self.subTest(alias=alias), self.assertRaises(ManifestError):
                validate_records([original, noncanonical])

    def test_present_null_prefix_is_not_a_legacy_absence(self) -> None:
        omitted = manifest_record("omitted", prefix=False)
        validate_records([omitted])

        present_null = manifest_record("present_null", prefix=False)
        present_null["prefix"] = None
        with self.assertRaises(ManifestError):
            validate_records([present_null])

    def test_legacy_record_requires_all_production_jobs_but_allows_extras(self) -> None:
        with self.assertRaises(ManifestError):
            validate_records([
                manifest_record("missing_job", owning_jobs=REQUIRED_JOBS[:-1])
            ])

        validate_records([
            manifest_record(
                "extra_job",
                owning_jobs=[*REQUIRED_JOBS, "Hermes: required legacy coverage"],
            )
        ])

    def test_malformed_and_non_object_legacy_records_are_rejected(self) -> None:
        malformed = manifest_record("malformed", prefix=False)
        malformed.pop("database")
        unsupported = manifest_record("unsupported", expected_sync="automatic")
        inconsistent_backup_only = manifest_record("inconsistent_backup_only", expected_sync="backup-only")
        malformed_jobs = manifest_record("malformed_jobs")
        malformed_jobs["owning_jobs"] = [*REQUIRED_JOBS, None]
        for record in (
            malformed,
            unsupported,
            inconsistent_backup_only,
            malformed_jobs,
            ["not", "an", "object"],
            None,
        ):
            with self.subTest(record=record), self.assertRaises(ManifestError):
                validate_records([record])  # type: ignore[list-item]

    def test_legacy_owner_unknown_fields_and_nul_identities_are_rejected(self) -> None:
        invalid_records: list[dict[str, object]] = []
        for owner in (None, [], "", "   ", "\tpjbeyer\n"):
            invalid = manifest_record(f"owner-{len(invalid_records)}", prefix=False)
            invalid["owner"] = owner
            invalid_records.append(invalid)
        invalid_records.append({**manifest_record("unknown", prefix=False), "legacy_note": "junk"})
        for key in ("path", "database", "prefix", "owner"):
            invalid = manifest_record(f"nul-{key}")
            invalid[key] = f"safe\x00unsafe"
            invalid_records.append(invalid)

        for invalid in invalid_records:
            with self.subTest(invalid=invalid), self.assertRaises(ManifestError):
                validate_records([invalid])

    def test_append_rejects_hardened_legacy_failures_byte_identically(self) -> None:
        candidate = manifest_record("candidate")
        malformed_records: list[dict[str, object]] = []
        for owner in (None, [], "", "   "):
            invalid = manifest_record(f"owner-{len(malformed_records)}", prefix=False)
            invalid["owner"] = owner
            malformed_records.append(invalid)
        malformed_records.extend(
            (
                {**manifest_record("unknown", prefix=False), "legacy_note": "junk"},
                {**manifest_record("nul-path", prefix=False), "path": "/synthetic/projects/nul\x00path"},
                {**manifest_record("nul-database", prefix=False), "database": "db\x00name"},
            )
        )

        for malformed in malformed_records:
            with self.subTest(malformed=malformed):
                self.write_manifest([malformed])
                before = self.manifest_path.read_bytes()
                with self.assertRaises(ManifestError):
                    append_record(self.manifest_path, candidate)
                self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_append_accepts_legacy_manifest_but_enforces_strict_new_record_policy(self) -> None:
        legacy = [
            manifest_record("missing_prefix", prefix=False),
            manifest_record("null_remote", expected_remote=None),
            manifest_record("backup_only", expected_remote=None, expected_sync="backup-only"),
            manifest_record(
                "extra_job",
                owning_jobs=[*REQUIRED_JOBS, "Hermes: required legacy coverage"],
            ),
        ]
        self.write_manifest(legacy)
        enrolled = manifest_record("new_enrollment")

        append_record(self.manifest_path, enrolled)

        reparsed, _ = load_manifest(self.manifest_path)
        self.assertEqual(reparsed["repositories"], [*legacy, enrolled])

        invalid_new_records: list[dict[str, object]] = []
        missing = manifest_record("new_missing")
        missing.pop("prefix")
        invalid_new_records.append(missing)
        invalid_new_records.append({**manifest_record("new_extra_field"), "legacy_note": "not permitted"})
        invalid_new_records.append(manifest_record("new_null_remote", expected_remote=None))
        invalid_new_records.append(manifest_record("new_backup_only", expected_sync="backup-only"))
        invalid_new_records.append(
            manifest_record("new_wrong_job", owning_jobs=REQUIRED_JOBS[:-1])
        )
        invalid_new_records.append(
            manifest_record(
                "new_extra_required_job",
                owning_jobs=[*REQUIRED_JOBS, "Hermes: required legacy coverage"],
            )
        )

        for invalid in invalid_new_records:
            before = self.manifest_path.read_bytes()
            with self.subTest(invalid=invalid), self.assertRaises(ManifestError):
                append_record(self.manifest_path, invalid)
            self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_append_rejects_malformed_legacy_manifest_without_changing_file(self) -> None:
        malformed_legacy = (
            manifest_record("missing_job", owning_jobs=REQUIRED_JOBS[:-1]),
            {**manifest_record("present_null", prefix=False), "prefix": None},
            {**manifest_record("noncanonical", prefix=False), "path": "/synthetic/./projects/noncanonical"},
        )
        candidate = manifest_record("candidate")

        for malformed in malformed_legacy:
            with self.subTest(malformed=malformed):
                self.write_manifest([malformed])
                before = self.manifest_path.read_bytes()
                with self.assertRaises(ManifestError):
                    append_record(self.manifest_path, candidate)
                self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_new_record_rejects_noncanonical_path_without_changing_file(self) -> None:
        self.write_manifest([manifest_record("legacy", prefix=False)])
        candidate = manifest_record("candidate")
        candidate["path"] = "/synthetic/projects/other/../candidate"
        before = self.manifest_path.read_bytes()

        with self.assertRaises(ManifestError):
            append_record(self.manifest_path, candidate)

        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_append_rejects_legacy_path_alias_of_candidate_without_changing_file(self) -> None:
        legacy = manifest_record("legacy", prefix=False)
        legacy["path"] = "/synthetic/projects/./candidate"
        self.write_manifest([legacy])
        candidate = manifest_record("candidate")
        before = self.manifest_path.read_bytes()

        with self.assertRaises(ManifestError):
            append_record(self.manifest_path, candidate)

        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_real_manifest_top_level_schema_is_accepted(self) -> None:
        from scripts.manifest import MANIFEST_FIELDS

        self.assertEqual(
            MANIFEST_FIELDS,
            {
                "version", "generated_from", "vocabulary", "managed_server",
                "required_jobs", "repositories", "maintenance_policy",
            },
        )
        full = {
            "version": 2,
            "generated_from": "synthetic",
            "managed_server": {"host": "127.0.0.1", "port": 3307},
            "required_jobs": {"Hermes: Beads health review": {"profile": "default"}},
            "repositories": [manifest_record("real")],
            "maintenance_policy": {"backup_max_age_hours": 18},
        }
        self.manifest_path.write_text(json.dumps(full), encoding="utf-8")
        manifest, digest = load_manifest(self.manifest_path)
        validate_records(manifest["repositories"])
        self.assertEqual(manifest["repositories"], [manifest_record("real")])
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_real_record_variants_and_remote_exception_are_accepted(self) -> None:
        records = [
            manifest_record("a", expected_remote=None, expected_sync="backup-only-no-dolt-remote"),
            manifest_record("b", expected_sync="github-upstream-pull-and-manual-dolt-remote"),
            manifest_record("c", expected_sync="remote-plus-backup"),
        ]
        records[0]["remote_health"] = "not-configured"
        records[0]["remote_exception"] = None
        records[1]["restore_tier"] = "canonical"
        self.write_manifest(records)
        manifest, _ = load_manifest(self.manifest_path)
        validate_records(manifest["repositories"])

        bad = {**manifest_record("d", expected_sync="remote-plus-backup"), "remote_exception": "boom"}
        with self.assertRaises(ManifestError):
            validate_records([bad])

    def test_owner_mapping_matches_real_manifest(self) -> None:
        from scripts.manifest import MANIFEST_OWNER_VALUES, manifest_owner_for

        self.assertEqual(manifest_owner_for("pjbeyer"), "personal")
        self.assertEqual(manifest_owner_for("flexapp"), "work")
        self.assertEqual(MANIFEST_OWNER_VALUES, {"personal", "work"})
        for unapproved in ("example", "unknown", ""):
            with self.subTest(owner=unapproved), self.assertRaises(ManifestError):
                manifest_owner_for(unapproved)


if __name__ == "__main__":
    unittest.main(verbosity=2)

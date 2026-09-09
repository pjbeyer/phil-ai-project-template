"""Conflict-safe managed-project manifest validation and append helpers."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUIRED = {
    "path", "prefix", "database", "owner", "profile", "expected_remote", "expected_backup",
    "expected_sync", "owning_jobs", "remote_health", "restore_tier",
}
LEGACY_REQUIRED = REQUIRED - {"prefix"}
OWNING_JOBS = {
    "Hermes: Beads health review",
    "Hermes: compliance audit",
    "Hermes: Beads Dolt maintenance",
    "Hermes: Beads Dolt integrity review",
}
MANIFEST_FIELDS = {"repositories"}


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class AppendResult:
    """Evidence for the exact post-append snapshot read under lock."""

    manifest: dict[str, Any]
    record: dict[str, Any]
    digest: str
    raw: bytes


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"manifest contains duplicate JSON member {key!r}")
        result[key] = value
    return result


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_members)
    except ManifestError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ManifestError("manifest is not valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("repositories"), list):
        raise ManifestError("manifest has no repositories list")
    if set(data) != MANIFEST_FIELDS:
        raise ManifestError("manifest has unrecognized top-level fields")
    return data


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    return _parse_manifest(raw), hashlib.sha256(raw).hexdigest()


def _identity(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if type(value) is not str or not value or not value.strip() or value != value.strip() or "\x00" in value:
        raise ManifestError(f"manifest record has invalid {key} identity")
    return value


def _canonical_path_identity(record: dict[str, Any]) -> str:
    """Return a canonical lexical absolute path without filesystem access."""
    value = _identity(record, "path")
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        raise ManifestError("manifest record path must be canonical and absolute")
    canonical = os.path.normpath(value)
    if value != canonical:
        raise ManifestError("manifest record path must use its canonical lexical spelling")
    return canonical


def validate_new_record(record: dict[str, Any]) -> None:
    """Enforce the exact current enrollment schema and owner-job policy."""
    if not isinstance(record, dict) or set(record) != REQUIRED:
        raise ManifestError("new manifest record must contain exactly the required fields")
    _canonical_path_identity(record)
    for key in ("prefix", "database", "owner"):
        _identity(record, key)
    if record["profile"] != "default" or record["expected_remote"] != "origin":
        raise ManifestError("new manifest record violates required profile or remote policy")
    if record["expected_backup"] is not True or record["expected_sync"] != "manual-dolt-remote":
        raise ManifestError("new manifest record violates backup or sync policy")
    if record["remote_health"] != "required" or record["restore_tier"] != "rotating":
        raise ManifestError("new manifest record violates remote-health or restore policy")
    owners = record["owning_jobs"]
    if not isinstance(owners, list):
        raise ManifestError("new manifest record must use the exact required owning jobs")
    if not all(isinstance(owner, str) and owner for owner in owners):
        raise ManifestError("new manifest record must use the exact required owning jobs")
    if len(owners) != len(OWNING_JOBS) or set(owners) != OWNING_JOBS:
        raise ManifestError("new manifest record must use the exact required owning jobs")


def validate_records(records: list[dict[str, Any]]) -> None:
    """Accept recognized production legacy shapes while preserving identity safety."""
    paths: set[str] = set()
    prefixes: set[str] = set()
    databases: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or not LEGACY_REQUIRED <= record.keys():
            raise ManifestError("manifest record is missing required fields")
        allowed_fields = REQUIRED if "prefix" in record else LEGACY_REQUIRED
        if set(record) != allowed_fields:
            raise ManifestError("manifest record has unrecognized fields")
        path = _canonical_path_identity(record)
        database = _identity(record, "database")
        _identity(record, "owner")
        if "prefix" not in record:
            prefix = None
        else:
            prefix = _identity(record, "prefix")
        if path in paths or database in databases or (prefix is not None and prefix in prefixes):
            raise ManifestError("manifest path/prefix/database identity is not globally unique")
        if record["profile"] != "default" or record["expected_remote"] not in ("origin", None):
            raise ManifestError("manifest record violates recognized profile or remote policy")
        if record["expected_backup"] is not True:
            raise ManifestError("manifest record violates recognized backup policy")
        sync_policy = record["expected_sync"]
        if sync_policy == "manual-dolt-remote":
            pass
        elif sync_policy == "backup-only" and record["expected_remote"] is None:
            pass
        else:
            raise ManifestError("manifest record violates recognized remote or sync policy")
        if record["remote_health"] != "required" or record["restore_tier"] != "rotating":
            raise ManifestError("manifest record violates remote-health or restore policy")
        owners = record["owning_jobs"]
        if not isinstance(owners, list) or not owners or not all(
            isinstance(owner, str) and owner for owner in owners
        ) or not OWNING_JOBS <= set(owners):
            raise ManifestError("manifest record is missing required owning jobs")
        paths.add(path)
        if prefix is not None:
            prefixes.add(prefix)
        databases.add(database)


@contextmanager
def _lock(path: Path):
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def append_record(path: Path, record: dict[str, Any]) -> AppendResult:
    """Append once and return the exact validated snapshot observed under lock."""
    validate_new_record(record)
    with _lock(path):
        manifest, digest = load_manifest(path)
        records = manifest["repositories"]
        validate_records(records)
        candidate_path = _canonical_path_identity(record)
        if any(
            _canonical_path_identity(item) == candidate_path
            or item.get("prefix") == record["prefix"]
            or item["database"] == record["database"]
            for item in records
        ):
            raise ManifestError("matching path, prefix, or database already exists")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ManifestError("manifest changed during enrollment")
        manifest["repositories"] = [*records, record]
        encoded = (json.dumps(manifest, indent=2, sort_keys=False) + "\n").encode()
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".manifest-", suffix=".json")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ManifestError("manifest changed before atomic replacement")
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

        committed_raw = path.read_bytes()
        if committed_raw != encoded:
            raise ManifestError("manifest changed during locked readback")
        committed = _parse_manifest(committed_raw)
        validate_records(committed["repositories"])
        if committed["repositories"] != [*records, record]:
            raise ManifestError("manifest locked readback was not the exact committed append")
        return AppendResult(
            manifest=deepcopy(committed),
            record=deepcopy(record),
            digest=hashlib.sha256(committed_raw).hexdigest(),
            raw=committed_raw,
        )

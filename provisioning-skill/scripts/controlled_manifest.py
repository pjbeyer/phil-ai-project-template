"""Isolated, descriptor-pinned controlled-G06 manifest append model.

This module is a cooperative disposable-fixture controller, not a hostile
same-process sandbox and not live readiness.  It is deliberately absent from
the public CLI and the quarantined live adapter.  It never executes G07 or a
coverage command; that boundary is recorded only as deferred evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import uuid
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .controlled_fixture import ControlledFixtureError, ControlledFixtureSession
from .evidence import redact
from .manifest import (
    AppendResult,
    ManifestError,
    _parse_manifest,
    append_record,
    validate_new_record,
    validate_records,
)
from .models import Gate, GateResult, ProvisioningEvidence

_MAX_MANIFEST_BYTES = 65_536
_ATTEMPT = "G06:controlled-manifest-append"
_DEFERRED_ACTION = (
    "Coverage audit is blocked and deferred at the controlled G06 boundary and was not "
    "executed; G07 and every live/public operation remain unavailable."
)


class ControlledManifestError(RuntimeError):
    """The controlled G06 fixture or lifecycle failed closed."""


@dataclass(frozen=True, slots=True)
class ControlledManifestRequest:
    """Exact controlled authority for one path/prefix/metadata-database tuple."""

    destination: Path
    prefix: str
    metadata_database: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.destination, Path)
            or not self.destination.is_absolute()
            or ".." in self.destination.parts
            or Path(str(self.destination)) != self.destination
        ):
            raise ControlledManifestError(
                "controlled manifest destination must be an exact canonical absolute Path"
            )
        for value, label in (
            (self.prefix, "prefix"),
            (self.metadata_database, "metadata database"),
        ):
            if (
                type(value) is not str
                or not value
                or value != value.strip()
                or "\x00" in value
                or "\n" in value
                or "\r" in value
            ):
                raise ControlledManifestError(
                    f"controlled manifest {label} must be exact nonempty text"
                )


class _ControlledManifestCapability:
    """Private construction key for the controlled-test-only factory."""


_CONTROLLED_MANIFEST_CAPABILITY = _ControlledManifestCapability()


def _stable(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_descriptor_bounded(fd: int, *, expected: os.stat_result, label: str) -> bytes:
    """Read one regular descriptor while proving its stable bounded snapshot."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > _MAX_MANIFEST_BYTES
            or _stable(before) != _stable(expected)
        ):
            raise ControlledManifestError(f"{label} was not a stable bounded regular file")
        remaining = _MAX_MANIFEST_BYTES + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(fd, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
    except OSError as error:
        raise ControlledManifestError(f"{label} descriptor readback failed") from error
    if len(raw) > _MAX_MANIFEST_BYTES or _stable(after) != _stable(before):
        raise ControlledManifestError(f"{label} changed during descriptor readback")
    return raw


class _CommittedManifestPin:
    """Post-atomic-replacement pin for the exact returned committed bytes."""

    def __init__(
        self,
        session: ControlledFixtureSession,
        fd: int,
        metadata: os.stat_result,
        raw: bytes,
    ) -> None:
        self._session = session
        self._fd = fd
        self._expected = metadata
        self._raw = raw

    @classmethod
    def open(
        cls,
        session: ControlledFixtureSession,
        expected_path_metadata: os.stat_result,
        expected_raw: bytes,
    ) -> _CommittedManifestPin:
        session.assert_ledger_binding()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open("manifest.json", flags, dir_fd=session.root_fd)
            metadata = os.fstat(fd)
        except OSError as error:
            raise ControlledManifestError(
                "controlled manifest committed binding could not be opened"
            ) from error
        try:
            if (
                not stat.S_ISREG(metadata.st_mode)
                or _stable(metadata) != _stable(expected_path_metadata)
            ):
                raise ControlledManifestError(
                    "controlled manifest committed binding was not the returned exact file"
                )
            pin = cls(session, fd, metadata, bytes(expected_raw))
            pin.assert_binding()
            return pin
        except Exception:
            os.close(fd)
            raise

    def assert_binding(self) -> None:
        self._session.assert_ledger_binding()
        try:
            canonical = os.stat(
                "manifest.json",
                dir_fd=self._session.root_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ControlledManifestError(
                "controlled manifest committed canonical binding was unavailable"
            ) from error
        if stat.S_ISLNK(canonical.st_mode) or _stable(canonical) != _stable(self._expected):
            raise ControlledManifestError(
                "controlled manifest committed binding changed before completion"
            )
        raw = _read_descriptor_bounded(
            self._fd,
            expected=self._expected,
            label="controlled committed manifest",
        )
        if raw != self._raw:
            raise ControlledManifestError(
                "controlled manifest committed bytes changed before completion"
            )
        self._session.assert_ledger_binding()

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


class ControlledManifestController:
    """Private, single-use controlled G06 controller for disposable fixtures."""

    def __init__(
        self,
        *,
        fixture_root: Path,
        _capability: _ControlledManifestCapability | None = None,
    ) -> None:
        if _capability is not _CONTROLLED_MANIFEST_CAPABILITY:
            raise ControlledManifestError(
                "controlled G06 requires the private controlled-test factory"
            )
        if type(self) is not ControlledManifestController:
            raise ControlledManifestError("controlled G06 controller subclasses are not admitted")
        self._root = self._validate_fixture_root(fixture_root)
        self._evidence_path = self._root / "evidence"
        self._manifest_path = self._root / "manifest.json"
        self._validate_required_leaf(self._evidence_path, directory=True, label="evidence")
        self._validate_required_leaf(self._manifest_path, directory=False, label="manifest")
        self._session: ControlledFixtureSession | None = None
        self._committed_pin: _CommittedManifestPin | None = None
        self._reservation: tuple[str, str, str] | None = None
        self._baseline_manifest: dict[str, Any] | None = None
        self._baseline_raw: bytes | None = None
        self._baseline_digest: str | None = None
        self._evidence: ProvisioningEvidence | None = None
        self._state = "new"

    @classmethod
    def _for_controlled_test(
        cls,
        *,
        fixture_root: Path,
    ) -> ControlledManifestController:
        """Construct solely for an exact disposable controlled-test fixture."""
        if cls is not ControlledManifestController:
            raise ControlledManifestError("controlled G06 controller subclasses are not admitted")
        return cls(
            fixture_root=fixture_root,
            _capability=_CONTROLLED_MANIFEST_CAPABILITY,
        )

    @staticmethod
    def _validate_fixture_root(root: Path) -> Path:
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise ControlledManifestError(
                "controlled G06 fixture root must be an exact canonical absolute Path"
            )
        try:
            canonical = root.resolve(strict=True)
            metadata = root.lstat()
            temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        except OSError as error:
            raise ControlledManifestError("controlled G06 fixture root was unavailable") from error
        if (
            canonical != root
            or root.parent != temporary_root
            or not root.name.startswith("tmp")
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ControlledManifestError(
                "controlled G06 accepts only an exact disposable temporary fixture root"
            )
        return root

    @staticmethod
    def _validate_required_leaf(
        path: Path,
        *,
        directory: bool,
        label: str,
    ) -> None:
        expected_name = "evidence" if directory else "manifest.json"
        if path.name != expected_name:
            raise ControlledManifestError(f"controlled G06 {label} leaf name was not exact")
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ControlledManifestError(f"controlled G06 {label} leaf was unavailable") from error
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if stat.S_ISLNK(metadata.st_mode) or not expected_type(metadata.st_mode):
            raise ControlledManifestError(
                f"controlled G06 {label} leaf must be an exact {'directory' if directory else 'regular file'}"
            )
        if not directory and (metadata.st_size < 0 or metadata.st_size > _MAX_MANIFEST_BYTES):
            raise ControlledManifestError("controlled G06 manifest leaf was not bounded")

    @staticmethod
    def _request_tuple(request: ControlledManifestRequest) -> tuple[str, str, str]:
        if type(request) is not ControlledManifestRequest:
            raise ControlledManifestError(
                "controlled G06 requires the exact ControlledManifestRequest type"
            )
        request.__post_init__()
        return (str(request.destination), request.prefix, request.metadata_database)

    @staticmethod
    def _fingerprint(authority: tuple[str, str, str]) -> str:
        canonical = json.dumps(authority, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_detail(error: BaseException) -> str:
        detail = redact(str(error) or "controlled manifest failure")
        if "[REDACTED]" in detail:
            return "controlled manifest failed with sanitized diagnostics"
        return detail[:500]

    @staticmethod
    def _validate_plain_candidate(value: object) -> dict[str, Any]:
        if type(value) is not dict or any(type(key) is not str for key in value):
            raise ControlledManifestError(
                "manifest candidate must use the exact controlled shape"
            )
        expected_string_fields = {
            "path",
            "prefix",
            "database",
            "owner",
            "profile",
            "expected_remote",
            "expected_sync",
            "remote_health",
            "restore_tier",
        }
        if any(type(value.get(key)) is not str for key in expected_string_fields):
            raise ControlledManifestError(
                "manifest candidate must use the exact controlled shape"
            )
        if type(value.get("expected_backup")) is not bool:
            raise ControlledManifestError(
                "manifest candidate must use the exact controlled shape"
            )
        jobs = value.get("owning_jobs")
        if type(jobs) is not list or any(type(job) is not str for job in jobs):
            raise ControlledManifestError(
                "manifest candidate must use the exact controlled shape"
            )
        snapshot = deepcopy(value)
        if type(snapshot) is not dict or type(snapshot["owning_jobs"]) is not list:
            raise ControlledManifestError(
                "manifest candidate must use the exact controlled shape"
            )
        try:
            validate_new_record(snapshot)
        except ManifestError as error:
            raise ControlledManifestError(
                "manifest candidate violates the strict controlled policy"
            ) from error
        return snapshot

    def _open_session(self) -> ControlledFixtureSession:
        try:
            session = ControlledFixtureSession(self._root)
            session.open()
            session.pin_directory("fixture-root", ())
            session.pin_regular(
                "fixture-root:manifest.json",
                "fixture-root",
                "manifest.json",
            )
        except ControlledFixtureError as error:
            try:
                session.close()
            except (NameError, UnboundLocalError):
                pass
            raise ControlledManifestError(
                "controlled G06 descriptor session could not be opened"
            ) from error
        self._session = session
        return session

    def _close(self) -> None:
        if self._committed_pin is not None:
            self._committed_pin.close()
            self._committed_pin = None
        if self._session is not None:
            self._session.close()
            self._session = None

    def _persist(self, *, preserve_manifest_failure: bool) -> None:
        if self._session is None or self._evidence is None:
            raise ControlledManifestError("controlled G06 evidence session was unavailable")
        try:
            self._session.persist(
                self._evidence,
                preserve_on_binding_failure=preserve_manifest_failure,
            )
        except (ControlledFixtureError, OSError, ValueError) as error:
            raise ControlledManifestError(
                "controlled G06 descriptor-bound evidence persistence failed"
            ) from error

    def _finish_failure(self, error: BaseException) -> None:
        evidence = self._evidence
        if evidence is None:
            return
        evidence.state = "partial"
        evidence.failed_gate = Gate.MANIFEST.value
        evidence.gates = [
            GateResult(Gate.MANIFEST, "failed", self._safe_detail(error))
        ]
        evidence.resume_requirement = "controlled-inspection-required"
        evidence.next_action = _DEFERRED_ACTION
        try:
            self._persist(preserve_manifest_failure=True)
        except ControlledManifestError:
            # A canonical evidence-leaf replacement is itself the failure.  The
            # original descriptor-held ledger retains the last durable attempt;
            # never write the replacement or mask the controlled G06 error.
            pass

    def reserve(self, request: ControlledManifestRequest) -> None:
        """Pin and reserve one exact tuple from a descriptor-backed baseline."""
        if self._state != "new":
            raise ControlledManifestError("controlled G06 controller is single-use")
        self._state = "reserving"
        session: ControlledFixtureSession | None = None
        try:
            authority = self._request_tuple(request)
            session = self._open_session()
            try:
                relative_destination = request.destination.relative_to(self._root)
            except ValueError as error:
                raise ControlledManifestError(
                    "controlled manifest destination escaped the disposable fixture root"
                ) from error
            if (
                not relative_destination.parts
                or relative_destination.parts[0] in {"evidence", "manifest.json"}
            ):
                raise ControlledManifestError(
                    "controlled manifest destination was not a fixture repository directory"
                )
            session.pin_directory("destination", tuple(relative_destination.parts))
            raw, _ = session.read_pinned_regular(
                "fixture-root",
                "manifest.json",
                label="controlled manifest",
            )
            try:
                manifest = _parse_manifest(raw)
                records = manifest["repositories"]
                validate_records(records)
            except (KeyError, ManifestError, TypeError) as error:
                raise ControlledManifestError(
                    "controlled manifest reservation rejected malformed current state"
                ) from error
            destination, prefix, database = authority
            if any(
                record["path"] == destination
                or record.get("prefix") == prefix
                or record["database"] == database
                for record in records
            ):
                raise ControlledManifestError(
                    "controlled manifest reservation found a path/prefix/database conflict"
                )
            self._reservation = authority
            self._baseline_manifest = deepcopy(manifest)
            self._baseline_raw = bytes(raw)
            self._baseline_digest = hashlib.sha256(raw).hexdigest()
            self._evidence = ProvisioningEvidence(
                run_id=uuid.uuid4().hex,
                request_fingerprint=self._fingerprint(authority),
                destination="[REDACTED]",
                repository_identity="controlled-fixture/g06",
                state="partial",
                failed_gate=Gate.MANIFEST.value,
                actual_database=database,
                resume_requirement="controlled-inspection-required",
                next_action=_DEFERRED_ACTION,
                simulation=True,
            )
            self._persist(preserve_manifest_failure=False)
            self._state = "reserved"
        except Exception as error:
            self._state = "finished"
            if self._evidence is not None:
                self._finish_failure(error)
            self._close()
            if isinstance(error, ControlledManifestError):
                raise
            raise ControlledManifestError(
                "controlled manifest reservation failed closed"
            ) from error

    def _validate_pre_append_baseline(self) -> None:
        if (
            self._session is None
            or self._baseline_raw is None
            or self._baseline_digest is None
            or self._baseline_manifest is None
        ):
            raise ControlledManifestError(
                "controlled G06 reservation baseline was unavailable"
            )
        self._session.assert_bindings()
        raw, _ = self._session.read_pinned_regular(
            "fixture-root",
            "manifest.json",
            label="controlled manifest",
        )
        if (
            raw != self._baseline_raw
            or hashlib.sha256(raw).hexdigest() != self._baseline_digest
            or _parse_manifest(raw) != self._baseline_manifest
        ):
            raise ControlledManifestError(
                "controlled manifest binding or reservation baseline changed before append"
            )

    def _validate_append_result(
        self,
        returned: object,
        candidate: dict[str, Any],
    ) -> AppendResult:
        if type(returned) is not AppendResult:
            raise ControlledManifestError(
                "controlled manifest append result used the wrong exact type"
            )
        if (
            type(returned.manifest) is not dict
            or type(returned.record) is not dict
            or type(returned.raw) is not bytes
            or type(returned.digest) is not str
            or len(returned.raw) > _MAX_MANIFEST_BYTES
        ):
            raise ControlledManifestError(
                "controlled manifest append result had an invalid exact shape"
            )
        if self._baseline_manifest is None:
            raise ControlledManifestError(
                "controlled manifest append result had no reserved baseline"
            )
        try:
            parsed = _parse_manifest(returned.raw)
            validate_records(parsed["repositories"])
        except (KeyError, ManifestError, TypeError) as error:
            raise ControlledManifestError(
                "controlled manifest append result failed strict parsing"
            ) from error
        expected_manifest = {
            "repositories": [
                *deepcopy(self._baseline_manifest["repositories"]),
                deepcopy(candidate),
            ]
        }
        canonical_raw = (
            json.dumps(parsed, indent=2, sort_keys=False) + "\n"
        ).encode("utf-8")
        if (
            returned.record != candidate
            or returned.manifest != parsed
            or parsed != expected_manifest
            or returned.raw != canonical_raw
            or hashlib.sha256(returned.raw).hexdigest() != returned.digest
        ):
            raise ControlledManifestError(
                "controlled manifest append result was not the exact canonical committed append"
            )
        return returned

    def _before_completion_for_controlled_test(self) -> None:
        """No-op failure-injection seam; controlled tests may replace fixture leaves."""

    def append(self, record: dict[str, Any]) -> ProvisioningEvidence:
        """Attempt one strict append; success and failure both consume the controller."""
        if self._state == "new":
            raise ControlledManifestError("controlled G06 reservation is required before append")
        if self._state != "reserved":
            raise ControlledManifestError("controlled G06 append retry is forbidden")
        self._state = "appending"
        try:
            if self._reservation is None or self._evidence is None or self._session is None:
                raise ControlledManifestError(
                    "controlled G06 reservation is required before append"
                )
            candidate = self._validate_plain_candidate(record)
            exact = (
                candidate["path"],
                candidate["prefix"],
                candidate["database"],
            )
            if exact != self._reservation:
                raise ControlledManifestError(
                    "manifest candidate does not match the reserved authoritative tuple"
                )

            self._evidence.mutation_attempts.append(_ATTEMPT)
            try:
                # The attempt must survive a later manifest-binding failure, so
                # persistence validates only the still-held root/evidence ledger.
                self._persist(preserve_manifest_failure=True)
            except Exception:
                self._evidence.mutation_attempts.pop()
                raise

            try:
                self._validate_pre_append_baseline()
            except (ControlledFixtureError, ManifestError) as error:
                raise ControlledManifestError(
                    "controlled manifest binding changed before append"
                ) from error

            try:
                returned = append_record(self._manifest_path, candidate)
            except (ManifestError, OSError, KeyError, TypeError, ValueError) as error:
                raise ControlledManifestError(
                    "controlled manifest compare-and-append failed"
                ) from error
            try:
                committed_path_metadata = os.stat(
                    "manifest.json",
                    dir_fd=self._session.root_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ControlledManifestError(
                    "controlled manifest committed binding was unavailable after append"
                ) from error
            committed = self._validate_append_result(returned, candidate)
            try:
                self._committed_pin = _CommittedManifestPin.open(
                    self._session,
                    committed_path_metadata,
                    committed.raw,
                )
                self._committed_pin.assert_binding()
                self._before_completion_for_controlled_test()
                self._committed_pin.assert_binding()
            except (ControlledFixtureError, ControlledManifestError, OSError) as error:
                raise ControlledManifestError(
                    "controlled manifest committed binding validation failed"
                ) from error

            self._evidence.mutations_completed.append(_ATTEMPT)
            self._evidence.state = "partial"
            self._evidence.failed_gate = None
            self._evidence.gates = [
                GateResult(
                    Gate.MANIFEST,
                    "passed",
                    "one exact controlled path/prefix/metadata-database record was appended, "
                    "strictly reparsed, and descriptor-bound; coverage remains deferred",
                )
            ]
            self._evidence.resume_requirement = "controlled-inspection-required"
            self._evidence.next_action = _DEFERRED_ACTION
            try:
                self._persist(preserve_manifest_failure=True)
                self._committed_pin.assert_binding()
            except Exception:
                self._evidence.mutations_completed.pop()
                raise
            result = self._evidence
            self._state = "finished"
            self._close()
            return result
        except Exception as error:
            self._state = "finished"
            self._finish_failure(error)
            self._close()
            if isinstance(error, ControlledManifestError):
                raise
            raise ControlledManifestError(
                "controlled manifest append failed closed"
            ) from error

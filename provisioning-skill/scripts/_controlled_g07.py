"""Private descriptor-pinned controlled-G07 fixture controller.

This is a cooperative disposable-fixture model, not a hostile same-process
sandbox and not live readiness. It has no production-adapter or public-CLI
wiring and performs no external command. Its only mutations create controlled
synthetic backup fixture leaves beneath an already pinned synthetic ``.beads``.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import uuid
from copy import deepcopy
from pathlib import Path

from .controlled_fixture import ControlledFixtureError, ControlledFixtureSession
from .controlled_manifest import ControlledManifestController
from .evidence import redact
from .manifest import ManifestError, _parse_manifest, validate_new_record, validate_records
from .models import Gate, GateResult, ProvisioningEvidence

_MAX_READ = 65_536
_G06_ATTEMPT = "G06:controlled-manifest-append"
_G07_INIT = "G07:controlled-backup-init"
_G07_SYNC = "G07:controlled-backup-sync"
_NEXT_ACTION = (
    "Controlled G07 passed; G08 and every live/public operation remain blocked "
    "and require a separate controlled design and approval."
)
_FAILURE_ACTION = (
    "Controlled G07 partial failure was recorded; preserve G06 completion and "
    "all controlled fixture state, perform controlled inspection, and do not retry."
)


class ControlledG07Error(RuntimeError):
    """The controlled G07 fixture or single-use lifecycle failed closed."""


class ControlledG07Request:
    """Immutable exact controlled authority for one synthetic enrollment tuple."""

    __slots__ = ("_database", "_destination", "_prefix")

    def __init__(self, destination: Path, prefix: str, database: str) -> None:
        self._validate(destination, prefix, database)
        object.__setattr__(self, "_destination", destination)
        object.__setattr__(self, "_prefix", prefix)
        object.__setattr__(self, "_database", database)

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("controlled G07 request is immutable")
        object.__setattr__(self, name, value)

    @staticmethod
    def _validate(destination: Path, prefix: str, database: str) -> None:
        if (
            not isinstance(destination, Path)
            or not destination.is_absolute()
            or ".." in destination.parts
            or Path(str(destination)) != destination
        ):
            raise ControlledG07Error(
                "controlled G07 destination must be an exact canonical absolute Path"
            )
        for value, label in ((prefix, "prefix"), (database, "database")):
            if (
                type(value) is not str
                or not value
                or value != value.strip()
                or "\x00" in value
                or "\n" in value
                or "\r" in value
            ):
                raise ControlledG07Error(f"controlled G07 {label} must be exact nonempty text")

    @property
    def destination(self) -> Path:
        return self._destination

    @property
    def prefix(self) -> str:
        return self._prefix

    @property
    def database(self) -> str:
        return self._database

    def exact_tuple(self) -> tuple[str, str, str]:
        self._validate(self.destination, self.prefix, self.database)
        return (str(self.destination), self.prefix, self.database)


class _ControlledG07Capability:
    """Private constructor key held only by the module test factory."""


_CONTROLLED_G07_CAPABILITY = _ControlledG07Capability()


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


def _request_fingerprint(authority: tuple[str, str, str], g06_fingerprint: str) -> str:
    canonical = json.dumps(
        {"g06": g06_fingerprint, "tuple": authority},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_detail(error: BaseException) -> str:
    detail = redact(str(error) or "controlled G07 failure")
    if "[REDACTED]" in detail:
        return "controlled G07 failed with sanitized diagnostics"
    return detail[:500]


def _read_exact_regular(
    directory_fd: int,
    leaf: str,
    *,
    expected_mode: int,
    expected_device: int,
    expected_raw: bytes | None = None,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        canonical_before = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(canonical_before.st_mode)
            or not stat.S_ISREG(canonical_before.st_mode)
            or canonical_before.st_dev != expected_device
            or stat.S_IMODE(canonical_before.st_mode) != expected_mode
            or canonical_before.st_size < 0
            or canonical_before.st_size > _MAX_READ
        ):
            raise ControlledG07Error("controlled G07 regular fixture binding was unsafe")
        fd = os.open(leaf, flags, dir_fd=directory_fd)
        opened = os.fstat(fd)
        if _stable(opened) != _stable(canonical_before):
            raise ControlledG07Error("controlled G07 regular fixture binding changed")
        chunks: list[bytes] = []
        remaining = _MAX_READ + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after_descriptor = os.fstat(fd)
        canonical_after = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except ControlledG07Error:
        raise
    except OSError as error:
        raise ControlledG07Error("controlled G07 regular fixture readback failed") from error
    finally:
        if fd is not None:
            os.close(fd)
    if (
        len(raw) > _MAX_READ
        or _stable(after_descriptor) != _stable(opened)
        or _stable(canonical_after) != _stable(opened)
        or (expected_raw is not None and raw != expected_raw)
    ):
        raise ControlledG07Error("controlled G07 regular fixture binding changed")
    return raw, opened


class _ControlledG07Controller:
    """Private single-use controlled G07 controller for disposable fixtures."""

    def __init__(
        self,
        *,
        fixture_root: Path,
        request: ControlledG07Request,
        g06_evidence: ProvisioningEvidence,
        _capability: _ControlledG07Capability | None = None,
    ) -> None:
        if _capability is not _CONTROLLED_G07_CAPABILITY:
            raise ControlledG07Error("controlled G07 requires the private controlled-test factory")
        if type(self) is not _ControlledG07Controller:
            raise ControlledG07Error("controlled G07 controller subclasses are not admitted")
        self._root = self._validate_fixture_root(fixture_root)
        if type(request) is not ControlledG07Request:
            raise ControlledG07Error("controlled G07 requires the exact request type")
        authority = request.exact_tuple()
        try:
            relative = request.destination.relative_to(self._root)
        except ValueError as error:
            raise ControlledG07Error(
                "controlled G07 destination escaped the disposable fixture root"
            ) from error
        if not relative.parts or relative.parts[0] in {"evidence", "manifest.json"}:
            raise ControlledG07Error("controlled G07 destination was not a fixture repository")
        self._destination_parts = tuple(relative.parts)
        self._request = request
        self._g06 = self._validate_g06_evidence(g06_evidence, authority)
        self._g06_evidence_name = (
            f"{self._g06.request_fingerprint}-{self._g06.run_id}.json"
        )
        self._manifest_expected_raw = self._load_initial_regular(
            self._root / "manifest.json", "manifest"
        )
        self._g06_expected_raw = self._load_initial_regular(
            self._root / "evidence" / self._g06_evidence_name,
            "G06 evidence",
        )
        self._validate_persisted_g06_predecessor(
            manifest_raw=self._manifest_expected_raw,
            g06_raw=self._g06_expected_raw,
        )
        self._state = "new"
        self._session: ControlledFixtureSession | None = None
        self._evidence = ProvisioningEvidence(
            run_id=uuid.uuid4().hex,
            request_fingerprint=_request_fingerprint(authority, self._g06.request_fingerprint),
            destination="[REDACTED]",
            repository_identity="controlled-fixture/g07",
            state="partial",
            failed_gate=Gate.BACKUP.value,
            gates=self._base_gates(),
            mutation_attempts=list(self._g06.mutation_attempts),
            mutations_completed=list(self._g06.mutations_completed),
            actual_database=request.database,
            resume_requirement="controlled-inspection-required",
            next_action=_FAILURE_ACTION,
            simulation=True,
        )

    @classmethod
    def _for_controlled_test(
        cls,
        *,
        fixture_root: Path,
        request: ControlledG07Request,
        g06_evidence: ProvisioningEvidence,
    ) -> _ControlledG07Controller:
        if cls is not _ControlledG07Controller:
            raise ControlledG07Error("controlled G07 controller subclasses are not admitted")
        return cls(
            fixture_root=fixture_root,
            request=request,
            g06_evidence=g06_evidence,
            _capability=_CONTROLLED_G07_CAPABILITY,
        )

    @staticmethod
    def _validate_fixture_root(root: Path) -> Path:
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise ControlledG07Error(
                "controlled G07 fixture root must be an exact canonical absolute Path"
            )
        try:
            canonical = root.resolve(strict=True)
            metadata = root.lstat()
            temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        except OSError as error:
            raise ControlledG07Error("controlled G07 fixture root was unavailable") from error
        if (
            canonical != root
            or root.parent != temporary_root
            or not root.name.startswith("tmp")
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ControlledG07Error(
                "controlled G07 accepts only an exact disposable temporary fixture root"
            )
        return root

    @staticmethod
    def _load_initial_regular(path: Path, label: str) -> bytes:
        try:
            metadata = path.lstat()
            raw = path.read_bytes()
            after = path.lstat()
        except OSError as error:
            raise ControlledG07Error(f"controlled G07 {label} was unavailable") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or metadata.st_size > _MAX_READ
            or _stable(metadata) != _stable(after)
            or len(raw) > _MAX_READ
        ):
            raise ControlledG07Error(f"controlled G07 {label} was not a stable bounded file")
        return raw

    @staticmethod
    def _validate_g06_evidence(
        evidence: ProvisioningEvidence,
        authority: tuple[str, str, str],
    ) -> ProvisioningEvidence:
        if type(evidence) is not ProvisioningEvidence:
            raise ControlledG07Error("controlled G07 requires exact G06 evidence")
        try:
            snapshot = deepcopy(evidence)
        except Exception as error:
            raise ControlledG07Error("controlled G07 could not snapshot G06 evidence") from error
        expected_gate = [
            (
                Gate.MANIFEST,
                "passed",
                "one exact controlled path/prefix/metadata-database record was appended, "
                "strictly reparsed, and descriptor-bound; coverage remains deferred",
            )
        ]
        if (
            snapshot.state != "partial"
            or snapshot.failed_gate is not None
            or snapshot.simulation is not True
            or snapshot.actual_database != authority[2]
            or snapshot.mutation_attempts != [_G06_ATTEMPT]
            or snapshot.mutations_completed != [_G06_ATTEMPT]
            or [(item.gate, item.status, item.detail) for item in snapshot.gates] != expected_gate
        ):
            raise ControlledG07Error(
                "controlled G07 requires completed descriptor-bound controlled G06 evidence"
            )
        return snapshot

    def _validate_persisted_g06_predecessor(
        self,
        *,
        manifest_raw: bytes,
        g06_raw: bytes,
    ) -> None:
        """Prove disk predecessor artifacts match this exact G06/G07 authority."""
        try:
            manifest = _parse_manifest(manifest_raw)
            records = manifest["repositories"]
            validate_records(records)
            persisted = json.loads(g06_raw.decode("utf-8"))
        except (
            KeyError,
            ManifestError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as error:
            raise ControlledG07Error(
                "controlled G06 predecessor readback was malformed"
            ) from error
        authority = self._request.exact_tuple()
        expected_g06_fingerprint = ControlledManifestController._fingerprint(authority)
        expected_gates = [
            {
                "detail": "one exact controlled path/prefix/metadata-database record was appended, strictly reparsed, and descriptor-bound; coverage remains deferred",
                "gate": Gate.MANIFEST,
                "status": "passed",
            }
        ]
        exact_records = [
            record
            for record in records
            if record["path"] == authority[0]
            and record.get("prefix") == authority[1]
            and record["database"] == authority[2]
        ]
        if len(exact_records) == 1:
            try:
                validate_new_record(exact_records[0])
            except ManifestError as error:
                raise ControlledG07Error(
                    "controlled G06 predecessor enrollment did not retain strict policy"
                ) from error
        if (
            type(persisted) is not dict
            or self._g06.request_fingerprint != expected_g06_fingerprint
            or persisted.get("request_fingerprint") != expected_g06_fingerprint
            or persisted.get("run_id") != self._g06.run_id
            or persisted.get("destination") != "[REDACTED]"
            or persisted.get("repository_identity") != "controlled-fixture/g06"
            or persisted.get("state") != "partial"
            or persisted.get("failed_gate") is not None
            or persisted.get("actual_database") != authority[2]
            or persisted.get("simulation") is not True
            or persisted.get("mutation_attempts") != [_G06_ATTEMPT]
            or persisted.get("mutations_completed") != [_G06_ATTEMPT]
            or persisted.get("gates") != expected_gates
            or persisted.get("resume_requirement") != "controlled-inspection-required"
            or len(exact_records) != 1
        ):
            raise ControlledG07Error(
                "controlled G06 predecessor did not prove the exact completed enrollment"
            )

    def _base_gates(self) -> list[GateResult]:
        return [
            GateResult(
                Gate.MANIFEST,
                "passed",
                "controlled G06 append completion was preserved and descriptor-bound",
            )
        ]

    def _open_session(self) -> ControlledFixtureSession:
        session: ControlledFixtureSession | None = None
        try:
            session = ControlledFixtureSession(self._root)
            session.open()
            self._session = session
            session.pin_directory("fixture-root", ())
            session.pin_directory("destination", self._destination_parts)
            session.pin_directory("beads", self._destination_parts + (".beads",))
            session.pin_directory("controlled-evidence", ("evidence",))
            session.pin_regular(
                "fixture-root:manifest.json", "fixture-root", "manifest.json"
            )
            session.pin_regular(
                f"controlled-evidence:{self._g06_evidence_name}",
                "controlled-evidence",
                self._g06_evidence_name,
            )
        except (ControlledFixtureError, OSError) as error:
            raise ControlledG07Error(
                "controlled G07 descriptor session could not be opened"
            ) from error
        return session

    def _assert_predecessor_bindings(self) -> None:
        if self._session is None:
            raise ControlledG07Error("controlled G07 descriptor session was unavailable")
        self._session.assert_bindings()
        manifest_raw, _ = self._session.read_pinned_regular(
            "fixture-root", "manifest.json", label="controlled G06 manifest"
        )
        g06_raw, _ = self._session.read_pinned_regular(
            "controlled-evidence",
            self._g06_evidence_name,
            label="controlled G06 evidence",
        )
        if manifest_raw != self._manifest_expected_raw or g06_raw != self._g06_expected_raw:
            raise ControlledG07Error("controlled G06 predecessor binding changed")
        self._validate_persisted_g06_predecessor(
            manifest_raw=manifest_raw,
            g06_raw=g06_raw,
        )

    def _persist(self, *, preserve_on_binding_failure: bool) -> None:
        if self._session is None:
            raise ControlledG07Error("controlled G07 evidence session was unavailable")
        try:
            self._session.persist(
                self._evidence,
                preserve_on_binding_failure=preserve_on_binding_failure,
            )
        except (ControlledFixtureError, OSError, ValueError) as error:
            raise ControlledG07Error(
                "controlled G07 descriptor-bound evidence persistence failed"
            ) from error

    def _record_attempt(self, attempt: str) -> None:
        self._evidence.mutation_attempts.append(attempt)
        try:
            self._persist(preserve_on_binding_failure=True)
        except Exception:
            self._evidence.mutation_attempts.pop()
            raise

    def _record_completion(self, attempt: str) -> None:
        self._evidence.mutations_completed.append(attempt)
        try:
            self._persist(preserve_on_binding_failure=True)
        except Exception:
            self._evidence.mutations_completed.pop()
            raise

    def _finish_failure(
        self,
        error: BaseException,
        *,
        preserve_g06_completion: bool,
    ) -> None:
        self._evidence.state = "partial"
        self._evidence.failed_gate = Gate.BACKUP.value
        predecessor = (
            self._base_gates()
            if preserve_g06_completion
            else [
                GateResult(
                    Gate.MANIFEST,
                    "failed",
                    "controlled G06 predecessor was not proven; its completion was not claimed",
                )
            ]
        )
        self._evidence.gates = [
            *predecessor,
            GateResult(Gate.BACKUP, "failed", _safe_detail(error)),
        ]
        self._evidence.resume_requirement = "controlled-inspection-required"
        self._evidence.next_action = _FAILURE_ACTION
        try:
            self._persist(preserve_on_binding_failure=True)
        except ControlledG07Error:
            pass

    def _close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def _validate_empty_backup_state(self) -> None:
        if self._session is None:
            raise ControlledG07Error("controlled G07 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        entries = set(self._session.list_directory("beads"))
        if "backup" in entries or "dolt-backup.json" in entries:
            raise ControlledG07Error(
                "existing backup state forbids controlled G07 initialization"
            )
        allowed = {"metadata.json"}
        if not entries.issubset(allowed):
            raise ControlledG07Error("unexpected controlled .beads fixture state")
        metadata_raw, metadata_stat = self._session.read_pinned_regular(
            "beads", "metadata.json", label="controlled metadata"
        )
        if stat.S_IMODE(metadata_stat.st_mode) != 0o600:
            raise ControlledG07Error("controlled metadata mode must be 0600")
        try:
            metadata = json.loads(metadata_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ControlledG07Error("controlled metadata readback failed") from error
        expected = {
            "dolt_database": self._request.database,
            "dolt_mode": "server",
            "dolt_server_port": 3307,
        }
        if type(metadata) is not dict or metadata != expected:
            raise ControlledG07Error("controlled metadata did not match exact G06 authority")

    def _initialize_fixture(self) -> None:
        if self._session is None:
            raise ControlledG07Error("controlled G07 descriptor session was unavailable")
        self._session.create_directory("beads", "backup", mode=0o700)
        self._session.pin_directory(
            "backup", self._destination_parts + (".beads", "backup")
        )
        sidecar = (
            json.dumps(
                {
                    "database": self._request.database,
                    "identity": "controlled-g07-sidecar/v1",
                    "root": ".beads/backup",
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self._session.create_regular(
            "beads", "dolt-backup.json", sidecar, mode=0o600
        )
        self._session.pin_regular(
            "beads:dolt-backup.json", "beads", "dolt-backup.json"
        )
        self._assert_predecessor_bindings()

    def _synchronize_for_controlled_test(self) -> None:
        if self._session is None:
            raise ControlledG07Error("controlled G07 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        snapshot = (
            json.dumps(
                {
                    "database": self._request.database,
                    "fresh": True,
                    "identity": "controlled-g07-snapshot/v1",
                    "synchronized": True,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self._session.create_regular(
            "backup", "snapshot.json", snapshot, mode=0o600
        )
        self._session.pin_regular(
            "backup:snapshot.json", "backup", "snapshot.json"
        )
        self._assert_predecessor_bindings()

    def _assert_terminal_state(self) -> None:
        if self._session is None:
            raise ControlledG07Error("controlled G07 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        beads_fd: int | None = None
        try:
            beads_fd = self._session.directory_fd("beads")
            backup_fd = self._session.directory_fd("backup")
        except Exception:
            if beads_fd is not None:
                os.close(beads_fd)
            raise
        try:
            beads_stat = os.fstat(beads_fd)
            backup_stat = os.fstat(backup_fd)
            if (
                not stat.S_ISDIR(backup_stat.st_mode)
                or stat.S_IMODE(backup_stat.st_mode) != 0o700
                or backup_stat.st_dev != beads_stat.st_dev
            ):
                raise ControlledG07Error("controlled backup root failed exact validation")
            if set(self._session.list_directory("backup")) != {"snapshot.json"}:
                raise ControlledG07Error("controlled backup tree had unexpected entries")
            sidecar_expected = (
                json.dumps(
                    {
                        "database": self._request.database,
                        "identity": "controlled-g07-sidecar/v1",
                        "root": ".beads/backup",
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            snapshot_expected = (
                json.dumps(
                    {
                        "database": self._request.database,
                        "fresh": True,
                        "identity": "controlled-g07-snapshot/v1",
                        "synchronized": True,
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            sidecar_raw, _ = _read_exact_regular(
                beads_fd,
                "dolt-backup.json",
                expected_mode=0o600,
                expected_device=beads_stat.st_dev,
                expected_raw=sidecar_expected,
            )
            snapshot_raw, _ = _read_exact_regular(
                backup_fd,
                "snapshot.json",
                expected_mode=0o600,
                expected_device=backup_stat.st_dev,
                expected_raw=snapshot_expected,
            )
        finally:
            os.close(backup_fd)
            if beads_fd is not None:
                os.close(beads_fd)
        try:
            sidecar = json.loads(sidecar_raw.decode("utf-8"))
            snapshot = json.loads(snapshot_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ControlledG07Error("controlled backup readback was invalid") from error
        if (
            sidecar
            != {
                "database": self._request.database,
                "identity": "controlled-g07-sidecar/v1",
                "root": ".beads/backup",
            }
            or snapshot
            != {
                "database": self._request.database,
                "fresh": True,
                "identity": "controlled-g07-snapshot/v1",
                "synchronized": True,
            }
        ):
            raise ControlledG07Error("controlled backup readback was not exact")
        self._assert_predecessor_bindings()
        self._session.assert_bindings()

    def _after_initialize_for_controlled_test(self) -> None:
        """Failure-injection seam for controlled leaf replacement tests."""

    def _after_synchronize_for_controlled_test(self) -> None:
        """Failure-injection seam for controlled readback tests."""

    def _before_terminal_confirmation_for_controlled_test(self) -> None:
        """Failure-injection seam immediately before final descriptor checks."""

    def run(self) -> ProvisioningEvidence:
        """Perform one synthetic G07 fixture transition; every outcome consumes it."""
        if self._state != "new":
            raise ControlledG07Error("controlled G07 controller is single-use")
        self._state = "running"
        g06_completion_proven = False
        try:
            session = self._open_session()
            session.pin_regular(
                "beads:metadata.json", "beads", "metadata.json"
            )
            self._assert_predecessor_bindings()
            g06_completion_proven = True
            self._validate_empty_backup_state()
            self._persist(preserve_on_binding_failure=False)

            self._record_attempt(_G07_INIT)
            self._assert_predecessor_bindings()
            self._initialize_fixture()
            self._record_completion(_G07_INIT)
            self._after_initialize_for_controlled_test()
            self._assert_predecessor_bindings()
            session.assert_bindings()

            self._record_attempt(_G07_SYNC)
            self._assert_predecessor_bindings()
            self._synchronize_for_controlled_test()
            self._record_completion(_G07_SYNC)
            self._after_synchronize_for_controlled_test()
            self._assert_predecessor_bindings()
            session.assert_bindings()

            self._before_terminal_confirmation_for_controlled_test()
            self._assert_terminal_state()
            self._evidence.state = "partial"
            self._evidence.failed_gate = None
            self._evidence.gates = [
                *self._base_gates(),
                GateResult(
                    Gate.BACKUP,
                    "passed",
                    "synthetic backup root, sidecar, synchronization, freshness, modes, "
                    "filesystem device, and exact descriptor-bound bytes were confirmed",
                ),
            ]
            self._evidence.resume_requirement = "controlled-inspection-required"
            self._evidence.next_action = _NEXT_ACTION
            self._persist(preserve_on_binding_failure=True)
            self._assert_terminal_state()
            result = self._evidence
            self._state = "finished"
            self._close()
            return result
        except Exception as error:
            self._state = "finished"
            self._finish_failure(error, preserve_g06_completion=g06_completion_proven)
            self._close()
            if isinstance(error, ControlledG07Error):
                raise
            if isinstance(error, ControlledFixtureError):
                raise ControlledG07Error("controlled G07 descriptor binding failed") from error
            raise ControlledG07Error("controlled G07 failed closed") from error


def _controlled_g07_for_test(
    *,
    fixture_root: Path,
    request: ControlledG07Request,
    g06_evidence: ProvisioningEvidence,
) -> _ControlledG07Controller:
    """Sole module factory for the private controlled-test-only controller."""
    return _ControlledG07Controller._for_controlled_test(
        fixture_root=fixture_root,
        request=request,
        g06_evidence=g06_evidence,
    )

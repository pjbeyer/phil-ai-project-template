"""Private descriptor-pinned controlled-G09 bootstrap fixture controller.

This is a cooperative disposable-fixture model, not a hostile same-process
sandbox and not live readiness. It has no production-adapter or public-CLI
wiring and performs no external command. Its only mutation creates one synthetic
bootstrap ledger leaf beneath an already pinned synthetic ``.beads`` tree.

Live G08 (SpecKit) remains blocked by the completed G08-C prerequisite; this
controlled G09 model records that gate as ``skipped`` (never ``passed``, never
``complete``) and chains its predecessor to the completed controlled-G07 state.
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
from .manifest import ManifestError, _parse_manifest, validate_records
from .models import Gate, GateResult, ProvisioningEvidence

_MAX_READ = 65_536
_G06_ATTEMPT = "G06:controlled-manifest-append"
_G07_INIT = "G07:controlled-backup-init"
_G07_SYNC = "G07:controlled-backup-sync"
_G09_ATTEMPT = "G09:controlled-bootstrap"
_BOOTSTRAP_IDENTITY = "controlled-g09-bootstrap/v1"
_NEXT_ACTION = (
    "Controlled G09 passed; G10/G11 and every live/public operation remain "
    "blocked and require a separate controlled design and approval."
)
_FAILURE_ACTION = (
    "Controlled G09 partial failure was recorded; preserve G06/G07 completion "
    "and all controlled fixture state, perform controlled inspection, and do "
    "not retry."
)


class ControlledG09Error(RuntimeError):
    """The controlled G09 fixture or single-use lifecycle failed closed."""


def _marker_valid(value: str, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise ControlledG09Error(f"controlled G09 {label} must be exact nonempty text")
    return value


class ControlledG09Request:
    """Immutable exact controlled authority for one synthetic bootstrap tuple."""

    __slots__ = ("_destination", "_prefix", "_database", "_markers")

    def __init__(
        self,
        destination: Path,
        prefix: str,
        database: str,
        markers: tuple[tuple[str, str], ...],
    ) -> None:
        self._validate(destination, prefix, database, markers)
        object.__setattr__(self, "_destination", destination)
        object.__setattr__(self, "_prefix", prefix)
        object.__setattr__(self, "_database", database)
        object.__setattr__(self, "_markers", tuple((m, t) for m, t in markers))

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("controlled G09 request is immutable")
        object.__setattr__(self, name, value)

    @staticmethod
    def _validate(
        destination: Path,
        prefix: str,
        database: str,
        markers: tuple[tuple[str, str], ...],
    ) -> None:
        if (
            not isinstance(destination, Path)
            or not destination.is_absolute()
            or ".." in destination.parts
            or Path(str(destination)) != destination
        ):
            raise ControlledG09Error(
                "controlled G09 destination must be an exact canonical absolute Path"
            )
        for value, label in ((prefix, "prefix"), (database, "database")):
            _marker_valid(value, label)
        if not isinstance(markers, tuple) or not markers:
            raise ControlledG09Error("controlled G09 markers must be a nonempty tuple")
        seen: set[str] = set()
        for marker, title in markers:
            _marker_valid(marker, "marker")
            _marker_valid(title, "title")
            if marker in seen:
                raise ControlledG09Error("controlled G09 markers must be unique")
            seen.add(marker)

    @property
    def destination(self) -> Path:
        return self._destination

    @property
    def prefix(self) -> str:
        return self._prefix

    @property
    def database(self) -> str:
        return self._database

    @property
    def markers(self) -> tuple[tuple[str, str], ...]:
        return self._markers

    def exact_tuple(self) -> tuple[str, str, str]:
        self._validate(self.destination, self.prefix, self.database, self.markers)
        return (str(self.destination), self.prefix, self.database)


class _ControlledG09Capability:
    """Private constructor key held only by the module test factory."""


_CONTROLLED_G09_CAPABILITY = _ControlledG09Capability()


def _request_fingerprint(authority: tuple[str, str, str], g07_fingerprint: str) -> str:
    canonical = json.dumps(
        {"g07": g07_fingerprint, "tuple": authority},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_detail(error: BaseException) -> str:
    detail = redact(str(error) or "controlled G09 failure")
    if "[REDACTED]" in detail:
        return "controlled G09 failed with sanitized diagnostics"
    return detail[:500]


def _load_initial_regular(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise ControlledG09Error(f"controlled G09 {label} was unavailable") from error
    stable = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_size, m.st_mtime_ns, m.st_ctime_ns)  # noqa: E731
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > _MAX_READ
        or stable(metadata) != stable(after)
        or len(raw) > _MAX_READ
    ):
        raise ControlledG09Error(f"controlled G09 {label} was not a stable bounded file")
    return raw


def _bootstrap_ledger(database: str, markers: tuple[tuple[str, str], ...]) -> bytes:
    return (
        json.dumps(
            {
                "database": database,
                "identity": _BOOTSTRAP_IDENTITY,
                "markers": [{"marker": m, "title": t} for m, t in markers],
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


class _ControlledG09Controller:
    """Private, single-use controlled G09 controller for disposable fixtures."""

    def __init__(
        self,
        *,
        fixture_root: Path,
        request: ControlledG09Request,
        g07_evidence: ProvisioningEvidence,
        _capability: _ControlledG09Capability | None = None,
    ) -> None:
        if _capability is not _CONTROLLED_G09_CAPABILITY:
            raise ControlledG09Error(
                "controlled G09 requires the private controlled-test factory"
            )
        if type(self) is not _ControlledG09Controller:
            raise ControlledG09Error("controlled G09 controller subclasses are not admitted")
        self._root = self._validate_fixture_root(fixture_root)
        if type(request) is not ControlledG09Request:
            raise ControlledG09Error("controlled G09 requires the exact request type")
        authority = request.exact_tuple()
        try:
            relative = request.destination.relative_to(self._root)
        except ValueError as error:
            raise ControlledG09Error(
                "controlled G09 destination escaped the disposable fixture root"
            ) from error
        if not relative.parts or relative.parts[0] in {"evidence", "manifest.json"}:
            raise ControlledG09Error("controlled G09 destination was not a fixture repository")
        self._destination_parts = tuple(relative.parts)
        self._request = request
        self._snapshot = self._validate_g07_evidence(g07_evidence, authority)
        self._g07_evidence_name = f"{self._snapshot.request_fingerprint}-{self._snapshot.run_id}.json"
        self._manifest_expected_raw = _load_initial_regular(
            self._root / "manifest.json", "manifest"
        )
        self._g07_expected_raw = _load_initial_regular(
            self._root / "evidence" / self._g07_evidence_name, "G07 evidence"
        )
        self._metadata = _load_initial_regular(
            self._root.joinpath(*self._destination_parts) / ".beads" / "metadata.json",
            "metadata",
        )
        self._backup_sidecar_expected = _load_initial_regular(
            self._root.joinpath(*self._destination_parts) / ".beads" / "dolt-backup.json",
            "backup sidecar",
        )
        self._backup_snapshot_expected = _load_initial_regular(
            self._root.joinpath(*self._destination_parts) / ".beads" / "backup" / "snapshot.json",
            "backup snapshot",
        )
        self._validate_persisted_g07_predecessor()
        self._state = "new"
        self._session: ControlledFixtureSession | None = None
        self._evidence = ProvisioningEvidence(
            run_id=uuid.uuid4().hex,
            request_fingerprint=_request_fingerprint(authority, self._snapshot.request_fingerprint),
            destination="[REDACTED]",
            repository_identity="controlled-fixture/g09",
            state="partial",
            failed_gate=Gate.BOOTSTRAP.value,
            gates=self._base_gates(),
            mutation_attempts=list(self._snapshot.mutation_attempts),
            mutations_completed=list(self._snapshot.mutations_completed),
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
        request: ControlledG09Request,
        g07_evidence: ProvisioningEvidence,
    ) -> "_ControlledG09Controller":
        if cls is not _ControlledG09Controller:
            raise ControlledG09Error("controlled G09 controller subclasses are not admitted")
        return cls(
            fixture_root=fixture_root,
            request=request,
            g07_evidence=g07_evidence,
            _capability=_CONTROLLED_G09_CAPABILITY,
        )

    @staticmethod
    def _validate_fixture_root(root: Path) -> Path:
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise ControlledG09Error(
                "controlled G09 fixture root must be an exact canonical absolute Path"
            )
        try:
            canonical = root.resolve(strict=True)
            metadata = root.lstat()
            temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        except OSError as error:
            raise ControlledG09Error("controlled G09 fixture root was unavailable") from error
        if (
            canonical != root
            or root.parent != temporary_root
            or not root.name.startswith("tmp")
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ControlledG09Error(
                "controlled G09 accepts only an exact disposable temporary fixture root"
            )
        return root

    @staticmethod
    def _validate_g07_evidence(
        evidence: ProvisioningEvidence,
        authority: tuple[str, str, str],
    ) -> ProvisioningEvidence:
        if type(evidence) is not ProvisioningEvidence:
            raise ControlledG09Error("controlled G09 requires exact G07 evidence")
        try:
            snapshot = deepcopy(evidence)
        except Exception as error:
            raise ControlledG09Error("controlled G09 could not snapshot G07 evidence") from error
        expected_gates = [
            (
                Gate.MANIFEST,
                "passed",
                "controlled G06 append completion was preserved and descriptor-bound",
            ),
            (
                Gate.BACKUP,
                "passed",
                "synthetic backup root, sidecar, synchronization, freshness, modes, "
                "filesystem device, and exact descriptor-bound bytes were confirmed",
            ),
        ]
        if (
            snapshot.state != "partial"
            or snapshot.failed_gate is not None
            or snapshot.simulation is not True
            or snapshot.actual_database != authority[2]
            or snapshot.mutation_attempts != [_G06_ATTEMPT, _G07_INIT, _G07_SYNC]
            or snapshot.mutations_completed != [_G06_ATTEMPT, _G07_INIT, _G07_SYNC]
            or [(i.gate, i.status, i.detail) for i in snapshot.gates] != expected_gates
        ):
            raise ControlledG09Error(
                "controlled G09 requires completed descriptor-bound controlled G07 evidence"
            )
        return snapshot

    def _validate_persisted_g07_predecessor(self) -> None:
        try:
            manifest = _parse_manifest(self._manifest_expected_raw)
            validate_records(manifest["repositories"])
            g07 = json.loads(self._g07_expected_raw.decode("utf-8"))
            metadata = json.loads(self._metadata.decode("utf-8"))
            sidecar = json.loads(self._backup_sidecar_expected.decode("utf-8"))
            snapshot = json.loads(self._backup_snapshot_expected.decode("utf-8"))
        except (KeyError, ManifestError, TypeError, UnicodeError, json.JSONDecodeError) as error:
            raise ControlledG09Error(
                "controlled G07 predecessor readback was malformed"
            ) from error
        authority = self._request.exact_tuple()
        expected_g07_fingerprint = self._snapshot.request_fingerprint
        if (
            g07.get("request_fingerprint") != expected_g07_fingerprint
            or g07.get("run_id") != self._snapshot.run_id
            or g07.get("actual_database") != authority[2]
            or g07.get("state") != "partial"
            or g07.get("failed_gate") is not None
            or g07.get("simulation") is not True
        ):
            raise ControlledG09Error("controlled G07 predecessor evidence did not match authority")
        if metadata != {
            "dolt_database": authority[2],
            "dolt_mode": "server",
            "dolt_server_port": 3307,
        }:
            raise ControlledG09Error("controlled G09 metadata did not match exact authority")
        if sidecar != {
            "database": authority[2],
            "identity": "controlled-g07-sidecar/v1",
            "root": ".beads/backup",
        }:
            raise ControlledG09Error("controlled G09 backup sidecar did not match authority")
        if snapshot != {
            "database": authority[2],
            "fresh": True,
            "identity": "controlled-g07-snapshot/v1",
            "synchronized": True,
        }:
            raise ControlledG09Error("controlled G09 backup snapshot did not match authority")
        exact_records = [
            r for r in manifest["repositories"]
            if r["path"] == authority[0]
            and r.get("prefix") == authority[1]
            and r["database"] == authority[2]
        ]
        if len(exact_records) != 1:
            raise ControlledG09Error("controlled G06 predecessor enrollment was not the exact record")

    def _base_gates(self) -> list[GateResult]:
        return [
            GateResult(
                Gate.MANIFEST,
                "passed",
                "controlled G06 append completion was preserved and descriptor-bound",
            ),
            GateResult(
                Gate.BACKUP,
                "passed",
                "controlled G07 backup/sidecar/snapshot completion was preserved and descriptor-bound",
            ),
            GateResult(
                Gate.SPECKIT,
                "skipped",
                "live G08 remains blocked by the completed G08-C prerequisite; this "
                "controlled G09 model neither executes nor asserts G08",
            ),
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
            session.pin_directory("backup", self._destination_parts + (".beads", "backup"))
            session.pin_directory("controlled-evidence", ("evidence",))
            session.pin_regular("fixture-root:manifest.json", "fixture-root", "manifest.json")
            session.pin_regular("beads:metadata.json", "beads", "metadata.json")
            session.pin_regular("beads:dolt-backup.json", "beads", "dolt-backup.json")
            session.pin_regular("backup:snapshot.json", "backup", "snapshot.json")
            session.pin_regular(
                f"controlled-evidence:{self._g07_evidence_name}",
                "controlled-evidence",
                self._g07_evidence_name,
            )
        except (ControlledFixtureError, OSError) as error:
            raise ControlledG09Error(
                "controlled G09 descriptor session could not be opened"
            ) from error
        return session

    def _assert_predecessor_bindings(self) -> None:
        if self._session is None:
            raise ControlledG09Error("controlled G09 descriptor session was unavailable")
        self._session.assert_bindings()
        manifest_raw, _ = self._session.read_pinned_regular(
            "fixture-root", "manifest.json", label="controlled manifest"
        )
        g07_raw, _ = self._session.read_pinned_regular(
            "controlled-evidence", self._g07_evidence_name, label="controlled G07 evidence"
        )
        if manifest_raw != self._manifest_expected_raw or g07_raw != self._g07_expected_raw:
            raise ControlledG09Error("controlled G07 predecessor binding changed")
        self._validate_persisted_g07_predecessor()

    def _persist(self, *, preserve_on_binding_failure: bool) -> None:
        if self._session is None:
            raise ControlledG09Error("controlled G09 evidence session was unavailable")
        try:
            self._session.persist(
                self._evidence,
                preserve_on_binding_failure=preserve_on_binding_failure,
            )
        except (ControlledFixtureError, OSError, ValueError) as error:
            raise ControlledG09Error(
                "controlled G09 descriptor-bound evidence persistence failed"
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

    def _initialize_bootstrap(self) -> None:
        if self._session is None:
            raise ControlledG09Error("controlled G09 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        ledger = _bootstrap_ledger(self._request.database, self._request.markers)
        self._session.create_regular("beads", "bootstrap.json", ledger, mode=0o600)
        self._session.pin_regular("beads:bootstrap.json", "beads", "bootstrap.json")
        self._assert_predecessor_bindings()

    def _assert_terminal_state(self) -> None:
        if self._session is None:
            raise ControlledG09Error("controlled G09 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        beads_fd = self._session.directory_fd("beads")
        try:
            beads_stat = os.fstat(beads_fd)
            expected = _bootstrap_ledger(self._request.database, self._request.markers)
            raw, _ = self._session.read_pinned_regular(
                "beads", "bootstrap.json", label="bootstrap ledger"
            )
            if raw != expected:
                raise ControlledG09Error("controlled bootstrap ledger readback was not exact")
            entries = set(self._session.list_directory("beads"))
            if "bootstrap.json" not in entries:
                raise ControlledG09Error("controlled bootstrap ledger was not recorded")
            self._assert_predecessor_bindings()
            self._session.assert_bindings()
            self._session.read_pinned_regular(
                "beads", "bootstrap.json", label="bootstrap ledger"
            )
            if os.fstat(beads_fd).st_dev != beads_stat.st_dev:
                raise ControlledG09Error("controlled beads descriptor changed device")
        finally:
            os.close(beads_fd)

    def _after_initialize_for_controlled_test(self) -> None:
        """Failure-injection seam for controlled leaf replacement tests."""

    def _before_terminal_confirmation_for_controlled_test(self) -> None:
        """Failure-injection seam immediately before final descriptor checks."""

    def _finish_failure(self, error: BaseException, *, preserve_g07: bool) -> None:
        self._evidence.state = "partial"
        self._evidence.failed_gate = Gate.BOOTSTRAP.value
        predecessor = (
            self._base_gates()
            if preserve_g07
            else [
                GateResult(
                    Gate.BACKUP,
                    "failed",
                    "controlled G07 predecessor was not proven; its completion was not claimed",
                )
            ]
        )
        self._evidence.gates = [
            *predecessor,
            GateResult(Gate.BOOTSTRAP, "failed", _safe_detail(error)),
        ]
        self._evidence.resume_requirement = "controlled-inspection-required"
        self._evidence.next_action = _FAILURE_ACTION
        try:
            self._persist(preserve_on_binding_failure=True)
        except ControlledG09Error:
            pass

    def _close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def run(self) -> ProvisioningEvidence:
        """Perform one synthetic G09 fixture transition; every outcome consumes it."""
        if self._state != "new":
            raise ControlledG09Error("controlled G09 controller is single-use")
        self._state = "running"
        g07_proven = False
        try:
            session = self._open_session()
            self._assert_predecessor_bindings()
            g07_proven = True
            self._persist(preserve_on_binding_failure=False)

            self._record_attempt(_G09_ATTEMPT)
            self._assert_predecessor_bindings()
            self._initialize_bootstrap()
            self._record_completion(_G09_ATTEMPT)
            self._after_initialize_for_controlled_test()
            self._assert_predecessor_bindings()
            session.assert_bindings()

            self._before_terminal_confirmation_for_controlled_test()
            self._assert_terminal_state()
            self._evidence.state = "partial"
            self._evidence.failed_gate = None
            self._evidence.gates = [
                *self._base_gates(),
                GateResult(
                    Gate.BOOTSTRAP,
                    "passed",
                    f"one exact bootstrap ledger with {len(self._request.markers)} unique "
                    f"duplicate-searched marker(s) and database "
                    f"{self._request.database} read back",
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
            self._finish_failure(error, preserve_g07=g07_proven)
            self._close()
            if isinstance(error, ControlledG09Error):
                raise
            if isinstance(error, ControlledFixtureError):
                raise ControlledG09Error("controlled G09 descriptor binding failed") from error
            raise ControlledG09Error("controlled G09 failed closed") from error


def _controlled_g09_for_test(
    *,
    fixture_root: Path,
    request: ControlledG09Request,
    g07_evidence: ProvisioningEvidence,
) -> _ControlledG09Controller:
    """Sole module factory for the private controlled-test-only controller."""
    return _ControlledG09Controller._for_controlled_test(
        fixture_root=fixture_root,
        request=request,
        g07_evidence=g07_evidence,
    )


def _validate_g09_evidence(
    evidence: ProvisioningEvidence,
    authority: tuple[str, str, str],
) -> ProvisioningEvidence:
    """Validate a completed controlled-G09 predecessor without trusting its detail text.

    Structural invariants only: exact gate status sequence (including the
    mandatory ``skipped`` live-G08 fence), state, sim flag, mutation ordering,
    authority database, and repository identity. The bootstrap detail is a
    f-string and is deliberately not matched byte-exactly.
    """
    if type(evidence) is not ProvisioningEvidence:
        raise ControlledG09Error("controlled G09 requires exact G09 evidence")
    try:
        snapshot = deepcopy(evidence)
    except Exception as error:
        raise ControlledG09Error("controlled G09 could not snapshot evidence") from error
    expected_statuses = [
        (Gate.MANIFEST, "passed"),
        (Gate.BACKUP, "passed"),
        (Gate.SPECKIT, "skipped"),
        (Gate.BOOTSTRAP, "passed"),
    ]
    if (
        snapshot.state != "partial"
        or snapshot.failed_gate is not None
        or snapshot.simulation is not True
        or snapshot.actual_database != authority[2]
        or snapshot.repository_identity != "controlled-fixture/g09"
        or snapshot.mutation_attempts != [_G06_ATTEMPT, _G07_INIT, _G07_SYNC, _G09_ATTEMPT]
        or snapshot.mutations_completed != [_G06_ATTEMPT, _G07_INIT, _G07_SYNC, _G09_ATTEMPT]
        or [(i.gate, i.status) for i in snapshot.gates] != expected_statuses
    ):
        raise ControlledG09Error(
            "controlled G09 requires completed descriptor-bound controlled G09 evidence"
        )
    for item in snapshot.gates:
        if item.gate is Gate.SPECKIT and item.status == "passed":
            raise ControlledG09Error(
                "controlled G09 evidence must never claim live G08 passed"
            )
    return snapshot
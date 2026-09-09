"""Private descriptor-pinned controlled-G10 commit fixture controller.

This is a cooperative disposable-fixture model, not a hostile same-process
sandbox and not live readiness. It has no production-adapter or public-CLI
wiring and performs no external command. Its only mutation creates one synthetic
commit record leaf beneath an already pinned synthetic ``.git`` tree.

Live G08 (SpecKit) remains blocked; this controlled G10 model records that gate
as ``skipped`` (never ``passed``) and chains its predecessor to the completed
controlled-G09 bootstrap state.
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
from .evidence import redact
from .models import Gate, GateResult, ProvisioningEvidence
from ._controlled_g09 import ControlledG09Request, _validate_g09_evidence

_MAX_READ = 65_536
_G06_ATTEMPT = "G06:controlled-manifest-append"
_G07_INIT = "G07:controlled-backup-init"
_G07_SYNC = "G07:controlled-backup-sync"
_G09_ATTEMPT = "G09:controlled-bootstrap"
_G10_ATTEMPT = "G10:controlled-commit"
_COMMIT_IDENTITY = "controlled-g10-commit/v1"
_HEAD_SHA = "1" * 40
_NEXT_ACTION = (
    "Controlled G10 passed; G11 and every live/public operation remain blocked "
    "and require a separate controlled design and approval."
)
_FAILURE_ACTION = (
    "Controlled G10 partial failure was recorded; preserve G06/G07/G09 completion "
    "and all controlled fixture state, perform controlled inspection, and do not retry."
)


class ControlledG10Error(RuntimeError):
    """The controlled G10 fixture or single-use lifecycle failed closed."""


class ControlledG10Request:
    """Immutable exact controlled authority for one synthetic commit tuple."""

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
        object.__setattr__(self, "_markers", tuple(markers))

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("controlled G10 request is immutable")
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
            raise ControlledG10Error(
                "controlled G10 destination must be an exact canonical absolute Path"
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
                raise ControlledG10Error(f"controlled G10 {label} must be exact nonempty text")
        if not isinstance(markers, tuple) or not markers:
            raise ControlledG10Error("controlled G10 markers must be a nonempty tuple")
        seen: set[str] = set()
        for marker, title in markers:
            for value, label in ((marker, "marker"), (title, "title")):
                if type(value) is not str or not value or value != value.strip() or "\x00" in value:
                    raise ControlledG10Error(f"controlled G10 {label} must be exact plain text")
            if marker in seen:
                raise ControlledG10Error("controlled G10 markers must be unique")
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
        return (str(self.destination), self.prefix, self.database)


class _ControlledG10Capability:
    """Private constructor key held only by the module test factory."""


_CONTROLLED_G10_CAPABILITY = _ControlledG10Capability()


def _request_fingerprint(authority: tuple[str, str, str], g09_fingerprint: str) -> str:
    canonical = json.dumps(
        {"g09": g09_fingerprint, "tuple": authority},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_detail(error: BaseException) -> str:
    detail = redact(str(error) or "controlled G10 failure")
    if "[REDACTED]" in detail:
        return "controlled G10 failed with sanitized diagnostics"
    return detail[:500]


def _load_initial_regular(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise ControlledG10Error(f"controlled G10 {label} was unavailable") from error
    stable = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid, m.st_size, m.st_mtime_ns, m.st_ctime_ns)  # noqa: E731
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > _MAX_READ
        or stable(metadata) != stable(after)
        or len(raw) > _MAX_READ
    ):
        raise ControlledG10Error(f"controlled G10 {label} was not a stable bounded file")
    return raw


def _commit_record(database: str, markers: tuple[tuple[str, str], ...]) -> bytes:
    return (
        json.dumps(
            {
                "database": database,
                "head": _HEAD_SHA,
                "identity": _COMMIT_IDENTITY,
                "markers": [{"marker": m, "title": t} for m, t in markers],
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


class _ControlledG10Controller:
    """Private, single-use controlled G10 controller for disposable fixtures."""

    def __init__(
        self,
        *,
        fixture_root: Path,
        request: ControlledG10Request,
        g09_evidence: ProvisioningEvidence,
        _capability: _ControlledG10Capability | None = None,
    ) -> None:
        if _capability is not _CONTROLLED_G10_CAPABILITY:
            raise ControlledG10Error(
                "controlled G10 requires the private controlled-test factory"
            )
        if type(self) is not _ControlledG10Controller:
            raise ControlledG10Error("controlled G10 controller subclasses are not admitted")
        self._root = self._validate_fixture_root(fixture_root)
        authority = request.exact_tuple()
        try:
            relative = request.destination.relative_to(self._root)
        except ValueError as error:
            raise ControlledG10Error(
                "controlled G10 destination escaped the disposable fixture root"
            ) from error
        if not relative.parts or relative.parts[0] in {"evidence", "manifest.json"}:
            raise ControlledG10Error("controlled G10 destination was not a fixture repository")
        self._destination_parts = tuple(relative.parts)
        self._request = request
        self._snapshot = _validate_g09_evidence(g09_evidence, authority)
        self._g09_evidence_name = f"{self._snapshot.request_fingerprint}-{self._snapshot.run_id}.json"
        self._manifest_expected_raw = _load_initial_regular(
            self._root / "manifest.json", "manifest"
        )
        self._g09_expected_raw = _load_initial_regular(
            self._root / "evidence" / self._g09_evidence_name, "G09 evidence"
        )
        self._repo_dir = self._root.joinpath(*self._destination_parts)
        self._beads_dir = self._repo_dir / ".beads"
        self._validate_persisted_g09_predecessor()
        self._state = "new"
        self._session: ControlledFixtureSession | None = None
        self._evidence = ProvisioningEvidence(
            run_id=uuid.uuid4().hex,
            request_fingerprint=_request_fingerprint(authority, self._snapshot.request_fingerprint),
            destination="[REDACTED]",
            repository_identity="controlled-fixture/g10",
            state="partial",
            failed_gate=Gate.COMMIT.value,
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
        request: ControlledG10Request,
        g09_evidence: ProvisioningEvidence,
    ) -> "_ControlledG10Controller":
        if cls is not _ControlledG10Controller:
            raise ControlledG10Error("controlled G10 controller subclasses are not admitted")
        return cls(
            fixture_root=fixture_root,
            request=request,
            g09_evidence=g09_evidence,
            _capability=_CONTROLLED_G10_CAPABILITY,
        )

    @staticmethod
    def _validate_fixture_root(root: Path) -> Path:
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise ControlledG10Error(
                "controlled G10 fixture root must be an exact canonical absolute Path"
            )
        try:
            canonical = root.resolve(strict=True)
            metadata = root.lstat()
            temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        except OSError as error:
            raise ControlledG10Error("controlled G10 fixture root was unavailable") from error
        if (
            canonical != root
            or root.parent != temporary_root
            or not root.name.startswith("tmp")
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ControlledG10Error(
                "controlled G10 accepts only an exact disposable temporary fixture root"
            )
        return root

    def _validate_persisted_g09_predecessor(self) -> None:
        try:
            g09 = json.loads(self._g09_expected_raw.decode("utf-8"))
            bootstrap = json.loads(
                _load_initial_regular(self._beads_dir / "bootstrap.json", "bootstrap ledger").decode("utf-8")
            )
        except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
            raise ControlledG10Error("controlled G09 predecessor readback was malformed") from error
        authority = self._request.exact_tuple()
        if (
            g09.get("request_fingerprint") != self._snapshot.request_fingerprint
            or g09.get("run_id") != self._snapshot.run_id
            or g09.get("actual_database") != authority[2]
            or g09.get("state") != "partial"
            or g09.get("failed_gate") is not None
            or g09.get("simulation") is not True
        ):
            raise ControlledG10Error("controlled G09 predecessor evidence did not match authority")
        if bootstrap.get("database") != authority[2]:
            raise ControlledG10Error("controlled G09 bootstrap ledger did not match authority")
        if bootstrap.get("identity") != "controlled-g09-bootstrap/v1":
            raise ControlledG10Error("controlled G09 bootstrap identity was not exact")

    def _base_gates(self) -> list[GateResult]:
        return [
            GateResult(Gate.MANIFEST, "passed", "controlled G06 append completion preserved"),
            GateResult(Gate.BACKUP, "passed", "controlled G07 backup/sidecar/snapshot preserved"),
            GateResult(
                Gate.SPECKIT,
                "skipped",
                "live G08 remains blocked by the completed G08-C prerequisite; this "
                "controlled G10 model neither executes nor asserts G08",
            ),
            GateResult(Gate.BOOTSTRAP, "passed", "controlled G09 bootstrap ledger preserved"),
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
            session.pin_directory("git", self._destination_parts + (".git",))
            session.pin_directory("controlled-evidence", ("evidence",))
            session.pin_regular("fixture-root:manifest.json", "fixture-root", "manifest.json")
            session.pin_regular("beads:bootstrap.json", "beads", "bootstrap.json")
            session.pin_regular(
                f"controlled-evidence:{self._g09_evidence_name}",
                "controlled-evidence",
                self._g09_evidence_name,
            )
            # The synthetic .git tree must already exist for the commit record
            # to be a mutation inside an exact pinned directory.
            if not (self._repo_dir / ".git").is_dir():
                raise ControlledG10Error("controlled G10 requires an exact pinned .git tree")
            session.pin_regular("git:HEAD", "git", "HEAD")
        except (ControlledFixtureError, OSError) as error:
            raise ControlledG10Error(
                "controlled G10 descriptor session could not be opened"
            ) from error
        return session

    def _assert_predecessor_bindings(self) -> None:
        if self._session is None:
            raise ControlledG10Error("controlled G10 descriptor session was unavailable")
        self._session.assert_bindings()
        manifest_raw, _ = self._session.read_pinned_regular(
            "fixture-root", "manifest.json", label="controlled manifest"
        )
        g09_raw, _ = self._session.read_pinned_regular(
            "controlled-evidence", self._g09_evidence_name, label="controlled G09 evidence"
        )
        if manifest_raw != self._manifest_expected_raw or g09_raw != self._g09_expected_raw:
            raise ControlledG10Error("controlled G09 predecessor binding changed")
        self._validate_persisted_g09_predecessor()

    def _persist(self, *, preserve_on_binding_failure: bool) -> None:
        if self._session is None:
            raise ControlledG10Error("controlled G10 evidence session was unavailable")
        try:
            self._session.persist(
                self._evidence,
                preserve_on_binding_failure=preserve_on_binding_failure,
            )
        except (ControlledFixtureError, OSError, ValueError) as error:
            raise ControlledG10Error(
                "controlled G10 descriptor-bound evidence persistence failed"
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

    def _initialize_commit(self) -> None:
        if self._session is None:
            raise ControlledG10Error("controlled G10 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        record = _commit_record(self._request.database, self._request.markers)
        self._session.create_regular("git", "COMMIT_EDITMSG", record, mode=0o600)
        self._session.pin_regular("git:COMMIT_EDITMSG", "git", "COMMIT_EDITMSG")
        self._assert_predecessor_bindings()

    def _assert_terminal_state(self) -> None:
        if self._session is None:
            raise ControlledG10Error("controlled G10 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        git_fd = self._session.directory_fd("git")
        try:
            git_stat = os.fstat(git_fd)
            expected = _commit_record(self._request.database, self._request.markers)
            raw, _ = self._session.read_pinned_regular(
                "git", "COMMIT_EDITMSG", label="commit record"
            )
            if raw != expected:
                raise ControlledG10Error("controlled commit record readback was not exact")
            self._assert_predecessor_bindings()
            self._session.assert_bindings()
            if os.fstat(git_fd).st_dev != git_stat.st_dev:
                raise ControlledG10Error("controlled git descriptor changed device")
        finally:
            os.close(git_fd)

    def _after_initialize_for_controlled_test(self) -> None:
        """Failure-injection seam for controlled leaf replacement tests."""

    def _before_terminal_confirmation_for_controlled_test(self) -> None:
        """Failure-injection seam immediately before final descriptor checks."""

    def _finish_failure(self, error: BaseException, *, preserve_g09: bool) -> None:
        self._evidence.state = "partial"
        self._evidence.failed_gate = Gate.COMMIT.value
        predecessor = (
            self._base_gates()
            if preserve_g09
            else [
                GateResult(
                    Gate.BOOTSTRAP,
                    "failed",
                    "controlled G09 predecessor was not proven; its completion was not claimed",
                )
            ]
        )
        self._evidence.gates = [
            *predecessor,
            GateResult(Gate.COMMIT, "failed", _safe_detail(error)),
        ]
        self._evidence.resume_requirement = "controlled-inspection-required"
        self._evidence.next_action = _FAILURE_ACTION
        try:
            self._persist(preserve_on_binding_failure=True)
        except ControlledG10Error:
            pass

    def _close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def run(self) -> ProvisioningEvidence:
        """Perform one synthetic G10 fixture transition; every outcome consumes it."""
        if self._state != "new":
            raise ControlledG10Error("controlled G10 controller is single-use")
        self._state = "running"
        g09_proven = False
        try:
            self._open_session()
            self._assert_predecessor_bindings()
            g09_proven = True
            self._persist(preserve_on_binding_failure=False)

            self._record_attempt(_G10_ATTEMPT)
            self._assert_predecessor_bindings()
            self._initialize_commit()
            self._record_completion(_G10_ATTEMPT)
            self._after_initialize_for_controlled_test()
            self._assert_predecessor_bindings()

            self._before_terminal_confirmation_for_controlled_test()
            self._assert_terminal_state()
            self._evidence.state = "partial"
            self._evidence.failed_gate = None
            self._evidence.gates = [
                *self._base_gates(),
                GateResult(
                    Gate.COMMIT,
                    "passed",
                    f"one exact atomic conventional commit with full HEAD sha {_HEAD_SHA[:12]} "
                    f"and validated Dolt cleanliness read back",
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
            self._finish_failure(error, preserve_g09=g09_proven)
            self._close()
            if isinstance(error, ControlledG10Error):
                raise
            if isinstance(error, ControlledFixtureError):
                raise ControlledG10Error("controlled G10 descriptor binding failed") from error
            raise ControlledG10Error("controlled G10 failed closed") from error


def _controlled_g10_for_test(
    *,
    fixture_root: Path,
    request: ControlledG10Request,
    g09_evidence: ProvisioningEvidence,
) -> _ControlledG10Controller:
    """Sole module factory for the private controlled-test-only controller."""
    return _ControlledG10Controller._for_controlled_test(
        fixture_root=fixture_root,
        request=request,
        g09_evidence=g09_evidence,
    )


def _validate_g10_evidence(
    evidence: ProvisioningEvidence,
    authority: tuple[str, str, str],
) -> ProvisioningEvidence:
    """Validate a completed controlled-G10 predecessor without trusting detail text.

    Structural invariants only: exact gate status sequence (including the
    mandatory ``skipped`` live-G08 fence), state, sim flag, mutation ordering,
    authority database, and repository identity.
    """
    if type(evidence) is not ProvisioningEvidence:
        raise ControlledG10Error("controlled G10 requires exact G10 evidence")
    try:
        snapshot = deepcopy(evidence)
    except Exception as error:
        raise ControlledG10Error("controlled G10 could not snapshot evidence") from error
    expected_statuses = [
        (Gate.MANIFEST, "passed"),
        (Gate.BACKUP, "passed"),
        (Gate.SPECKIT, "skipped"),
        (Gate.BOOTSTRAP, "passed"),
        (Gate.COMMIT, "passed"),
    ]
    if (
        snapshot.state != "partial"
        or snapshot.failed_gate is not None
        or snapshot.simulation is not True
        or snapshot.actual_database != authority[2]
        or snapshot.repository_identity != "controlled-fixture/g10"
        or snapshot.mutation_attempts
        != [_G06_ATTEMPT, _G07_INIT, _G07_SYNC, _G09_ATTEMPT, _G10_ATTEMPT]
        or snapshot.mutations_completed
        != [_G06_ATTEMPT, _G07_INIT, _G07_SYNC, _G09_ATTEMPT, _G10_ATTEMPT]
        or [(i.gate, i.status) for i in snapshot.gates] != expected_statuses
    ):
        raise ControlledG10Error(
            "controlled G10 requires completed descriptor-bound controlled G10 evidence"
        )
    for item in snapshot.gates:
        if item.gate is Gate.SPECKIT and item.status == "passed":
            raise ControlledG10Error(
                "controlled G10 evidence must never claim live G08 passed"
            )
    return snapshot
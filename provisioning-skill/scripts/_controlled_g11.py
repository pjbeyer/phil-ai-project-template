"""Private descriptor-pinned controlled-G11 push fixture controller.

This is a cooperative disposable-fixture model, not a hostile same-process
sandbox and not live readiness. It has no production-adapter or public-CLI
wiring and performs no external command. Its only mutations create two synthetic
synchronization leaves — an individual Git head equality and an individual Dolt
push completion — that remain independent so neither one alone proves completion.

Live G08 (SpecKit) remains blocked; this controlled G11 model records that gate
as ``skipped`` (never ``passed``) and chains its predecessor to the completed
controlled-G10 commit state.
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
from ._controlled_g10 import _validate_g10_evidence

_MAX_READ = 65_536
_G06_ATTEMPT = "G06:controlled-manifest-append"
_G07_INIT = "G07:controlled-backup-init"
_G07_SYNC = "G07:controlled-backup-sync"
_G09_ATTEMPT = "G09:controlled-bootstrap"
_G10_ATTEMPT = "G10:controlled-commit"
_G11_GIT = "G11:controlled-git-push"
_G11_DOLT = "G11:controlled-dolt-push"
_GIT_IDENTITY = "controlled-g11-git/v1"
_DOLT_IDENTITY = "controlled-g11-dolt/v1"
_HEAD_SHA = "1" * 40
_NEXT_ACTION = (
    "Controlled G11 passed; every live/public operation remains blocked and "
    "requires separate approval."
)
_FAILURE_ACTION = (
    "Controlled G11 partial failure was recorded; preserve G06/G07/G09/G10 "
    "completion and all controlled fixture state, perform controlled inspection, "
    "and do not retry."
)


class ControlledG11Error(RuntimeError):
    """The controlled G11 fixture or single-use lifecycle failed closed."""


class ControlledG11Request:
    """Immutable exact controlled authority for one synthetic push tuple."""

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
            raise AttributeError("controlled G11 request is immutable")
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
            raise ControlledG11Error(
                "controlled G11 destination must be an exact canonical absolute Path"
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
                raise ControlledG11Error(f"controlled G11 {label} must be exact nonempty text")
        if not isinstance(markers, tuple) or not markers:
            raise ControlledG11Error("controlled G11 markers must be a nonempty tuple")
        seen: set[str] = set()
        for marker, title in markers:
            for value, label in ((marker, "marker"), (title, "title")):
                if type(value) is not str or not value or value != value.strip() or "\x00" in value:
                    raise ControlledG11Error(f"controlled G11 {label} must be exact plain text")
            if marker in seen:
                raise ControlledG11Error("controlled G11 markers must be unique")
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


class _ControlledG11Capability:
    """Private constructor key held only by the module test factory."""


_CONTROLLED_G11_CAPABILITY = _ControlledG11Capability()


def _request_fingerprint(authority: tuple[str, str, str], g10_fingerprint: str) -> str:
    canonical = json.dumps(
        {"g10": g10_fingerprint, "tuple": authority},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_detail(error: BaseException) -> str:
    detail = redact(str(error) or "controlled G11 failure")
    if "[REDACTED]" in detail:
        return "controlled G11 failed with sanitized diagnostics"
    return detail[:500]


def _load_initial_regular(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise ControlledG11Error(f"controlled G11 {label} was unavailable") from error
    stable = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_size, m.st_mtime_ns, m.st_ctime_ns)  # noqa: E731
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > _MAX_READ
        or stable(metadata) != stable(after)
        or len(raw) > _MAX_READ
    ):
        raise ControlledG11Error(f"controlled G11 {label} was not a stable bounded file")
    return raw


def _git_leaf(head: str) -> bytes:
    return (
        json.dumps(
            {"head": head, "identity": _GIT_IDENTITY, "upstream": head},
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _dolt_leaf(database: str) -> bytes:
    return (
        json.dumps(
            {"database": database, "identity": _DOLT_IDENTITY, "remote": "origin"},
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


class _ControlledG11Controller:
    """Private, single-use controlled G11 controller for disposable fixtures."""

    def __init__(
        self,
        *,
        fixture_root: Path,
        request: ControlledG11Request,
        g10_evidence: ProvisioningEvidence,
        _capability: _ControlledG11Capability | None = None,
    ) -> None:
        if _capability is not _CONTROLLED_G11_CAPABILITY:
            raise ControlledG11Error(
                "controlled G11 requires the private controlled-test factory"
            )
        if type(self) is not _ControlledG11Controller:
            raise ControlledG11Error("controlled G11 controller subclasses are not admitted")
        self._root = self._validate_fixture_root(fixture_root)
        authority = request.exact_tuple()
        try:
            relative = request.destination.relative_to(self._root)
        except ValueError as error:
            raise ControlledG11Error(
                "controlled G11 destination escaped the disposable fixture root"
            ) from error
        if not relative.parts or relative.parts[0] in {"evidence", "manifest.json"}:
            raise ControlledG11Error("controlled G11 destination was not a fixture repository")
        self._destination_parts = tuple(relative.parts)
        self._request = request
        self._snapshot = _validate_g10_evidence(g10_evidence, authority)
        self._g10_evidence_name = f"{self._snapshot.request_fingerprint}-{self._snapshot.run_id}.json"
        self._manifest_expected_raw = _load_initial_regular(
            self._root / "manifest.json", "manifest"
        )
        self._g10_expected_raw = _load_initial_regular(
            self._root / "evidence" / self._g10_evidence_name, "G10 evidence"
        )
        self._repo_dir = self._root.joinpath(*self._destination_parts)
        self._git_dir = self._repo_dir / ".git"
        self._validate_persisted_g10_predecessor()
        self._state = "new"
        self._session: ControlledFixtureSession | None = None
        self._evidence = ProvisioningEvidence(
            run_id=uuid.uuid4().hex,
            request_fingerprint=_request_fingerprint(authority, self._snapshot.request_fingerprint),
            destination="[REDACTED]",
            repository_identity="controlled-fixture/g11",
            state="partial",
            failed_gate=Gate.PUSH.value,
            gates=self._base_gates(),
            mutation_attempts=list(self._snapshot.mutation_attempts),
            mutations_completed=list(self._snapshot.mutations_completed),
            actual_database=request.database,
            git_sync="not-attempted",
            dolt_sync="not-attempted",
            resume_requirement="controlled-inspection-required",
            next_action=_FAILURE_ACTION,
            simulation=True,
        )

    @classmethod
    def _for_controlled_test(
        cls,
        *,
        fixture_root: Path,
        request: ControlledG11Request,
        g10_evidence: ProvisioningEvidence,
    ) -> "_ControlledG11Controller":
        if cls is not _ControlledG11Controller:
            raise ControlledG11Error("controlled G11 controller subclasses are not admitted")
        return cls(
            fixture_root=fixture_root,
            request=request,
            g10_evidence=g10_evidence,
            _capability=_CONTROLLED_G11_CAPABILITY,
        )

    @staticmethod
    def _validate_fixture_root(root: Path) -> Path:
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise ControlledG11Error(
                "controlled G11 fixture root must be an exact canonical absolute Path"
            )
        try:
            canonical = root.resolve(strict=True)
            metadata = root.lstat()
            temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        except OSError as error:
            raise ControlledG11Error("controlled G11 fixture root was unavailable") from error
        if (
            canonical != root
            or root.parent != temporary_root
            or not root.name.startswith("tmp")
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ControlledG11Error(
                "controlled G11 accepts only an exact disposable temporary fixture root"
            )
        return root

    def _validate_persisted_g10_predecessor(self) -> None:
        try:
            g10 = json.loads(self._g10_expected_raw.decode("utf-8"))
            commit = json.loads(
                _load_initial_regular(self._git_dir / "COMMIT_EDITMSG", "commit record").decode("utf-8")
            )
        except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
            raise ControlledG11Error("controlled G10 predecessor readback was malformed") from error
        authority = self._request.exact_tuple()
        if (
            g10.get("request_fingerprint") != self._snapshot.request_fingerprint
            or g10.get("run_id") != self._snapshot.run_id
            or g10.get("actual_database") != authority[2]
            or g10.get("state") != "partial"
            or g10.get("failed_gate") is not None
            or g10.get("simulation") is not True
        ):
            raise ControlledG11Error("controlled G10 predecessor evidence did not match authority")
        if commit.get("head") != _HEAD_SHA or commit.get("identity") != "controlled-g10-commit/v1":
            raise ControlledG11Error("controlled G11 commit record did not match authority")

    def _base_gates(self) -> list[GateResult]:
        return [
            GateResult(Gate.MANIFEST, "passed", "controlled G06 append completion preserved"),
            GateResult(Gate.BACKUP, "passed", "controlled G07 backup completion preserved"),
            GateResult(
                Gate.SPECKIT,
                "skipped",
                "live G08 remains blocked by G08-C; this controlled G11 model neither "
                "executes nor asserts G08",
            ),
            GateResult(Gate.BOOTSTRAP, "passed", "controlled G09 bootstrap ledger preserved"),
            GateResult(Gate.COMMIT, "passed", "controlled G10 commit preserved"),
        ]

    def _open_session(self) -> ControlledFixtureSession:
        session: ControlledFixtureSession | None = None
        try:
            session = ControlledFixtureSession(self._root)
            session.open()
            self._session = session
            session.pin_directory("fixture-root", ())
            session.pin_directory("destination", self._destination_parts)
            session.pin_directory("git", self._destination_parts + (".git",))
            session.pin_directory("beads", self._destination_parts + (".beads",))
            session.pin_directory("dolt", self._destination_parts + (".dolt",))
            session.pin_directory("controlled-evidence", ("evidence",))
            session.pin_regular("fixture-root:manifest.json", "fixture-root", "manifest.json")
            session.pin_regular("git:COMMIT_EDITMSG", "git", "COMMIT_EDITMSG")
            session.pin_regular(
                f"controlled-evidence:{self._g10_evidence_name}",
                "controlled-evidence",
                self._g10_evidence_name,
            )
            dolt = self._repo_dir / ".dolt"
            if not dolt.is_dir():
                dolt.mkdir(mode=0o700)
        except (ControlledFixtureError, OSError) as error:
            raise ControlledG11Error(
                "controlled G11 descriptor session could not be opened"
            ) from error
        return session

    def _assert_predecessor_bindings(self) -> None:
        if self._session is None:
            raise ControlledG11Error("controlled G11 descriptor session was unavailable")
        self._session.assert_bindings()
        manifest_raw, _ = self._session.read_pinned_regular(
            "fixture-root", "manifest.json", label="controlled manifest"
        )
        g10_raw, _ = self._session.read_pinned_regular(
            "controlled-evidence", self._g10_evidence_name, label="controlled G10 evidence"
        )
        if manifest_raw != self._manifest_expected_raw or g10_raw != self._g10_expected_raw:
            raise ControlledG11Error("controlled G10 predecessor binding changed")
        self._validate_persisted_g10_predecessor()

    def _persist(self, *, preserve_on_binding_failure: bool) -> None:
        if self._session is None:
            raise ControlledG11Error("controlled G11 evidence session was unavailable")
        try:
            self._session.persist(
                self._evidence,
                preserve_on_binding_failure=preserve_on_binding_failure,
            )
        except (ControlledFixtureError, OSError, ValueError) as error:
            raise ControlledG11Error(
                "controlled G11 descriptor-bound evidence persistence failed"
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

    def _push_git(self) -> None:
        if self._session is None:
            raise ControlledG11Error("controlled G11 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        self._session.create_regular(
            "git", "upstream.json", _git_leaf(_HEAD_SHA), mode=0o600
        )
        self._session.pin_regular("git:upstream.json", "git", "upstream.json")
        self._evidence.git_sync = "succeeded"
        self._assert_predecessor_bindings()

    def _push_dolt(self) -> None:
        if self._session is None:
            raise ControlledG11Error("controlled G11 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        self._session.create_regular(
            "dolt", "push.json", _dolt_leaf(self._request.database), mode=0o600
        )
        self._session.pin_regular("dolt:push.json", "dolt", "push.json")
        self._evidence.dolt_sync = "succeeded"
        self._assert_predecessor_bindings()

    def _assert_terminal_state(self) -> None:
        if self._session is None:
            raise ControlledG11Error("controlled G11 descriptor session was unavailable")
        self._assert_predecessor_bindings()
        git_fd = self._session.directory_fd("git")
        dolt_fd = self._session.directory_fd("dolt")
        try:
            git_stat = os.fstat(git_fd)
            dolt_stat = os.fstat(dolt_fd)
            git_raw, _ = self._session.read_pinned_regular(
                "git", "upstream.json", label="git upstream"
            )
            dolt_raw, _ = self._session.read_pinned_regular(
                "dolt", "push.json", label="dolt push"
            )
            if git_raw != _git_leaf(_HEAD_SHA):
                raise ControlledG11Error("controlled git upstream readback was not exact")
            if dolt_raw != _dolt_leaf(self._request.database):
                raise ControlledG11Error("controlled dolt push readback was not exact")
            self._assert_predecessor_bindings()
            self._session.assert_bindings()
            if os.fstat(git_fd).st_dev != git_stat.st_dev:
                raise ControlledG11Error("controlled git descriptor changed device")
            if os.fstat(dolt_fd).st_dev != dolt_stat.st_dev:
                raise ControlledG11Error("controlled dolt descriptor changed device")
        finally:
            os.close(dolt_fd)
            os.close(git_fd)

    def _after_git_for_controlled_test(self) -> None:
        """Failure-injection seam after git push, before dolt push."""

    def _finish_failure(self, error: BaseException, *, preserve_g10: bool) -> None:
        self._evidence.state = "partial"
        self._evidence.failed_gate = Gate.PUSH.value
        predecessor = (
            self._base_gates()
            if preserve_g10
            else [
                GateResult(
                    Gate.COMMIT,
                    "failed",
                    "controlled G10 predecessor was not proven; its completion was not claimed",
                )
            ]
        )
        self._evidence.gates = [
            *predecessor,
            GateResult(Gate.PUSH, "failed", _safe_detail(error)),
        ]
        self._evidence.resume_requirement = "controlled-inspection-required"
        self._evidence.next_action = _FAILURE_ACTION
        try:
            self._persist(preserve_on_binding_failure=True)
        except ControlledG11Error:
            pass

    def _close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def run(self) -> ProvisioningEvidence:
        """Perform one synthetic G11 fixture transition; every outcome consumes it."""
        if self._state != "new":
            raise ControlledG11Error("controlled G11 controller is single-use")
        self._state = "running"
        g10_proven = False
        try:
            self._open_session()
            self._assert_predecessor_bindings()
            g10_proven = True
            self._persist(preserve_on_binding_failure=False)

            self._record_attempt(_G11_GIT)
            self._assert_predecessor_bindings()
            self._push_git()
            self._record_completion(_G11_GIT)
            self._after_git_for_controlled_test()
            self._assert_predecessor_bindings()

            self._record_attempt(_G11_DOLT)
            self._assert_predecessor_bindings()
            self._push_dolt()
            self._record_completion(_G11_DOLT)
            self._assert_predecessor_bindings()

            self._assert_terminal_state()
            self._evidence.state = "partial"
            self._evidence.failed_gate = None
            self._evidence.gates = [
                *self._base_gates(),
                GateResult(
                    Gate.PUSH,
                    "passed",
                    f"Git HEAD {_HEAD_SHA[:12]} == upstream and Dolt remote 'origin' "
                    f"push completed independently read back",
                ),
            ]
            self._evidence.git_sync = "succeeded"
            self._evidence.dolt_sync = "succeeded"
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
            self._finish_failure(error, preserve_g10=g10_proven)
            self._close()
            if isinstance(error, ControlledG11Error):
                raise
            if isinstance(error, ControlledFixtureError):
                raise ControlledG11Error("controlled G11 descriptor binding failed") from error
            raise ControlledG11Error("controlled G11 failed closed") from error


def _controlled_g11_for_test(
    *,
    fixture_root: Path,
    request: ControlledG11Request,
    g10_evidence: ProvisioningEvidence,
) -> _ControlledG11Controller:
    """Sole module factory for the private controlled-test-only controller."""
    return _ControlledG11Controller._for_controlled_test(
        fixture_root=fixture_root,
        request=request,
        g10_evidence=g10_evidence,
    )
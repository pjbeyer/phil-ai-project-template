#!/usr/bin/env python3
"""Simulation-only project-provisioning state machine.

The public CLI always constructs exact ``FakeAdapter`` and exits nonzero. The
retained ``LiveAdapter`` draft is rejected and fail-closed; there is no built-in
runner or approved live path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol

from .adapters import (
    AdapterError,
    ControlledG01G03Adapter,
    ControlledGateTransport,
    FakeAdapter,
    LiveAdapter,
    ProvisioningAdapter,
    _register_controlled_transport,
)
from .bootstrap_issues import ensure_bootstrap_issues
from .controlled_fixture import ControlledFixtureError, ControlledFixtureSession
from .manifest import OWNING_JOBS
from .evidence import (
    InspectionEvidence,
    InspectionFinding,
    ResumeAuthorization,
    inspection_evidence_id,
    persist,
    redact,
    request_fingerprint,
)
from .models import (
    APPROVED_COMPONENT_NAMES,
    Gate,
    GateResult,
    ImmutableLiveConfiguration,
    ProvisioningEvidence,
    ProvisioningRequest,
    RenderProvenance,
)
from .preflight import (
    PreflightError,
    normalize_inspection_request,
    normalize_request,
    required_tools_available,
)

POST_PREFLIGHT = (
    Gate.CLONE, Gate.RENDER, Gate.BEADS, Gate.BEADS_REMOTE, Gate.MANIFEST,
    Gate.BACKUP, Gate.SPECKIT, Gate.BOOTSTRAP, Gate.COMMIT, Gate.PUSH,
)


class InspectionControlError(RuntimeError):
    """Inspection or exact-gate resume failed closed before mutation."""


class InspectionOperation(Enum):
    """Closed read-only terminal-invariant observation set."""

    REPOSITORY = "inspect-repository"
    RENDER = "inspect-render"
    BEADS = "inspect-beads"
    BEADS_REMOTE = "inspect-beads-remote"
    MANIFEST = "inspect-manifest"
    BACKUP = "inspect-backup"
    SPECKIT = "inspect-speckit"
    BOOTSTRAP = "inspect-bootstrap"
    COMMIT = "inspect-commit"
    SYNC = "inspect-sync"


class _InspectionCapability:
    """Private construction key for the controlled internal control plane."""


class _ResumeCapability:
    """Private one-use-in-process authority issued after exact admission."""


_INSPECTION_CAPABILITY = _InspectionCapability()


@dataclass(frozen=True, slots=True)
class RawInspectionResult:
    """Bounded raw observer output; it cannot assert trusted invariant facts."""

    gate: Gate
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True, slots=True)
class ResumeStart:
    """Proof that the controlled test executor was invoked at one exact gate."""

    started_gate: Gate
    evidence_id: str


class InspectionObserver(Protocol):
    def execute_inspection(self, operation: InspectionOperation) -> RawInspectionResult: ...


class ResumeExecutor(Protocol):
    def execute_gate_for_test(self, gate: Gate, capability: _ResumeCapability) -> None: ...


_TERMINAL_GATES = tuple(Gate)[1:]
_INSPECTION_OPERATION: Mapping[Gate, InspectionOperation] = MappingProxyType(
    {
        Gate.CLONE: InspectionOperation.REPOSITORY,
        Gate.RENDER: InspectionOperation.RENDER,
        Gate.BEADS: InspectionOperation.BEADS,
        Gate.BEADS_REMOTE: InspectionOperation.BEADS_REMOTE,
        Gate.MANIFEST: InspectionOperation.MANIFEST,
        Gate.BACKUP: InspectionOperation.BACKUP,
        Gate.SPECKIT: InspectionOperation.SPECKIT,
        Gate.BOOTSTRAP: InspectionOperation.BOOTSTRAP,
        Gate.COMMIT: InspectionOperation.COMMIT,
        Gate.PUSH: InspectionOperation.SYNC,
    }
)
_EXPECTED_HOOKS = (
    "post-checkout", "post-merge", "pre-commit", "pre-push", "prepare-commit-msg",
)
_MAX_INSPECTION_OUTPUT = 65_536
_EXACT_KEYS: Mapping[Gate, frozenset[str]] = MappingProxyType(
    {
        Gate.CLONE: frozenset(
            {"identity", "origin_url", "destination", "branch", "checkout_exists"}
        ),
        Gate.RENDER: frozenset(
            {"configuration_fingerprint", "template_commit", "render_valid"}
        ),
        Gate.BEADS: frozenset({"mode", "host", "port", "prefix", "database"}),
        Gate.BEADS_REMOTE: frozenset(
            {"remote_name", "remote_url", "integrations", "hooks"}
        ),
        Gate.MANIFEST: frozenset(
            {
                "manifest_identity", "manifest_valid", "path", "prefix", "database",
                "globally_unique", "policy_valid",
            }
        ),
        Gate.BACKUP: frozenset(
            {
                "root_is_exact", "sidecar_valid", "tree_safe", "ownership_valid",
                "modes_valid", "synchronized", "fresh", "coverage_path",
                "coverage_database", "coverage_findings",
            }
        ),
        Gate.SPECKIT: frozenset(
            {"integration", "components", "pins_valid", "excluded_components", "constitution_valid"}
        ),
        Gate.BOOTSTRAP: frozenset(
            {"database", "markers", "duplicate_markers", "readback_valid"}
        ),
        Gate.COMMIT: frozenset(
            {"validation_passed", "hygiene_passed", "commit_valid", "dolt_non_ignored_dirty"}
        ),
        Gate.PUSH: frozenset({"git_upstream_equal", "dolt_push_complete"}),
    }
)
_GATE_SUMMARIES: Mapping[Gate, str] = MappingProxyType(
    {
        Gate.CLONE: "repository origin, route, branch, and checkout identity read back",
        Gate.RENDER: "render configuration and immutable template revision read back",
        Gate.BEADS: "central Beads mode, prefix, and metadata database read back",
        Gate.BEADS_REMOTE: "Dolt remote, integrations, and managed hooks read back",
        Gate.MANIFEST: "manifest identity, enrollment, uniqueness, and policy read back",
        Gate.BACKUP: "backup containment, tree, ownership, freshness, and coverage read back",
        Gate.SPECKIT: "Hermes integration, exact components, pins, and constitution read back",
        Gate.BOOTSTRAP: "bootstrap marker uniqueness and database identities read back",
        Gate.COMMIT: "terminal validation, hygiene, commit, and Dolt cleanliness read back",
        Gate.PUSH: "Git and Dolt synchronization independently read back",
    }
)


def _reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("inspection observation has duplicate object members")
        result[key] = value
    return result


def _observation_digest(gate: Gate, payload: Mapping[str, Any]) -> str:
    """Bind one safely admitted raw observation without disclosing its values."""
    canonical = json.dumps(
        {"gate": gate.value, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_failure(
    gate: Gate,
    reason: str,
    observation_digest: str | None,
) -> InspectionFinding:
    detail = redact(reason)
    # No raw transport text, path, or assertion value belongs in a finding.
    if "[REDACTED]" in detail:
        detail = "inspection observation contained unsafe material and was rejected"
    return InspectionFinding(gate, "failed", detail[:500], observation_digest)


def _invoke_observer(observer: InspectionObserver, gate: Gate) -> RawInspectionResult:
    """Call one closed read-only operation and normalize observer failures."""
    try:
        raw = observer.execute_inspection(_INSPECTION_OPERATION[gate])
    except Exception as error:
        raise ValueError("inspection observation was unavailable") from error
    return raw


def _parse_observation(
    raw: RawInspectionResult,
    expected_gate: Gate,
    *,
    allowed_private_value: str,
) -> dict[str, Any]:
    if type(raw) is not RawInspectionResult or raw.gate is not expected_gate:
        raise ValueError("inspection observer returned the wrong exact raw result")
    if isinstance(raw.returncode, bool) or type(raw.returncode) is not int:
        raise ValueError("inspection observer returned an invalid status")
    if type(raw.stdout) is not str or type(raw.stderr) is not str:
        raise ValueError("inspection observer returned invalid raw text")
    if len(raw.stdout) > _MAX_INSPECTION_OUTPUT or len(raw.stderr) > _MAX_INSPECTION_OUTPUT:
        raise ValueError("inspection observation exceeded its bounded size")
    if redact(raw.stderr) != raw.stderr:
        raise ValueError("inspection observation contained unsafe material")
    if raw.returncode != 0:
        raise ValueError("inspection observation was unavailable")
    try:
        payload = json.loads(raw.stdout, object_pairs_hook=_reject_duplicate_json_members)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError("inspection observation was malformed") from error
    if type(payload) is not dict or set(payload) != _EXACT_KEYS[expected_gate]:
        raise ValueError("inspection observation had an invalid exact shape")

    def assert_safe(value: object) -> None:
        if type(value) is str:
            if value != allowed_private_value and redact(value) != value:
                raise ValueError("inspection observation contained unsafe material")
        elif type(value) is list:
            for item in value:
                assert_safe(item)
        elif type(value) is dict:
            for key, item in value.items():
                if type(key) is not str or redact(key) != key:
                    raise ValueError("inspection observation contained unsafe material")
                assert_safe(item)

    assert_safe(payload)
    return payload


def _safe_database(value: object) -> str:
    if type(value) is not str or not value or not value.replace("_", "a").isalnum():
        raise ValueError("inspection metadata database identity was invalid")
    if redact(value) != value:
        raise ValueError("inspection metadata database identity was unsafe")
    return value


def _require_exact(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ValueError(f"{label} invariant did not match")


def _validate_gate(
    gate: Gate,
    payload: Mapping[str, Any],
    *,
    request: ProvisioningRequest,
    identity: str,
    destination: Path,
    configuration_fingerprint: str,
    database: str | None,
) -> str | None:
    """Adapter-owned parser/invariant admission; return authoritative database."""
    if gate is Gate.CLONE:
        for value, expected, label in (
            (payload["identity"], identity, "repository identity"),
            (payload["origin_url"], request.origin_url, "origin URL"),
            (payload["destination"], str(destination), "canonical destination"),
            (payload["branch"], "main", "primary branch"),
            (payload["checkout_exists"], True, "checkout presence"),
        ):
            _require_exact(value, expected, label)
    elif gate is Gate.RENDER:
        _require_exact(
            payload["configuration_fingerprint"],
            configuration_fingerprint,
            "configuration fingerprint",
        )
        template_commit = payload["template_commit"]
        if type(template_commit) is not str or len(template_commit) != 40 or any(
            character not in "0123456789abcdef" for character in template_commit
        ):
            raise ValueError("immutable template commit invariant did not match")
        _require_exact(payload["render_valid"], True, "render validation")
    elif gate is Gate.BEADS:
        for value, expected, label in (
            (payload["mode"], "server", "Beads mode"),
            (payload["host"], "127.0.0.1", "Beads host"),
            (payload["port"], 3307, "Beads port"),
            (payload["prefix"], request.beads_prefix, "Beads prefix"),
        ):
            _require_exact(value, expected, label)
        return _safe_database(payload["database"])
    elif gate is Gate.BEADS_REMOTE:
        expected_remote = f"git+https://github.com/{identity}.git"
        for value, expected, label in (
            (payload["remote_name"], "origin", "Dolt remote name"),
            (payload["remote_url"], expected_remote, "Dolt remote URL"),
            (payload["integrations"], ["claude", "codex"], "Beads integrations"),
            (payload["hooks"], list(_EXPECTED_HOOKS), "managed hook set"),
        ):
            _require_exact(value, expected, label)
    elif gate is Gate.MANIFEST:
        if database is None:
            raise ValueError("authoritative metadata database was not established")
        for value, expected, label in (
            (payload["manifest_identity"], "managed-projects-manifest/v1", "manifest identity"),
            (payload["manifest_valid"], True, "manifest validity"),
            (payload["path"], str(destination), "manifest path"),
            (payload["prefix"], request.beads_prefix, "manifest prefix"),
            (payload["database"], database, "manifest database"),
            (payload["globally_unique"], True, "manifest uniqueness"),
            (payload["policy_valid"], True, "manifest policy"),
        ):
            _require_exact(value, expected, label)
    elif gate is Gate.BACKUP:
        if database is None:
            raise ValueError("authoritative metadata database was not established")
        for key in (
            "root_is_exact", "sidecar_valid", "tree_safe", "ownership_valid",
            "modes_valid", "synchronized", "fresh",
        ):
            _require_exact(payload[key], True, f"backup {key}")
        _require_exact(payload["coverage_path"], str(destination), "backup coverage path")
        _require_exact(payload["coverage_database"], database, "backup coverage database")
        _require_exact(payload["coverage_findings"], [], "backup coverage findings")
    elif gate is Gate.SPECKIT:
        for value, expected, label in (
            (payload["integration"], "hermes", "SpecKit integration"),
            (payload["components"], sorted(APPROVED_COMPONENT_NAMES), "SpecKit component set"),
            (payload["pins_valid"], True, "SpecKit pins"),
            (payload["excluded_components"], [], "SpecKit exclusions"),
            (payload["constitution_valid"], True, "SpecKit constitution"),
        ):
            _require_exact(value, expected, label)
    elif gate is Gate.BOOTSTRAP:
        if database is None:
            raise ValueError("authoritative metadata database was not established")
        expected_markers = ["first-speckit-spec", "scope-readme"]
        if request.project_kind == "macos-cli":
            expected_markers.append("macos-cli-real-tests")
        elif request.project_kind == "homebrew-tap":
            expected_markers.extend(
                ["homebrew-actions-secret", "homebrew-first-package", "homebrew-lifecycle-tests"]
            )
        elif request.project_kind == "coding-agent-plugin":
            expected_markers.append("coding-agent-plugin-skeleton")
        for value, expected, label in (
            (payload["database"], database, "bootstrap database"),
            (payload["markers"], sorted(expected_markers), "bootstrap markers"),
            (payload["duplicate_markers"], [], "bootstrap duplicate markers"),
            (payload["readback_valid"], True, "bootstrap readback"),
        ):
            _require_exact(value, expected, label)
    elif gate is Gate.COMMIT:
        for key in ("validation_passed", "hygiene_passed", "commit_valid"):
            _require_exact(payload[key], True, f"terminal {key}")
        _require_exact(payload["dolt_non_ignored_dirty"], [], "Dolt cleanliness")
    elif gate is Gate.PUSH:
        _require_exact(payload["git_upstream_equal"], True, "Git synchronization")
        _require_exact(payload["dolt_push_complete"], True, "Dolt synchronization")
    else:
        raise ValueError("inspection requested a non-terminal gate")
    return database


def _destination_digest(destination: Path) -> str:
    return hashlib.sha256(str(destination).encode("utf-8")).hexdigest()


class InspectionController:
    """Internal inspect/resume control plane, unreachable from the public CLI."""

    def __init__(
        self,
        observer: InspectionObserver,
        *,
        _capability: _InspectionCapability | None = None,
    ) -> None:
        if _capability is not _INSPECTION_CAPABILITY:
            raise InspectionControlError("inspection controller requires the private controlled factory")
        self._observer = observer

    @classmethod
    def _for_controlled_test(cls, observer: InspectionObserver) -> InspectionController:
        """Construct only for disposable controlled tests; public CLI never calls this."""
        if cls is not InspectionController:
            raise InspectionControlError("inspection controller subclasses are not admitted")
        return cls(observer, _capability=_INSPECTION_CAPABILITY)

    @staticmethod
    def _configuration_fingerprint(value: str) -> str:
        if type(value) is not str or len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise InspectionControlError("configuration fingerprint must be an exact SHA-256 digest")
        return value

    def inspect(
        self,
        request: ProvisioningRequest,
        *,
        configuration_fingerprint: str,
        home: Path | None = None,
    ) -> InspectionEvidence:
        configuration_fingerprint = self._configuration_fingerprint(configuration_fingerprint)
        try:
            origin, destination = normalize_inspection_request(request, home)
            fingerprint = request_fingerprint(request, destination)
        except (PreflightError, ValueError) as error:
            raise InspectionControlError("inspection request normalization failed") from error

        findings: list[InspectionFinding] = []
        database: str | None = None
        failed_gate: Gate | None = None
        git_sync = "not-attempted"
        dolt_sync = "not-attempted"
        for gate in _TERMINAL_GATES:
            if failed_gate is not None:
                findings.append(
                    InspectionFinding(
                        gate,
                        "not-reached",
                        "not reached after first failed invariant",
                        None,
                    )
                )
                continue
            observation_digest: str | None = None
            try:
                raw = _invoke_observer(self._observer, gate)
                payload = _parse_observation(
                    raw,
                    gate,
                    allowed_private_value=str(destination),
                )
                observation_digest = _observation_digest(gate, payload)
                if gate is Gate.PUSH:
                    git_sync = "succeeded" if payload["git_upstream_equal"] is True else "failed"
                    dolt_sync = "succeeded" if payload["dolt_push_complete"] is True else "failed"
                database = _validate_gate(
                    gate,
                    payload,
                    request=request,
                    identity=origin.identity,
                    destination=destination,
                    configuration_fingerprint=configuration_fingerprint,
                    database=database,
                )
                findings.append(
                    InspectionFinding(
                        gate,
                        "passed",
                        _GATE_SUMMARIES[gate],
                        observation_digest,
                    )
                )
            except (AttributeError, KeyError, TypeError, ValueError) as error:
                failed_gate = gate
                findings.append(
                    _safe_failure(
                        gate,
                        str(error) or "inspection invariant failed",
                        observation_digest,
                    )
                )

        state = "verified-existing" if failed_gate is None else "blocked-preflight"
        evidence_fields = {
            "configuration_fingerprint": configuration_fingerprint,
            "destination_digest": _destination_digest(destination),
            "dolt_sync": dolt_sync,
            "findings": [
                {
                    "gate": finding.gate.value,
                    "status": finding.status,
                    "detail": finding.detail,
                    "observation_digest": finding.observation_digest,
                }
                for finding in findings
            ],
            "git_sync": git_sync,
            "next_gate": None if failed_gate is None else failed_gate.value,
            "repository_identity_digest": hashlib.sha256(
                origin.identity.encode("utf-8")
            ).hexdigest(),
            "request_fingerprint": fingerprint,
            "state": state,
        }
        return InspectionEvidence(
            evidence_id=inspection_evidence_id(evidence_fields),
            request_fingerprint=fingerprint,
            configuration_fingerprint=configuration_fingerprint,
            repository_identity=origin.identity,
            destination_digest=evidence_fields["destination_digest"],
            state=state,
            next_gate=failed_gate,
            findings=tuple(findings),
            git_sync=git_sync,
            dolt_sync=dolt_sync,
        )

    def resume(
        self,
        request: ProvisioningRequest,
        *,
        inspected: InspectionEvidence,
        authorization: object,
        configuration_fingerprint: str,
        home: Path | None = None,
        executor: ResumeExecutor,
    ) -> ResumeStart:
        """Revalidate predecessors, then invoke only the exact authorized gate.

        The supplied executor is a controlled-test seam.  This controller is not
        connected to ``LiveAdapter`` and is not reachable from ``main``.
        """
        if type(inspected) is not InspectionEvidence:
            raise InspectionControlError("resume requires exact inspection evidence type")
        try:
            inspected.__post_init__()
        except ValueError as error:
            raise InspectionControlError("resume inspection evidence is invalid") from error
        if type(authorization) is not ResumeAuthorization:
            raise InspectionControlError("resume requires exact resume authorization type")
        try:
            authorization.__post_init__()
        except ValueError as error:
            raise InspectionControlError("resume authorization is invalid") from error
        if inspected.state != "blocked-preflight" or inspected.next_gate is None:
            raise InspectionControlError("inspection has no exact resumable gate")
        reached = tuple(
            finding for finding in inspected.findings if finding.status != "not-reached"
        )
        if any(finding.observation_digest is None for finding in reached):
            raise InspectionControlError("inspection contains non-resumable unadmitted observations")
        if inspected.evidence_id != inspection_evidence_id(inspected.canonical_payload()):
            raise InspectionControlError("resume inspection evidence id is invalid")
        expected = (
            inspected.evidence_id,
            inspected.request_fingerprint,
            inspected.configuration_fingerprint,
            inspected.next_gate,
        )
        supplied = (
            authorization.evidence_id,
            authorization.request_fingerprint,
            authorization.configuration_fingerprint,
            authorization.next_gate,
        )
        if supplied != expected:
            raise InspectionControlError(
                "resume authorization does not exactly bind evidence, request, configuration, and next gate"
            )
        if type(self._observer) is not type(executor) or self._observer is not executor:
            raise InspectionControlError(
                "resume requires one exact observer/executor capability for revalidation and start"
            )
        current = self.inspect(
            request,
            configuration_fingerprint=configuration_fingerprint,
            home=home,
        )
        if (
            current.evidence_id != inspected.evidence_id
            or current != inspected
            or current.state != "blocked-preflight"
            or current.next_gate is not inspected.next_gate
        ):
            raise InspectionControlError("full inspected state changed before resume")
        capability = _ResumeCapability()
        executor.execute_gate_for_test(inspected.next_gate, capability)
        return ResumeStart(inspected.next_gate, inspected.evidence_id)


class _ControlledG01G03Capability:
    """Private key admitting only the controlled G01-G05 fixture controller."""


_CONTROLLED_G01_G03_CAPABILITY = _ControlledG01G03Capability()


class ControlledG01G03Controller:
    """Persisted controlled G01-G05 state machine, never public CLI wiring."""

    def __init__(
        self,
        transport: ControlledGateTransport,
        *,
        evidence_dir: Path,
        _capability: _ControlledG01G03Capability | None = None,
    ) -> None:
        if _capability is not _CONTROLLED_G01_G03_CAPABILITY:
            raise InspectionControlError(
                "controlled G01-G05 controller requires its private fixture factory"
            )
        if not isinstance(evidence_dir, Path) or not evidence_dir.is_absolute():
            raise InspectionControlError("controlled evidence directory must be an absolute Path")
        self._transport = transport
        self._admission: object | None = None
        self._active_evidence: ProvisioningEvidence | None = None
        self._fixture_session: ControlledFixtureSession | None = None
        self._preserve_on_binding_failure = False
        self._evidence_fds_used: list[int] = []
        self._used = False
        self._evidence_dir = evidence_dir
        if ".." in self._evidence_dir.parts:
            raise InspectionControlError("controlled evidence directory must be canonical")
        try:
            canonical_evidence = self._evidence_dir.resolve(strict=False)
        except OSError as error:
            raise InspectionControlError("controlled evidence directory could not be normalized") from error
        if canonical_evidence != self._evidence_dir:
            raise InspectionControlError("controlled evidence directory must be canonical")
        if self._evidence_dir.name != "evidence":
            raise InspectionControlError("controlled evidence directory must be the exact evidence leaf")
        self._fixture_root = self._evidence_dir.parent
        try:
            root_metadata = self._fixture_root.lstat()
            self._expected_home = (self._fixture_root / "home").resolve(strict=False)
        except OSError as error:
            raise InspectionControlError("controlled fixture paths were unavailable") from error
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise InspectionControlError("controlled fixture root must be an exact directory")
        if self._expected_home.parent != self._fixture_root:
            raise InspectionControlError("controlled fixture home escaped its disposable root")
        self._assert_exact_directory_chain(
            self._fixture_root,
            self._evidence_dir,
            allow_missing_leaf=True,
        )

    @classmethod
    def _for_controlled_test(
        cls,
        transport: ControlledGateTransport,
        *,
        evidence_dir: Path,
    ) -> ControlledG01G03Controller:
        if cls is not ControlledG01G03Controller:
            raise InspectionControlError("controlled G01-G05 controller subclasses are not admitted")
        return cls(
            transport,
            evidence_dir=evidence_dir,
            _capability=_CONTROLLED_G01_G03_CAPABILITY,
        )

    @staticmethod
    def _assert_exact_directory_chain(
        root: Path,
        target: Path,
        *,
        allow_missing_leaf: bool = False,
        allow_missing_tail: bool = False,
    ) -> None:
        try:
            relative = target.relative_to(root)
            current = root
            roots_metadata = root.lstat()
        except (OSError, ValueError) as error:
            raise InspectionControlError("controlled fixture directory chain was unavailable") from error
        if stat.S_ISLNK(roots_metadata.st_mode) or not stat.S_ISDIR(roots_metadata.st_mode):
            raise InspectionControlError("controlled fixture root must be an exact directory")
        for index, part in enumerate(relative.parts):
            current = current / part
            is_leaf = index == len(relative.parts) - 1
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                if (is_leaf and allow_missing_leaf) or allow_missing_tail:
                    return
                raise InspectionControlError("controlled fixture directory chain was unavailable") from None
            except OSError as error:
                raise InspectionControlError("controlled fixture directory chain was unavailable") from error
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise InspectionControlError("controlled fixture directory chain must use exact directories")
        try:
            resolved = target.resolve(strict=not (allow_missing_leaf or allow_missing_tail))
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise InspectionControlError("controlled fixture directory chain escaped its root") from error

    def _bootstrap_evidence_directory(self) -> None:
        """Create only the validated missing evidence leaf without following links."""
        self._assert_exact_directory_chain(
            self._fixture_root,
            self._evidence_dir,
            allow_missing_leaf=True,
        )
        try:
            os.mkdir(self._evidence_dir, mode=0o700)
        except FileExistsError:
            # A concurrent creator or swap is accepted only after a fresh exact
            # no-follow validation below.
            pass
        except OSError as error:
            raise InspectionControlError("controlled evidence directory could not be created") from error
        self._assert_exact_directory_chain(self._fixture_root, self._evidence_dir)

    def _persist_owned(self, evidence: ProvisioningEvidence) -> None:
        session = self._fixture_session
        if session is None:
            raise InspectionControlError("controlled descriptor session was unavailable")
        try:
            if self._preserve_on_binding_failure:
                session.assert_ledger_binding()
            else:
                session.assert_bindings()
            self._evidence_fds_used.append(session.evidence_fd)
            session.persist(evidence, preserve_on_binding_failure=self._preserve_on_binding_failure)
            if self._preserve_on_binding_failure:
                session.assert_ledger_binding()
            else:
                session.assert_bindings()
        except ControlledFixtureError as error:
            raise InspectionControlError("controlled descriptor-bound persistence failed") from error

    def _record_mutation_attempt(self, gate: Gate, label: str) -> bool:
        """Persist the exact pre-mutation attempt on the active owned ledger."""
        evidence = self._active_evidence
        if evidence is None:
            raise AdapterError("controlled mutation attempt had no active controller ledger")
        allowed = {
            Gate.CLONE: ("G02:modeled-clone",),
            Gate.RENDER: ("G03:modeled-render",),
            Gate.BEADS: ("G04:modeled-beads-init",),
            Gate.BEADS_REMOTE: (
                "G05:modeled-dolt-remote-add",
                "G05:modeled-claude-setup",
                "G05:modeled-codex-setup",
                "G05:modeled-hooks-install",
            ),
        }
        if gate not in allowed or label not in allowed[gate]:
            raise AdapterError("controlled mutation attempt did not match the active gate")
        if label in evidence.mutation_attempts:
            raise AdapterError("controlled mutation attempt was already recorded")
        evidence.mutation_attempts.append(label)
        try:
            self._persist_owned(evidence)
        except Exception:
            evidence.mutation_attempts.pop()
            raise
        return True

    def _record_mutation_completion(self, gate: Gate, label: str) -> bool:
        """Persist one completion only after its mandatory readbacks passed."""
        evidence = self._active_evidence
        if evidence is None:
            raise AdapterError("controlled mutation completion had no active controller ledger")
        if label not in evidence.mutation_attempts or label in evidence.mutations_completed:
            raise AdapterError("controlled mutation completion did not match one pending attempt")
        if not label.startswith(f"{gate.value}:modeled-"):
            raise AdapterError("controlled mutation completion did not match the active gate")
        evidence.mutations_completed.append(label)
        try:
            self._persist_owned(evidence)
        except Exception:
            evidence.mutations_completed.pop()
            raise
        return True

    @staticmethod
    def _safe_detail(error: BaseException) -> str:
        detail = redact(str(error) or "controlled gate failed")
        if "[REDACTED]" in detail:
            return "controlled gate failed with sanitized diagnostics"
        return detail[:500]

    def run(
        self,
        request: ProvisioningRequest,
        *,
        configuration: ImmutableLiveConfiguration,
        home: Path,
    ) -> ProvisioningEvidence:
        """Open one descriptor session and model G01-G05 exactly once."""
        if self._used:
            raise InspectionControlError(
                "controlled G01-G05 controller is single-use; use Task-5 exact inspection/resume"
            )
        self._used = True
        try:
            session = ControlledFixtureSession(self._fixture_root)
            session.open()
            self._fixture_session = session
            return self._run_opened(request, configuration=configuration, home=home)
        except ControlledFixtureError as error:
            raise InspectionControlError("controlled descriptor session could not be opened") from error
        finally:
            if self._fixture_session is not None:
                self._fixture_session.close()
                self._fixture_session = None

    def _run_opened(
        self,
        request: ProvisioningRequest,
        *,
        configuration: ImmutableLiveConfiguration,
        home: Path,
    ) -> ProvisioningEvidence:
        """Model G01-G05 on the run-scoped root/evidence descriptors."""
        if not isinstance(home, Path) or not home.is_absolute():
            raise InspectionControlError("controlled fixture home must be an absolute Path")
        if home != self._expected_home:
            raise InspectionControlError("controlled fixture home must be the canonical disposable home")
        expected_destination = home / configuration.destination_route
        self._assert_exact_directory_chain(
            self._fixture_root,
            expected_destination,
            allow_missing_tail=True,
        )
        try:
            self._assert_exact_directory_chain(self._fixture_root, home)
            canonical_home = home.resolve(strict=True)
            canonical_home.relative_to(self._fixture_root)
        except (OSError, ValueError) as error:
            raise InspectionControlError("controlled fixture home escaped its disposable root") from error
        if canonical_home != self._expected_home or home != canonical_home:
            raise InspectionControlError("controlled fixture home must be the canonical disposable home")
        try:
            home_metadata = home.lstat()
        except OSError as error:
            raise InspectionControlError("controlled fixture home metadata was unavailable") from error
        if stat.S_ISLNK(home_metadata.st_mode) or not stat.S_ISDIR(home_metadata.st_mode):
            raise InspectionControlError("controlled fixture home must be an exact directory")
        run_id = uuid.uuid4().hex
        run_nonce = secrets.token_hex(32)
        self._assert_exact_directory_chain(self._fixture_root, home)
        try:
            origin, destination = normalize_request(request, home)
            if type(configuration) is not ImmutableLiveConfiguration:
                raise ValueError("configuration must use the exact immutable type")
            if destination != expected_destination:
                raise ValueError("normalized destination did not match the controlled route")
            self._assert_exact_directory_chain(
                self._fixture_root,
                destination,
                allow_missing_tail=True,
            )
            fingerprint = request_fingerprint(request, destination)
        except (
            AttributeError,
            InspectionControlError,
            OSError,
            PreflightError,
            ValueError,
        ) as error:
            evidence = ProvisioningEvidence(
                run_id=run_id,
                request_fingerprint="not-computed",
                destination="not-reached",
                repository_identity="not-reached",
                state="blocked-preflight",
                failed_gate=str(Gate.PREFLIGHT),
                gates=[
                    GateResult(
                        Gate.PREFLIGHT,
                        "failed",
                        self._safe_detail(error),
                    )
                ],
                resume_requirement="phil-authorization-required",
                next_action="Correct the controlled preflight failure; no mutation was performed.",
                simulation=True,
            )
            self._persist_owned(evidence)
            return evidence

        provenance = RenderProvenance.capture(
            configuration,
            repository_owner=origin.owner,
            repository_name=origin.repository,
            project_kind=request.project_kind,
            project_description=request.description,
            visibility=request.visibility,
        )
        evidence = ProvisioningEvidence(
            run_id=run_id,
            request_fingerprint=fingerprint,
            destination="[REDACTED]",
            repository_identity=origin.identity,
            state="blocked-preflight",
            template_revision=configuration.resolved_template_commit,
            simulation=True,
            render_provenance=provenance,
        )
        self._active_evidence = evidence
        self._assert_exact_directory_chain(
            self._fixture_root,
            destination,
            allow_missing_tail=True,
        )
        self._persist_owned(evidence)

        self._assert_exact_directory_chain(
            self._fixture_root,
            destination,
            allow_missing_tail=True,
        )
        self._admission = _register_controlled_transport(
            self,
            self._transport,
            self._record_mutation_attempt,
            self._record_mutation_completion,
        )
        try:
            adapter = ControlledG01G03Adapter(
                self._transport,
                request=request,
                origin=origin,
                destination=destination,
                configuration=configuration,
                fingerprint=fingerprint,
                run_nonce=run_nonce,
                fixture_session=self._fixture_session,
                _admission=self._admission,
            )
            self._adapter = adapter
            self._admission = None
        except (AdapterError, OSError, ValueError) as error:
            evidence.failed_gate = str(Gate.PREFLIGHT)
            evidence.gates.append(
                GateResult(Gate.PREFLIGHT, "failed", self._safe_detail(error))
            )
            evidence.resume_requirement = "task-5-exact-inspection-required"
            evidence.next_action = "Use Task-5 exact inspection/resume; this controller cannot replay."
            self._persist_owned(evidence)
            return evidence

        for gate in (Gate.PREFLIGHT, Gate.CLONE, Gate.RENDER, Gate.BEADS, Gate.BEADS_REMOTE):
            returned_mutations: tuple[str, ...] = ()
            try:
                returned, detail = adapter.run_gate(gate)
                if returned is None:
                    returned_mutations = ()
                elif type(returned) is str:
                    returned_mutations = (returned,)
                elif type(returned) is tuple and all(type(item) is str for item in returned):
                    returned_mutations = returned
                else:
                    raise AdapterError("controlled mutation outcome had an invalid exact type")
                expected_mutations = {
                    Gate.PREFLIGHT: (),
                    Gate.CLONE: ("G02:modeled-clone",),
                    Gate.RENDER: ("G03:modeled-render",),
                    Gate.BEADS: ("G04:modeled-beads-init",),
                    Gate.BEADS_REMOTE: (
                        "G05:modeled-dolt-remote-add",
                        "G05:modeled-claude-setup",
                        "G05:modeled-codex-setup",
                        "G05:modeled-hooks-install",
                    ),
                }[gate]
                if returned_mutations != expected_mutations:
                    raise AdapterError("controlled mutation outcome did not match its controller-owned attempt")
                if any(label not in evidence.mutation_attempts for label in returned_mutations):
                    raise AdapterError("controlled mutation executed without persisted controller attempt")
                if any(label not in evidence.mutations_completed for label in returned_mutations):
                    raise AdapterError("controlled mutation completed without persisted mandatory readbacks")
                if gate is Gate.BEADS:
                    evidence.actual_database = adapter.actual_database
                tentative = GateResult(gate, "passed", detail)
                evidence.gates.append(tentative)
                try:
                    self._persist_owned(evidence)
                except Exception:
                    evidence.gates.pop()
                    raise
            except (AdapterError, ControlledFixtureError, InspectionControlError, OSError, RuntimeError, TypeError, ValueError) as error:
                evidence.state = "blocked-preflight" if gate is Gate.PREFLIGHT else "partial"
                evidence.failed_gate = str(gate)
                evidence.gates.append(GateResult(gate, "failed", self._safe_detail(error)))
                evidence.resume_requirement = "task-5-exact-inspection-required"
                evidence.next_action = (
                    "Correct the controlled G01 failure; no mutation was performed."
                    if gate is Gate.PREFLIGHT
                    else "Use Task-5 exact inspection/resume; this single-use controller cannot replay."
                )
                try:
                    self._preserve_on_binding_failure = True
                    self._persist_owned(evidence)
                except InspectionControlError:
                    # A canonical evidence-leaf replacement is itself the failure.
                    # The held original ledger already retains the last durable
                    # attempt; never write the replacement or mask the gate result.
                    pass
                return evidence

        evidence.state = "partial"
        evidence.failed_gate = None
        evidence.resume_requirement = "task-5-exact-inspection-required"
        evidence.next_action = (
            "Controlled G01-G05 model passed. Live execution remains unavailable; "
            "G06-G11 and any production transport are unimplemented."
        )
        self._persist_owned(evidence)
        return evidence


class Provisioner:
    def __init__(self, adapter: ProvisioningAdapter, evidence_dir: Path | None = None) -> None:
        self.adapter = adapter
        self.evidence_dir = evidence_dir

    @property
    def _simulation(self) -> bool:
        """Only the exact offline adapter may use simulated-success semantics.

        Adapter-provided flags are untrusted: a subclass or monkeypatch must not
        turn the in-memory test seam into a live provisioning claim.
        """
        return type(self.adapter) is FakeAdapter

    def run(self, request: ProvisioningRequest, *, home: Path | None = None, existing: bool = False) -> ProvisioningEvidence:
        try:
            origin, destination = normalize_request(request, home)
            missing = required_tools_available()
            if missing:
                raise PreflightError("required commands unavailable: " + ", ".join(missing))
        except PreflightError as exc:
            return self._blocked(request, str(exc))
        # Do not admit subclasses or hybrid multiple-inheritance adapters.  The
        # adapter type itself is the security boundary: exact FakeAdapter means
        # simulation; exact LiveAdapter is the only production-capable seam.
        if not self._simulation and type(self.adapter) is not LiveAdapter:
            return self._blocked(
                request,
                "unrecognized adapter; refusing any live-success semantics",
            )
        if request.live_authorization and self._simulation:
            return self._blocked(
                request,
                "live adapter is unavailable; refusing named live authorization in simulation mode",
            )
        if request.resume_authorization is not None:
            return self._blocked(
                request,
                "internal exact-gate resume is unavailable from the public simulation provisioner",
            )
        fingerprint = request_fingerprint(request, destination)
        try:
            self.adapter.prepare(request, origin, destination, fingerprint)
        except AdapterError as exc:
            return self._blocked(request, str(exc))
        evidence = ProvisioningEvidence(
            run_id=uuid.uuid4().hex,
            request_fingerprint=fingerprint,
            # The routed destination is a private absolute path; evidence must
            # carry no private path (NFR-007/FR-027). Identity and routing are
            # already bound by request_fingerprint; persist() rejects any
            # private-path evidence, so record the redacted marker here like the
            # controlled fixtures do.
            destination="[REDACTED]",
            repository_identity=origin.identity,
            state="blocked-preflight",
            template_revision=self.adapter.template_revision,
            simulation=self._simulation,
        )
        if existing:
            return self._inspect_existing(evidence)
        try:
            self.adapter.run_gate(Gate.PREFLIGHT)
        except AdapterError as exc:
            evidence.failed_gate = str(Gate.PREFLIGHT)
            evidence.resume_requirement = "phil-authorization-required"
            evidence.gates.append(GateResult(Gate.PREFLIGHT, "failed", str(exc)))
            evidence.next_action = "Correct the preflight failure; no mutation was performed."
            self._persist(evidence)
            return evidence
        preflight_status = "simulated" if self._simulation else "passed"
        preflight_detail = (
            "G01 simulated adapter boundary exercised; request normalization was local and no live probe or mutation was performed"
            if self._simulation
            else "validated request and live preflight probes"
        )
        evidence.gates.append(
            GateResult(
                Gate.PREFLIGHT,
                preflight_status,
                preflight_detail if self._simulation else self.adapter.gate_evidence(Gate.PREFLIGHT),
            )
        )
        for gate in POST_PREFLIGHT:
            try:
                self.adapter.run_gate(gate)
                if gate is Gate.MANIFEST:
                    metadata = self.adapter.read_metadata()
                    self.adapter.append_manifest({
                        "path": str(destination), "prefix": request.beads_prefix,
                        "database": metadata["dolt_database"], "owner": origin.owner,
                        "project_kind": request.project_kind, "visibility": request.visibility,
                        "profile": "default", "expected_remote": "origin", "expected_backup": True,
                        "expected_sync": "manual-dolt-remote", "owning_jobs": OWNING_JOBS,
                        "remote_health": "required", "restore_tier": "rotating",
                    })
                if gate is Gate.BOOTSTRAP:
                    ensure_bootstrap_issues(self.adapter, request.project_kind)
                if gate is Gate.PUSH:
                    self._sync(evidence)
                gate_status = "simulated" if self._simulation else "passed"
                evidence.gates.append(GateResult(gate, gate_status, self._gate_evidence(gate)))
                if not self._simulation:
                    evidence.mutations_completed.append(str(gate))
            except AdapterError as exc:
                return self._partial(evidence, gate, str(exc))
        if self._simulation:
            evidence.state = "simulation-passed"
            evidence.simulation = True
            evidence.git_sync = "simulated"
            evidence.dolt_sync = "simulated"
            evidence.next_action = "Simulation passed; this is not a provisioned repository. The public CLI is simulation-only and nonzero; the retained LiveAdapter draft is rejected and fail-closed, with no approved runner or production path."
        else:
            evidence.state = "complete"
            evidence.next_action = "Complete; Git and Dolt synchronization were independently read back."
        self._persist(evidence)
        return evidence

    def _inspect_existing(self, evidence: ProvisioningEvidence) -> ProvisioningEvidence:
        try:
            valid = self.adapter.verify_existing()
        except AdapterError as exc:
            return self._partial(evidence, Gate.PREFLIGHT, f"existing-state inspection failed: {exc}")
        if not valid:
            evidence.state = "blocked-preflight"
            evidence.resume_requirement = "phil-authorization-required"
            evidence.gates.append(GateResult(Gate.PREFLIGHT, "failed", "existing state is not proven complete"))
            evidence.next_action = "Inspect the partial state and obtain Phil authorization naming this fingerprint and failed gate before mutation."
        elif self._simulation:
            evidence.state = "blocked-preflight"
            evidence.gates.append(GateResult(Gate.PREFLIGHT, "failed", "simulation cannot verify an existing live project"))
            evidence.next_action = "Live inspection is required before claiming verified-existing."
        else:
            evidence.state = "verified-existing"
            evidence.gates.append(GateResult(Gate.PREFLIGHT, "passed", "live completion invariants read back"))
            evidence.next_action = "No mutation; complete state was inspection-verified."
        self._persist(evidence)
        return evidence

    def _sync(self, evidence: ProvisioningEvidence) -> None:
        try:
            self.adapter.push_git()
            evidence.git_sync = "simulated" if self._simulation else "succeeded"
        except AdapterError:
            evidence.git_sync = "failed"
            raise
        try:
            self.adapter.push_dolt()
            evidence.dolt_sync = "simulated" if self._simulation else "succeeded"
        except AdapterError:
            evidence.dolt_sync = "failed"
            raise

    def _partial(self, evidence: ProvisioningEvidence, gate: Gate, detail: str) -> ProvisioningEvidence:
        evidence.state = "partial"
        evidence.failed_gate = str(gate)
        evidence.resume_requirement = "phil-authorization-required"
        evidence.next_action = (
            f"Inspect first; Phil authorization must name fingerprint {evidence.request_fingerprint} "
            f"and failed gate {gate} before mutation."
        )
        evidence.gates.append(GateResult(gate, "failed", detail))
        self._persist(evidence)
        return evidence

    def _gate_evidence(self, gate: Gate) -> str:
        if self._simulation:
            return f"{gate} simulated adapter boundary exercised; no live mutation performed"
        return self.adapter.gate_evidence(gate)

    def _blocked(self, request: ProvisioningRequest, detail: str) -> ProvisioningEvidence:
        evidence = ProvisioningEvidence(
            run_id=uuid.uuid4().hex,
            request_fingerprint="not-computed",
            destination="not-reached",
            repository_identity="not-reached",
            state="blocked-preflight",
            failed_gate=str(Gate.PREFLIGHT),
            resume_requirement="phil-authorization-required",
            gates=[GateResult(Gate.PREFLIGHT, "failed", detail)],
            next_action="Correct the preflight failure; no mutation was performed.",
            simulation=self._simulation,
        )
        self._persist(evidence)
        return evidence

    def _persist(self, evidence: ProvisioningEvidence) -> None:
        if self.evidence_dir is not None:
            persist(evidence, self.evidence_dir)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulation-only project provisioning harness")
    parser.add_argument("--origin-url", required=True)
    parser.add_argument("--beads-prefix", required=True)
    parser.add_argument("--project-kind", required=True, choices=["generic", "macos-cli", "homebrew-tap", "coding-agent-plugin"])
    parser.add_argument("--visibility", default="personal-only", choices=["personal-only", "work-internal", "open-source"])
    parser.add_argument("--description", default="")
    parser.add_argument("--destination-confirmation")
    parser.add_argument("--inspect-existing", action="store_true")
    args = parser.parse_args(argv)
    request = ProvisioningRequest(
        origin_url=args.origin_url,
        beads_prefix=args.beads_prefix,
        project_kind=args.project_kind,
        description=args.description,
        visibility=args.visibility,
        destination_confirmation=args.destination_confirmation,
    )
    result = Provisioner(FakeAdapter()).run(request, existing=args.inspect_existing)
    payload = result.serializable()
    # Simulation performs no mutation, so evidence goes to stdout only; the
    # absent on-disk ledger is intentional, not a gap in evidence preservation.
    if isinstance(payload, dict):
        payload["evidence_note"] = (
            "simulation evidence is intentionally not persisted; this run wrote no on-disk ledger"
        )
    print(json.dumps(payload, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

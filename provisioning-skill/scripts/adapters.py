"""Injected simulation boundary and quarantined LiveAdapter draft.

The public CLI constructs only ``FakeAdapter``. ``LiveAdapter`` is a rejected,
incomplete design artifact retained for redesign reference; its availability
guard fails before runner/config validation, command construction, or runner
invocation. There is no subprocess implementation or approved live path.
"""
from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import threading
import weakref
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

from .backup import BackupError, assert_safe_backup_root, validate_backup_tree
from .closeout import scan_staged_content, validate_commit_message
from .controlled_fixture import ControlledFixtureError, ControlledFixtureSession, ControlledMutationTarget
from .live_executor import (
    ControlledLiveExecutor as _ControlledLiveExecutor,
    BeadsHooksInstallRequest,
    BeadsHooksListRequest,
    BeadsInitRequest,
    BeadsPrefixReadRequest,
    BeadsSetupRequest,
    CopierRenderRequest,
    DoltRemoteAddRequest,
    DoltRemoteListRequest,
    GitCloneRequest,
    GitRemoteReadbackRequest,
    GitTemplateRevisionRequest,
    LiveOperation,
)
from .production_transport import make_production_executor
from .manifest import ManifestError, append_record, load_manifest, validate_records
from .evidence import redact
from .models import (
    ConfigurationError,
    Gate,
    ImmutableLiveConfiguration,
    LiveAdapterConfig,
    ProvisioningRequest,
    assert_live_authorized,
    configuration_digest,
)
from .preflight import ParsedOrigin
from .speckit import COMPATIBLE_EXTENSIONS, COMPATIBLE_PRESETS, EXCLUDED, init_command


class AdapterError(RuntimeError):
    """A command, safety assertion, or mandatory readback failed."""


@dataclass(frozen=True)
class CommandSpec:
    """One argv-only command invocation with a complete isolated environment."""

    operation: str
    argv: tuple[str, ...]
    cwd: Path | None
    env: Mapping[str, str]
    timeout_seconds: int = 60
    mutating: bool = False
    beads: bool = False


@dataclass(frozen=True)
class CommandResult:
    """Structured runner result; ``data`` contains operation-specific readback."""

    operation: str
    argv: tuple[str, ...]
    cwd: Path | None
    returncode: int
    stdout: str = ""
    stderr: str = ""
    data: Mapping[str, Any] = field(default_factory=dict)


class SafeCommandRunner(Protocol):
    """A runner explicitly opting into the LiveAdapter safety contract."""

    is_safe_command_runner: bool

    def run(self, spec: CommandSpec) -> CommandResult: ...


class ProvisioningAdapter(Protocol):
    is_simulation: bool

    @property
    def template_revision(self) -> str: ...
    def prepare(
        self,
        request: ProvisioningRequest,
        origin: ParsedOrigin,
        destination: Path,
        fingerprint: str,
    ) -> None: ...
    def run_gate(self, gate: Gate) -> None: ...
    def gate_evidence(self, gate: Gate) -> str: ...
    def read_metadata(self) -> dict[str, Any]: ...
    def append_manifest(self, record: dict[str, Any]) -> None: ...
    def create_issue(self, marker: str, title: str) -> dict[str, Any]: ...
    def verify_existing(self) -> bool: ...
    def push_git(self) -> None: ...
    def push_dolt(self) -> None: ...


@dataclass
class FakeAdapter:
    """Deterministic simulation seam. No external command is executed."""

    failures: set[str] = field(default_factory=set)
    calls: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=lambda: {
        "dolt_mode": "server", "dolt_server_port": 3307, "dolt_database": "example_db",
    })
    manifest_records: list[dict[str, Any]] = field(default_factory=list)
    issues: dict[str, dict[str, Any]] = field(default_factory=dict)
    existing_valid: bool = False

    @property
    def is_simulation(self) -> bool:
        """Invariant: this in-memory adapter can never represent live execution."""
        return True

    @property
    def template_revision(self) -> str:
        return "simulated"

    def prepare(
        self,
        request: ProvisioningRequest,
        origin: ParsedOrigin,
        destination: Path,
        fingerprint: str,
    ) -> None:
        del request, origin, destination, fingerprint

    def run_gate(self, gate: Gate) -> None:
        self.calls.append(str(gate))
        if str(gate) in self.failures:
            raise AdapterError(f"injected failure at {gate}")

    def gate_evidence(self, gate: Gate) -> str:
        return f"{gate} simulated adapter boundary exercised; no live mutation performed"

    def read_metadata(self) -> dict[str, Any]:
        return dict(self.metadata)

    def append_manifest(self, record: dict[str, Any]) -> None:
        self.manifest_records.append(dict(record))

    def create_issue(self, marker: str, title: str) -> dict[str, Any]:
        self.calls.append(f"issue:{marker}")
        if f"issue:{marker}" in self.failures:
            raise AdapterError(f"injected failure creating bootstrap issue {marker}")
        return self.issues.setdefault(marker, {"marker": marker, "title": title})

    def verify_existing(self) -> bool:
        self.calls.append("inspect-existing")
        return self.existing_valid

    def push_git(self) -> None:
        self.calls.append("git-push")
        if "git-push" in self.failures:
            raise AdapterError("injected Git synchronization failure")

    def push_dolt(self) -> None:
        self.calls.append("dolt-push")
        if "dolt-push" in self.failures:
            raise AdapterError("injected Dolt synchronization failure")


class ControlledGateOperation(Enum):
    """Closed G01-G05 operation set for disposable controlled fixtures only."""

    ORIGIN_ACCESS_READ = "g01-g02-origin-access-read"
    TOOLCHAIN_READ = "g01-toolchain-read"
    CENTRAL_DOLT_READ = "g01-central-dolt-read"
    CLONE_MUTATION = "g02-modeled-clone"
    CHECKOUT_READBACK = "g02-g03-checkout-readback"
    TEMPLATE_REVISION_READ = "g03-template-revision-readback"
    RENDER_MUTATION = "g03-modeled-render"
    BEADS_INIT_MUTATION = "g04-modeled-beads-init"
    BEADS_METADATA_READBACK = "g04-generated-metadata-readback"
    BEADS_PREFIX_READBACK = "g04-prefix-readback"
    DOLT_REMOTE_READBACK = "g05-dolt-remote-readback"
    DOLT_REMOTE_ADD_MUTATION = "g05-modeled-dolt-remote-add"
    AGENT_SETUP_MUTATION = "g05-modeled-agent-setup"
    AGENT_SETUP_READBACK = "g05-agent-setup-readback"
    INTEGRATIONS_READBACK = "g05-integrations-readback"
    HOOKS_INSTALL_MUTATION = "g05-modeled-hooks-install"
    HOOKS_READBACK = "g05-hooks-readback"
    CORE_HOOKS_PATH_READBACK = "g05-core-hooks-path-readback"


@dataclass(frozen=True, slots=True)
class OriginAccessRequest:
    origin_url: str
    repository_identity: str
    destination: Path
    challenge: str


@dataclass(frozen=True, slots=True)
class ToolchainReadRequest:
    expected_tools: tuple[str, ...]
    challenge: str


@dataclass(frozen=True, slots=True)
class CentralProbeRequest:
    beads_prefix: str
    challenge: str


@dataclass(frozen=True, slots=True)
class CloneMutationRequest:
    origin_url: str
    repository_identity: str
    destination: Path


@dataclass(frozen=True, slots=True)
class CheckoutReadbackRequest:
    origin_url: str
    repository_identity: str
    destination: Path
    destination_digest: str
    challenge: str


@dataclass(frozen=True, slots=True)
class TemplateRevisionReadRequest:
    template_source_identity: str
    template_tag: str
    expected_commit: str
    challenge: str


@dataclass(frozen=True, slots=True)
class RenderMutationRequest:
    destination: Path
    template_source_identity: str
    template_tag: str
    template_commit: str
    repository_owner: str
    repository_name: str
    project_description: str
    project_kind: str


@dataclass(frozen=True, slots=True)
class BeadsInitRequest:
    target: ControlledMutationTarget
    beads_prefix: str
    central_host: str
    central_port: int


@dataclass(frozen=True, slots=True)
class BeadsMetadataReadbackRequest:
    destination: Path
    beads_prefix: str
    expected_database: str
    challenge: str


@dataclass(frozen=True, slots=True)
class BeadsPrefixReadbackRequest:
    destination: Path
    beads_prefix: str
    challenge: str


@dataclass(frozen=True, slots=True)
class DoltRemoteReadbackRequest:
    destination: Path
    expected_remote_url: str
    expected_absent: bool
    challenge: str


@dataclass(frozen=True, slots=True)
class DoltRemoteAddRequest:
    target: ControlledMutationTarget
    remote_name: str
    remote_url: str


@dataclass(frozen=True, slots=True)
class AgentSetupMutationRequest:
    target: ControlledMutationTarget
    integration: str


@dataclass(frozen=True, slots=True)
class AgentSetupReadbackRequest:
    destination: Path
    integration: str
    challenge: str


@dataclass(frozen=True, slots=True)
class IntegrationsReadbackRequest:
    destination: Path
    expected_integrations: tuple[str, ...]
    challenge: str


@dataclass(frozen=True, slots=True)
class HooksInstallRequest:
    target: ControlledMutationTarget
    expected_location: str
    expected_hooks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HooksReadbackRequest:
    destination: Path
    expected_location: str
    expected_hooks: tuple[str, ...]
    challenge: str


@dataclass(frozen=True, slots=True)
class CoreHooksPathReadbackRequest:
    destination: Path
    expected_hooks_path: str
    challenge: str


@dataclass(frozen=True, slots=True)
class RawControlledGateResult:
    """Raw controlled transport fields; there is no trusted assertion map."""

    operation: ControlledGateOperation
    returncode: int
    stdout: str = ""
    stderr: str = ""


class ControlledGateTransport(Protocol):
    """Test-only operation seam. No production implementation exists."""

    def execute_gate_for_test(
        self,
        operation: ControlledGateOperation,
        parameters: object,
    ) -> RawControlledGateResult: ...


_CONTROLLED_GATE_MAX_OUTPUT = 65_536
_EXPECTED_CONTROLLED_TOOLS = ("bd", "copier", "git", "python3", "specify")
_EXACT_CONTROLLED_KEYS: Mapping[ControlledGateOperation, frozenset[str]] = MappingProxyType(
    {
        ControlledGateOperation.ORIGIN_ACCESS_READ: frozenset(
            {"challenge", "identity", "operation", "origin_url", "permission", "references"}
        ),
        ControlledGateOperation.TOOLCHAIN_READ: frozenset(
            {"challenge", "operation", "tools"}
        ),
        ControlledGateOperation.CENTRAL_DOLT_READ: frozenset(
            {"challenge", "host", "operation", "port", "prefix_matches", "query_result"}
        ),
        ControlledGateOperation.CHECKOUT_READBACK: frozenset(
            {"branch", "challenge", "identity", "operation", "origin_url", "root_digest"}
        ),
        ControlledGateOperation.TEMPLATE_REVISION_READ: frozenset(
            {"challenge", "operation", "resolved_commit", "source_identity", "tag"}
        ),
        ControlledGateOperation.BEADS_METADATA_READBACK: frozenset(
            {"challenge", "database", "host", "mode", "operation", "port", "prefix"}
        ),
        ControlledGateOperation.BEADS_PREFIX_READBACK: frozenset(
            {"challenge", "operation", "prefix"}
        ),
        ControlledGateOperation.DOLT_REMOTE_READBACK: frozenset(
            {"challenge", "operation", "remotes"}
        ),
        ControlledGateOperation.AGENT_SETUP_READBACK: frozenset(
            {"challenge", "installed", "integration", "operation"}
        ),
        ControlledGateOperation.INTEGRATIONS_READBACK: frozenset(
            {"challenge", "integrations", "operation"}
        ),
        ControlledGateOperation.HOOKS_READBACK: frozenset(
            {"challenge", "hook_location", "hooks", "managed", "operation"}
        ),
        ControlledGateOperation.CORE_HOOKS_PATH_READBACK: frozenset(
            {"challenge", "hooks_path", "operation"}
        ),
    }
)


class _ControlledAdapterAdmission:
    """One exact controller can admit one exact transport once."""

    __slots__ = ("_entries", "_lock", "_owners")

    def __init__(self) -> None:
        self._entries: dict[
            int,
            tuple[
                weakref.ReferenceType[object],
                weakref.ReferenceType[object],
                object,
                object,
                object,
            ],
        ] = {}
        self._owners: dict[int, weakref.ReferenceType[object]] = {}
        self._lock = threading.RLock()

    def register(
        self,
        owner: object,
        transport: object,
        recorder: object,
        completer: object,
    ) -> object:
        # This is an in-process wiring guard, not a sandbox against arbitrary
        # same-process monkeypatching.  It prevents accidental/direct admission
        # by binding the only registration to the exact controller type and its
        # own unmodified bound persistence callbacks.
        from .provision_project import ControlledG01G03Controller

        if type(owner) is not ControlledG01G03Controller:
            raise AdapterError("controlled transport admission requires the exact controller owner")
        if (
            getattr(recorder, "__self__", None) is not owner
            or getattr(recorder, "__func__", None)
            is not ControlledG01G03Controller._record_mutation_attempt
        ):
            raise AdapterError(
                "controlled transport admission requires the controller-owned persistence callback"
            )
        if (
            getattr(completer, "__self__", None) is not owner
            or getattr(completer, "__func__", None)
            is not ControlledG01G03Controller._record_mutation_completion
        ):
            raise AdapterError(
                "controlled transport admission requires the controller-owned completion callback"
            )
        token = object()
        identity = id(transport)
        owner_identity = id(owner)

        def remove_transport(
            reference: weakref.ReferenceType[object], *, key: int = identity
        ) -> None:
            with self._lock:
                current = self._entries.get(key)
                if current is not None and current[1] is reference:
                    self._entries.pop(key, None)

        def remove_owner(
            reference: weakref.ReferenceType[object], *, key: int = owner_identity
        ) -> None:
            with self._lock:
                if self._owners.get(key) is reference:
                    self._owners.pop(key, None)

        try:
            owner_reference = weakref.ref(owner, remove_owner)
            transport_reference = weakref.ref(transport, remove_transport)
        except TypeError as error:
            raise AdapterError("controlled transport and owner must support identity admission") from error
        with self._lock:
            current_owner = self._owners.get(owner_identity)
            if current_owner is not None and current_owner() is owner:
                raise AdapterError("controlled controller already registered its one transport")
            if identity in self._entries and self._entries[identity][1]() is transport:
                raise AdapterError("controlled transport is already registered")
            self._owners[owner_identity] = owner_reference
            self._entries[identity] = (
                owner_reference,
                transport_reference,
                token,
                recorder,
                completer,
            )
        return token

    def consume(self, transport: object, token: object) -> object:
        identity = id(transport)
        with self._lock:
            current = self._entries.pop(identity, None)
        if (
            current is None
            or current[0]() is None
            or current[1]() is not transport
            or current[2] is not token
        ):
            raise AdapterError("controlled adapter requires one registered fixture admission")
        return current[3], current[4]


_CONTROLLED_ADMISSION = _ControlledAdapterAdmission()


def _register_controlled_transport(
    owner: object,
    transport: object,
    recorder: object,
    completer: object | None = None,
) -> object:
    """Internal one-time controller wiring; arbitrary callbacks are rejected."""
    if completer is None:
        completer = getattr(owner, "_record_mutation_completion", None)
    return _CONTROLLED_ADMISSION.register(owner, transport, recorder, completer)


def _controlled_challenge(
    fingerprint: str,
    run_nonce: str,
    operation: ControlledGateOperation,
    sequence: int,
) -> str:
    return hashlib.sha256(
        f"{fingerprint}:{run_nonce}:{operation.value}:{sequence}".encode("utf-8")
    ).hexdigest()


def _reject_duplicate_controlled_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("controlled observation has duplicate object members")
        payload[key] = value
    return payload


def _safe_adapter_error(detail: object, fallback: str) -> AdapterError:
    try:
        admitted = redact(str(detail) or fallback)
    except Exception:
        admitted = fallback
    if "[REDACTED]" in admitted:
        admitted = fallback
    return AdapterError(admitted[:500])


class ControlledG01G03Adapter:
    """Parser-owned G01-G05 model over closed fakes and disposable files.

    Construction is owned by the internal controller factory. This adapter has
    no command builder, subprocess transport, credential path, or public CLI
    route, and completing its slice cannot represent live readiness.
    """

    def __init__(
        self,
        transport: ControlledGateTransport,
        *,
        request: ProvisioningRequest,
        origin: ParsedOrigin,
        destination: Path,
        configuration: ImmutableLiveConfiguration,
        fingerprint: str,
        run_nonce: str,
        fixture_session: ControlledFixtureSession,
        _admission: object | None = None,
    ) -> None:
        if type(self) is not ControlledG01G03Adapter:
            raise AdapterError("controlled gate adapter subclasses are not admitted")
        callbacks = _CONTROLLED_ADMISSION.consume(transport, _admission)
        if type(callbacks) is not tuple or len(callbacks) != 2:
            raise AdapterError("controlled gate adapter admission omitted its recorders")
        self._record_attempt, self._record_completion = callbacks
        if not callable(self._record_attempt) or not callable(self._record_completion):
            raise AdapterError("controlled gate adapter admission omitted its recorder")
        if type(configuration) is not ImmutableLiveConfiguration:
            raise AdapterError("controlled gate model requires exact immutable configuration")
        if type(request) is not ProvisioningRequest or type(origin) is not ParsedOrigin:
            raise AdapterError("controlled gate model requires exact normalized request types")
        if type(fixture_session) is not ControlledFixtureSession:
            raise AdapterError("controlled gate model requires its exact descriptor session")
        fixture_session.assert_bindings()
        configuration.__post_init__()
        if configuration.destination_route != str(
            Path("Projects") / ("work" if origin.owner == "flexapp" else "pjbeyer") / origin.repository
        ):
            raise AdapterError("controlled gate configuration does not match the exact destination route")
        if configuration.repository_identity != origin.identity:
            raise AdapterError("controlled gate configuration does not match repository identity")
        configuration_digest(configuration)
        self._transport = transport
        self._fixture_session = fixture_session
        self._destination = destination
        # The session owns and validates this lexical anchor against its held
        # descriptor; adapter code never re-derives a root from destination.
        self._fixture_root = fixture_session.root_path
        self._configuration = configuration
        self._fingerprint = fingerprint
        if type(run_nonce) is not str or re.fullmatch(r"[0-9a-f]{64}", run_nonce) is None:
            raise AdapterError("controlled run nonce is invalid")
        self._run_nonce = run_nonce
        self._sequence = 0
        self._g02_complete = False
        self._g03_complete = False
        self._g04_complete = False
        self._actual_database: str | None = None
        self._request_snapshot = (
            request.origin_url,
            request.beads_prefix,
            request.project_kind,
            request.description,
        )
        self._origin_snapshot = (origin.owner, origin.repository, origin.identity)
        self._g01_origin_snapshot: tuple[str, str, str, tuple[str, ...]] | None = None

    def _challenge(self, operation: ControlledGateOperation) -> str:
        self._sequence += 1
        return _controlled_challenge(
            self._fingerprint,
            self._run_nonce,
            operation,
            self._sequence,
        )

    def _invoke(
        self,
        operation: ControlledGateOperation,
        parameters: object,
        request_type: type[object],
        *,
        expect_empty: bool = False,
    ) -> dict[str, Any]:
        if type(parameters) is not request_type:
            raise AdapterError("controlled operation received the wrong exact request type")
        try:
            raw = self._transport.execute_gate_for_test(operation, parameters)
        except Exception as error:
            raise _safe_adapter_error(error, "controlled transport operation was unavailable") from error
        if type(raw) is not RawControlledGateResult or raw.operation is not operation:
            raise AdapterError("controlled transport returned the wrong exact raw result")
        if (
            isinstance(raw.returncode, bool)
            or type(raw.returncode) is not int
            or type(raw.stdout) is not str
            or type(raw.stderr) is not str
        ):
            raise AdapterError("controlled transport returned invalid raw result fields")
        if len(raw.stdout) > _CONTROLLED_GATE_MAX_OUTPUT or len(raw.stderr) > _CONTROLLED_GATE_MAX_OUTPUT:
            raise AdapterError("controlled transport output exceeded its bounded size")
        if raw.returncode != 0:
            raise AdapterError("controlled transport operation returned nonzero")
        if expect_empty:
            if raw.stdout or raw.stderr:
                raise AdapterError("controlled mutation result contained unexpected assertion output")
            return {}
        if redact(raw.stdout) != raw.stdout or redact(raw.stderr) != raw.stderr:
            raise AdapterError("controlled observation contained unsafe material")
        try:
            payload = json.loads(raw.stdout, object_pairs_hook=_reject_duplicate_controlled_members)
        except (json.JSONDecodeError, ValueError) as error:
            raise AdapterError("controlled observation was malformed") from error
        if type(payload) is not dict or set(payload) != _EXACT_CONTROLLED_KEYS[operation]:
            raise AdapterError("controlled observation had an invalid exact shape")
        return payload

    @staticmethod
    def _require_exact(value: object, expected: object, label: str) -> None:
        if type(value) is not type(expected) or value != expected:
            raise AdapterError(f"{label} parser invariant did not match")

    @staticmethod
    def _destination_digest(destination: Path) -> str:
        return hashlib.sha256(str(destination).encode("utf-8")).hexdigest()

    def _assert_destination_absent(self) -> None:
        self._assert_fixture_path(
            self._destination,
            require_leaf=None,
            allow_missing_tail=True,
        )
        try:
            self._destination.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise _safe_adapter_error(error, "destination metadata read failed") from error
        raise AdapterError("destination changed or became occupied before modeled clone")

    def _origin_access_read(self) -> tuple[str, str, str, tuple[str, ...]]:
        challenge = self._challenge(ControlledGateOperation.ORIGIN_ACCESS_READ)
        payload = self._invoke(
            ControlledGateOperation.ORIGIN_ACCESS_READ,
            OriginAccessRequest(
                self._request_snapshot[0],
                self._origin_snapshot[2],
                self._destination,
                challenge,
            ),
            OriginAccessRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "origin challenge"),
            (payload["operation"], "authenticated-repository-access", "origin operation"),
            (payload["identity"], self._origin_snapshot[2], "origin identity"),
            (payload["origin_url"], self._request_snapshot[0], "origin URL"),
            (payload["permission"], "write", "origin write permission"),
            (payload["references"], [], "origin empty reference set"),
        ):
            self._require_exact(value, expected, label)
        return (
            payload["identity"],
            payload["origin_url"],
            payload["permission"],
            tuple(payload["references"]),
        )

    def _toolchain_read(self) -> None:
        challenge = self._challenge(ControlledGateOperation.TOOLCHAIN_READ)
        payload = self._invoke(
            ControlledGateOperation.TOOLCHAIN_READ,
            ToolchainReadRequest(_EXPECTED_CONTROLLED_TOOLS, challenge),
            ToolchainReadRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "toolchain challenge"),
            (payload["operation"], "toolchain-read", "toolchain operation"),
            (payload["tools"], list(_EXPECTED_CONTROLLED_TOOLS), "toolchain set"),
        ):
            self._require_exact(value, expected, label)

    def _central_read(self) -> None:
        challenge = self._challenge(ControlledGateOperation.CENTRAL_DOLT_READ)
        payload = self._invoke(
            ControlledGateOperation.CENTRAL_DOLT_READ,
            CentralProbeRequest(self._request_snapshot[1], challenge),
            CentralProbeRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "central challenge"),
            (
                payload["operation"],
                "central-dolt-select-one-and-prefix-read",
                "central operation",
            ),
            (payload["host"], "127.0.0.1", "central host"),
            (payload["port"], 3307, "central port"),
            (payload["query_result"], [{"ok": 1}], "central SELECT result"),
            (payload["prefix_matches"], [], "prefix empty match set"),
        ):
            self._require_exact(value, expected, label)

    def _checkout_readback(self) -> None:
        challenge = self._challenge(ControlledGateOperation.CHECKOUT_READBACK)
        digest = self._destination_digest(self._destination)
        payload = self._invoke(
            ControlledGateOperation.CHECKOUT_READBACK,
            CheckoutReadbackRequest(
                self._request_snapshot[0],
                self._origin_snapshot[2],
                self._destination,
                digest,
                challenge,
            ),
            CheckoutReadbackRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "checkout challenge"),
            (payload["operation"], "checkout-readback", "checkout operation"),
            (payload["identity"], self._origin_snapshot[2], "checkout identity"),
            (payload["origin_url"], self._request_snapshot[0], "checkout origin URL"),
            (payload["branch"], "main", "checkout primary branch"),
            (payload["root_digest"], digest, "checkout destination digest"),
        ):
            self._require_exact(value, expected, label)

    def _validate_checkout_filesystem(self) -> None:
        self._assert_fixture_path(self._destination, require_leaf="directory")
        self._assert_fixture_path(self._destination / ".git", require_leaf="directory")

    def _assert_fixture_path(
        self,
        path: Path,
        *,
        require_leaf: str | None,
        allow_missing_leaf: bool = False,
        allow_missing_tail: bool = False,
    ) -> None:
        """Lstat every node from the disposable root without following links."""
        try:
            relative = path.relative_to(self._fixture_root)
            root_metadata = self._fixture_root.lstat()
        except (OSError, ValueError) as error:
            raise AdapterError("controlled fixture root was unavailable") from error
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise AdapterError("controlled fixture root must be an exact directory")
        current = self._fixture_root
        parts = relative.parts
        for index, part in enumerate(parts):
            current = current / part
            is_leaf = index == len(parts) - 1
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                if (is_leaf and allow_missing_leaf) or allow_missing_tail:
                    return
                raise AdapterError("controlled fixture path node was missing") from None
            except OSError as error:
                raise _safe_adapter_error(error, "controlled fixture metadata read failed") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise AdapterError("controlled fixture path contained a symlink")
            if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
                raise AdapterError("controlled fixture ancestor was not an exact directory")
            if is_leaf and require_leaf == "directory" and not stat.S_ISDIR(metadata.st_mode):
                raise AdapterError("controlled fixture leaf was not an exact directory")
            if is_leaf and require_leaf == "file" and not stat.S_ISREG(metadata.st_mode):
                raise AdapterError("controlled fixture leaf was not an exact regular file")

    def _template_revision_read(self) -> None:
        challenge = self._challenge(ControlledGateOperation.TEMPLATE_REVISION_READ)
        config = self._configuration
        payload = self._invoke(
            ControlledGateOperation.TEMPLATE_REVISION_READ,
            TemplateRevisionReadRequest(
                config.template_source_identity,
                config.template_tag,
                config.resolved_template_commit,
                challenge,
            ),
            TemplateRevisionReadRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "template challenge"),
            (payload["operation"], "template-revision-readback", "template operation"),
            (payload["source_identity"], config.template_source_identity, "template source"),
            (payload["tag"], config.template_tag, "template tag"),
            (
                payload["resolved_commit"],
                config.resolved_template_commit,
                "immutable template commit",
            ),
        ):
            self._require_exact(value, expected, label)

    @staticmethod
    def _parse_yaml_scalar(value: str) -> str:
        if not value.startswith(" "):
            raise AdapterError("Copier answers scalar must be one JSON-quoted exact string")
        stripped = value[1:]
        if not stripped or stripped != stripped.strip() or not stripped.startswith('"'):
            raise AdapterError("Copier answers scalar must be one JSON-quoted exact string")
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as error:
            raise AdapterError("Copier answers contained a malformed JSON-quoted scalar") from error
        if type(parsed) is not str or json.dumps(parsed, ensure_ascii=True) != stripped:
            raise AdapterError("Copier answers scalar was not canonical JSON-quoted exact text")
        return parsed

    def _read_copier_answers(self) -> dict[str, str]:
        path = self._destination / ".copier-answers.yml"
        self._validate_checkout_filesystem()
        self._assert_fixture_path(path, require_leaf="file")
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise _safe_adapter_error(error, "Copier answers disk readback failed") from error
        if len(raw) > 65_536:
            raise AdapterError("Copier answers disk readback exceeded its bounded size")
        try:
            text = raw.decode("utf-8")
        except UnicodeError as error:
            raise AdapterError("Copier answers disk readback was not UTF-8") from error
        if redact(text) != text:
            raise AdapterError("Copier answers disk readback contained unsafe material")
        answers: dict[str, str] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if line != line.lstrip() or ":" not in line:
                raise AdapterError("Copier answers YAML was outside the bounded flat mapping")
            key, value = line.split(":", 1)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in answers:
                raise AdapterError("Copier answers YAML had an invalid or duplicate key")
            answers[key] = self._parse_yaml_scalar(value)
        return answers

    def _validate_rendered_filesystem(self) -> None:
        self._validate_checkout_filesystem()
        expected_common = {
            ".copier-answers.yml",
            ".gitignore",
            ".github/workflows/release-please.yml",
            ".release-please-manifest.json",
            "AGENTS.md",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "README.md",
            "VERSION",
            "release-please-config.json",
        }
        expected_extra = {
            "generic": set(),
            "macos-cli": {"scripts/ci-macos.sh", ".github/workflows/ci.yml"},
            "homebrew-tap": {
                "Formula/.gitkeep",
                "Casks/.gitkeep",
                ".github/workflows/tap-ci.yml",
            },
        }[self._request_snapshot[2]]
        try:
            files: set[str] = set()
            pending = [self._destination]
            while pending:
                directory = pending.pop()
                self._assert_fixture_path(directory, require_leaf="directory")
                for path in directory.iterdir():
                    relative = path.relative_to(self._destination).as_posix()
                    metadata = path.lstat()
                    if stat.S_ISLNK(metadata.st_mode):
                        raise AdapterError("rendered fixture contained a symlink")
                    if relative == ".git":
                        if not stat.S_ISDIR(metadata.st_mode):
                            raise AdapterError("modeled checkout metadata is not an exact directory")
                        continue
                    if stat.S_ISREG(metadata.st_mode):
                        files.add(relative)
                    elif stat.S_ISDIR(metadata.st_mode):
                        pending.append(path)
                    else:
                        raise AdapterError("rendered fixture contained a special entry")
        except AdapterError:
            raise
        except OSError as error:
            raise _safe_adapter_error(error, "rendered fixture filesystem readback failed") from error
        if files != expected_common | expected_extra:
            raise AdapterError("rendered fixture file matrix did not match the project kind")

    def _validate_answers(self, answers: Mapping[str, str]) -> None:
        expected = {
            "_commit": self._configuration.resolved_template_commit,
            "_src_path": self._configuration.template_source_identity,
            "project_description": self._request_snapshot[3],
            "project_kind": self._request_snapshot[2],
            "repository_name": self._origin_snapshot[1],
            "repository_owner": self._origin_snapshot[0],
            "template_revision": self._configuration.template_tag,
        }
        if type(answers) is not dict or set(answers) != set(expected):
            raise AdapterError("Copier answers disk readback had an invalid exact shape")
        for key, expected_value in expected.items():
            self._require_exact(answers[key], expected_value, f"Copier answer {key}")

    @staticmethod
    def _safe_generated_database(value: object) -> str:
        if type(value) is not str or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,127}", value) is None:
            raise AdapterError("generated Beads database identity was invalid")
        if redact(value) != value:
            raise AdapterError("generated Beads database identity was unsafe")
        return value

    def _read_fixture_regular_file(self, path: Path, *, label: str) -> tuple[bytes, os.stat_result]:
        """Read one bounded fixture leaf through no-follow directory descriptors."""
        self._assert_fixture_path(path, require_leaf="file")
        try:
            relative = path.relative_to(self._fixture_root)
        except ValueError as error:
            raise AdapterError(f"{label} escaped the controlled fixture root") from error
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if type(nofollow) is not int or type(directory) is not int:
            raise AdapterError(f"{label} requires no-follow directory descriptor support")
        descriptors: list[int] = []
        try:
            root_descriptor = os.open(self._fixture_root, os.O_RDONLY | directory | nofollow)
            descriptors.append(root_descriptor)
            root_metadata = os.fstat(root_descriptor)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise AdapterError("controlled fixture root was not an exact directory")
            parent_descriptor = root_descriptor
            for component in relative.parts[:-1]:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | directory | nofollow,
                    dir_fd=parent_descriptor,
                )
                descriptors.append(next_descriptor)
                directory_metadata = os.fstat(next_descriptor)
                if not stat.S_ISDIR(directory_metadata.st_mode):
                    raise AdapterError(f"{label} ancestor was not an exact directory")
                parent_descriptor = next_descriptor
            descriptor = os.open(
                relative.parts[-1], os.O_RDONLY | nofollow, dir_fd=parent_descriptor
            )
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise AdapterError(f"{label} was not an exact regular file")
            if opened.st_size < 0 or opened.st_size > _CONTROLLED_GATE_MAX_OUTPUT:
                raise AdapterError(f"{label} exceeded its bounded size")
            chunks: list[bytes] = []
            remaining = _CONTROLLED_GATE_MAX_OUTPUT + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            final_metadata = os.fstat(descriptor)
            if (
                len(raw) > _CONTROLLED_GATE_MAX_OUTPUT
                or (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_mode,
                    opened.st_uid,
                    opened.st_gid,
                    opened.st_size,
                    opened.st_mtime_ns,
                    opened.st_ctime_ns,
                )
                != (
                    final_metadata.st_dev,
                    final_metadata.st_ino,
                    final_metadata.st_mode,
                    final_metadata.st_uid,
                    final_metadata.st_gid,
                    final_metadata.st_size,
                    final_metadata.st_mtime_ns,
                    final_metadata.st_ctime_ns,
                )
            ):
                raise AdapterError(f"{label} changed during its secure readback")
            return raw, opened
        except AdapterError:
            raise
        except OSError as error:
            raise _safe_adapter_error(error, f"{label} secure readback failed") from error
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _read_generated_beads_metadata(self) -> dict[str, Any]:
        self._fixture_session.assert_bindings()
        raw, _ = self._fixture_session.read_pinned_regular(
            "beads", "metadata.json", label="Beads metadata disk readback"
        )
        try:
            text = raw.decode("utf-8")
        except UnicodeError as error:
            raise AdapterError("Beads metadata disk readback was not UTF-8") from error
        if redact(text) != text:
            raise AdapterError("Beads metadata disk readback contained unsafe material")
        try:
            payload = json.loads(text, object_pairs_hook=_reject_duplicate_controlled_members)
        except (json.JSONDecodeError, ValueError) as error:
            raise AdapterError("Beads metadata disk readback was malformed") from error
        expected_keys = {
            "dolt_database", "dolt_mode", "dolt_server_host", "dolt_server_port",
        }
        if type(payload) is not dict or set(payload) != expected_keys:
            raise AdapterError("Beads metadata disk readback had an invalid exact shape")
        database = self._safe_generated_database(payload["dolt_database"])
        for value, expected, label in (
            (payload["dolt_mode"], "server", "Beads metadata mode"),
            (payload["dolt_server_host"], "127.0.0.1", "Beads metadata host"),
            (payload["dolt_server_port"], 3307, "Beads metadata port"),
        ):
            self._require_exact(value, expected, label)
        return {**payload, "dolt_database": database}

    def _beads_metadata_transport_readback(self, database: str) -> None:
        challenge = self._challenge(ControlledGateOperation.BEADS_METADATA_READBACK)
        payload = self._invoke(
            ControlledGateOperation.BEADS_METADATA_READBACK,
            BeadsMetadataReadbackRequest(
                self._destination, self._request_snapshot[1], database, challenge
            ),
            BeadsMetadataReadbackRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "Beads metadata challenge"),
            (payload["operation"], "beads-generated-metadata-readback", "Beads metadata operation"),
            (payload["mode"], "server", "Beads mode"),
            (payload["host"], "127.0.0.1", "Beads host"),
            (payload["port"], 3307, "Beads port"),
            (payload["prefix"], self._request_snapshot[1], "Beads metadata prefix"),
            (payload["database"], database, "generated Beads database"),
        ):
            self._require_exact(value, expected, label)

    def _beads_prefix_readback(self) -> None:
        challenge = self._challenge(ControlledGateOperation.BEADS_PREFIX_READBACK)
        payload = self._invoke(
            ControlledGateOperation.BEADS_PREFIX_READBACK,
            BeadsPrefixReadbackRequest(self._destination, self._request_snapshot[1], challenge),
            BeadsPrefixReadbackRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "Beads prefix challenge"),
            (payload["operation"], "beads-prefix-readback", "Beads prefix operation"),
            (payload["prefix"], self._request_snapshot[1], "Beads prefix"),
        ):
            self._require_exact(value, expected, label)

    def _expected_dolt_remote(self) -> str:
        return f"git+https://github.com/{self._origin_snapshot[2]}.git"

    def _dolt_remote_readback(self, *, expected_absent: bool) -> None:
        challenge = self._challenge(ControlledGateOperation.DOLT_REMOTE_READBACK)
        expected_remote = self._expected_dolt_remote()
        payload = self._invoke(
            ControlledGateOperation.DOLT_REMOTE_READBACK,
            DoltRemoteReadbackRequest(
                self._destination, expected_remote, expected_absent, challenge
            ),
            DoltRemoteReadbackRequest,
        )
        self._require_exact(payload["challenge"], challenge, "Dolt remote challenge")
        self._require_exact(payload["operation"], "dolt-remote-readback", "Dolt remote operation")
        expected = [] if expected_absent else [{"name": "origin", "url": expected_remote}]
        self._require_exact(payload["remotes"], expected, "credential-free HTTPS Dolt remote")

    def _agent_setup_readback(self, integration: str) -> None:
        challenge = self._challenge(ControlledGateOperation.AGENT_SETUP_READBACK)
        payload = self._invoke(
            ControlledGateOperation.AGENT_SETUP_READBACK,
            AgentSetupReadbackRequest(self._destination, integration, challenge),
            AgentSetupReadbackRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "agent setup challenge"),
            (payload["operation"], "agent-setup-readback", "agent setup operation"),
            (payload["integration"], integration, "agent integration"),
            (payload["installed"], True, "agent integration installation"),
        ):
            self._require_exact(value, expected, label)

    def _integrations_readback(self) -> None:
        expected = ("claude", "codex")
        challenge = self._challenge(ControlledGateOperation.INTEGRATIONS_READBACK)
        payload = self._invoke(
            ControlledGateOperation.INTEGRATIONS_READBACK,
            IntegrationsReadbackRequest(self._destination, expected, challenge),
            IntegrationsReadbackRequest,
        )
        for value, wanted, label in (
            (payload["challenge"], challenge, "integrations challenge"),
            (payload["operation"], "agent-integrations-readback", "integrations operation"),
            (payload["integrations"], list(expected), "intended integration set"),
        ):
            self._require_exact(value, wanted, label)

    @staticmethod
    def _expected_hooks() -> tuple[str, ...]:
        return ("post-checkout", "post-merge", "pre-commit", "pre-push", "prepare-commit-msg")

    @staticmethod
    def _controlled_hook_content(name: str) -> bytes:
        if name not in ControlledG01G03Adapter._expected_hooks():
            raise AdapterError("managed hook name was outside the exact set")
        return f"#!/bin/sh\n# controlled managed hook: {name}\nexit 0\n".encode("utf-8")

    def _validate_hooks_disk_readback(self) -> None:
        self._fixture_session.assert_bindings()
        try:
            entries = self._fixture_session.list_directory("hooks")
        except ControlledFixtureError as error:
            raise _safe_adapter_error(error, "managed hooks disk readback failed") from error
        names: list[str] = []
        for name in entries:
            if not name or "/" in name or name in {".", ".."}:
                raise AdapterError("managed hooks disk readback contained an invalid leaf")
            try:
                self._fixture_session.pin_regular(f"hooks:{name}", "hooks", name)
                raw, metadata = self._fixture_session.read_pinned_regular(
                    "hooks", name, label="managed hook disk readback"
                )
            except ControlledFixtureError as error:
                raise _safe_adapter_error(error, "managed hook disk readback failed") from error
            if metadata.st_mode & 0o111 == 0:
                raise AdapterError("managed hook disk readback was not executable")
            if raw != self._controlled_hook_content(name):
                raise AdapterError("managed hook disk readback did not match trusted content")
            names.append(name)
        if tuple(sorted(names)) != self._expected_hooks():
            raise AdapterError("managed hooks disk readback did not match the exact hook set")

    def _hooks_readbacks(self) -> None:
        expected_hooks = self._expected_hooks()
        challenge = self._challenge(ControlledGateOperation.HOOKS_READBACK)
        payload = self._invoke(
            ControlledGateOperation.HOOKS_READBACK,
            HooksReadbackRequest(self._destination, ".beads/hooks", expected_hooks, challenge),
            HooksReadbackRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "hooks challenge"),
            (payload["operation"], "beads-hooks-readback", "hooks operation"),
            (payload["managed"], True, "managed hooks"),
            (payload["hook_location"], ".beads/hooks", "actual hook location"),
            (payload["hooks"], list(expected_hooks), "managed hook set"),
        ):
            self._require_exact(value, expected, label)
        self._validate_hooks_disk_readback()
        challenge = self._challenge(ControlledGateOperation.CORE_HOOKS_PATH_READBACK)
        payload = self._invoke(
            ControlledGateOperation.CORE_HOOKS_PATH_READBACK,
            CoreHooksPathReadbackRequest(self._destination, ".beads/hooks", challenge),
            CoreHooksPathReadbackRequest,
        )
        for value, expected, label in (
            (payload["challenge"], challenge, "core.hooksPath challenge"),
            (payload["operation"], "git-core-hooks-path-readback", "core.hooksPath operation"),
            (payload["hooks_path"], ".beads/hooks", "core.hooksPath"),
        ):
            self._require_exact(value, expected, label)
        self._validate_hooks_disk_readback()
        self._fixture_session.assert_bindings()

    def _authorize_mutation_attempt(
        self,
        gate: Gate,
        label: str,
    ) -> None:
        self._fixture_session.assert_bindings()
        result = self._record_attempt(gate, label)
        self._fixture_session.assert_bindings()
        if result is not True:
            raise AdapterError("controller-owned pre-execution persistence was not confirmed")

    def _complete_mutation(self, gate: Gate, label: str) -> None:
        self._fixture_session.assert_bindings()
        result = self._record_completion(gate, label)
        self._fixture_session.assert_bindings()
        if result is not True:
            raise AdapterError("controller-owned mutation completion persistence was not confirmed")

    def _invoke_mutation(
        self,
        operation: ControlledGateOperation,
        parameters: object,
        request_type: type[object],
        target: ControlledMutationTarget,
    ) -> None:
        """Bind one opaque target immediately before/after cooperative mutation."""
        self._fixture_session.assert_bindings()
        self._invoke(operation, parameters, request_type, expect_empty=True)
        self._fixture_session.assert_target_consumed(target)
        self._fixture_session.assert_bindings()

    @property
    def actual_database(self) -> str:
        if self._actual_database is None:
            raise AdapterError("controlled actual database was not proven")
        return self._actual_database

    def run_gate(self, gate: Gate) -> tuple[object | None, str]:
        try:
            configuration_digest(self._configuration)
        except (ConfigurationError, TypeError, ValueError) as error:
            raise AdapterError("controlled immutable configuration failed its sealed readback") from error
        expected_route = Path(self._configuration.destination_route)
        if expected_route != (
            Path("Projects") / ("work" if self._origin_snapshot[0] == "flexapp" else "pjbeyer") / self._origin_snapshot[1]
        ):
            raise AdapterError("controlled gate configuration does not match the exact destination route")
        destination_parts = self._destination.parts
        route_parts = expected_route.parts
        if len(destination_parts) <= len(route_parts) or destination_parts[-len(route_parts):] != route_parts:
            raise AdapterError("controlled gate destination changed from its normalized route")
        if self._configuration.repository_identity != self._origin_snapshot[2]:
            raise AdapterError("controlled gate configuration does not match repository identity")
        self._fixture_session.assert_bindings()
        if gate is Gate.PREFLIGHT:
            self._assert_destination_absent()
            self._g01_origin_snapshot = self._origin_access_read()
            self._toolchain_read()
            self._central_read()
            return (
                None,
                "controlled parser read back exact origin identity, empty references, write "
                "permission, tools, prefix availability, and fixed central probe",
            )
        if gate is Gate.CLONE:
            self._assert_destination_absent()
            current_origin = self._origin_access_read()
            if self._g01_origin_snapshot is None or current_origin != self._g01_origin_snapshot:
                raise AdapterError("origin access state changed before modeled clone")
            self._assert_destination_absent()
            attempt = "G02:modeled-clone"
            self._authorize_mutation_attempt(gate, attempt)
            self._invoke(
                ControlledGateOperation.CLONE_MUTATION,
                CloneMutationRequest(
                    self._request_snapshot[0],
                    self._origin_snapshot[2],
                    self._destination,
                ),
                CloneMutationRequest,
                expect_empty=True,
            )
            self._validate_checkout_filesystem()
            self._checkout_readback()
            self._validate_checkout_filesystem()
            self._fixture_session.pin_directory(
                "destination", ("home",) + tuple(Path(self._configuration.destination_route).parts)
            )
            self._fixture_session.assert_bindings()
            self._g02_complete = True
            self._complete_mutation(gate, attempt)
            return attempt, "controlled modeled clone completed and checkout identity was read back"
        if gate is Gate.RENDER:
            if not self._g02_complete:
                raise AdapterError("G03 requires the controlled G02 readback")
            self._checkout_readback()
            self._validate_checkout_filesystem()
            self._template_revision_read()
            self._validate_checkout_filesystem()
            attempt = "G03:modeled-render"
            self._authorize_mutation_attempt(gate, attempt)
            self._invoke(
                ControlledGateOperation.RENDER_MUTATION,
                RenderMutationRequest(
                    self._destination,
                    self._configuration.template_source_identity,
                    self._configuration.template_tag,
                    self._configuration.resolved_template_commit,
                    self._origin_snapshot[0],
                    self._origin_snapshot[1],
                    self._request_snapshot[3],
                    self._request_snapshot[2],
                ),
                RenderMutationRequest,
                expect_empty=True,
            )
            answers = self._read_copier_answers()
            self._validate_answers(answers)
            self._validate_rendered_filesystem()
            self._g03_complete = True
            self._complete_mutation(gate, attempt)
            return (
                attempt,
                "controlled modeled render completed; immutable revision, Copier answers, "
                "and project-kind file matrix were read back",
            )
        if gate is Gate.BEADS:
            if not self._g03_complete:
                raise AdapterError("G04 requires the controlled G03 readback")
            self._validate_rendered_filesystem()
            beads = self._destination / ".beads"
            self._assert_fixture_path(beads, require_leaf=None, allow_missing_leaf=True)
            try:
                beads.lstat()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise _safe_adapter_error(error, "Beads state metadata read failed") from error
            else:
                raise AdapterError("existing .beads state forbids modeled Beads initialization")
            # FR-007: re-probe the selected central service and prefix at the
            # irreversible Beads-init boundary, rather than relying on G01.
            self._central_read()
            attempt = "G04:modeled-beads-init"
            self._authorize_mutation_attempt(gate, attempt)
            target = self._fixture_session.target("beads-init", "destination")
            self._invoke_mutation(
                ControlledGateOperation.BEADS_INIT_MUTATION,
                BeadsInitRequest(target, self._request_snapshot[1], "127.0.0.1", 3307),
                BeadsInitRequest,
                target,
            )
            self._fixture_session.assert_bindings()
            metadata = self._read_generated_beads_metadata()
            database = metadata["dolt_database"]
            self._beads_metadata_transport_readback(database)
            metadata_after_transport = self._read_generated_beads_metadata()
            self._require_exact(
                metadata_after_transport["dolt_database"],
                database,
                "generated Beads database after transport readback",
            )
            self._beads_prefix_readback()
            final_metadata = self._read_generated_beads_metadata()
            final_database = final_metadata["dolt_database"]
            self._require_exact(
                final_database,
                database,
                "generated Beads database final readback",
            )
            self._fixture_session.assert_bindings()
            self._actual_database = final_database
            self._g04_complete = True
            self._complete_mutation(gate, attempt)
            return (
                attempt,
                "controlled modeled Beads init completed; exact generated metadata, legal actual "
                "database identity, prefix, server mode, and central endpoint were read back",
            )
        if gate is Gate.BEADS_REMOTE:
            if not self._g04_complete or self._actual_database is None:
                raise AdapterError("G05 requires the controlled G04 readbacks")
            metadata = self._read_generated_beads_metadata()
            self._require_exact(
                metadata["dolt_database"], self._actual_database, "authoritative metadata database"
            )
            self._beads_metadata_transport_readback(self._actual_database)
            self._dolt_remote_readback(expected_absent=True)
            remote_attempt = "G05:modeled-dolt-remote-add"
            self._authorize_mutation_attempt(gate, remote_attempt)
            remote_target = self._fixture_session.target("dolt-remote-add", "beads")
            self._invoke_mutation(
                ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION,
                DoltRemoteAddRequest(remote_target, "origin", self._expected_dolt_remote()),
                DoltRemoteAddRequest,
                remote_target,
            )
            self._dolt_remote_readback(expected_absent=False)
            self._complete_mutation(gate, remote_attempt)
            completed = [remote_attempt]
            for integration in ("claude", "codex"):
                attempt = f"G05:modeled-{integration}-setup"
                self._authorize_mutation_attempt(gate, attempt)
                agent_target = self._fixture_session.target(
                    f"agent-setup:{integration}", "beads"
                )
                self._invoke_mutation(
                    ControlledGateOperation.AGENT_SETUP_MUTATION,
                    AgentSetupMutationRequest(agent_target, integration),
                    AgentSetupMutationRequest,
                    agent_target,
                )
                self._agent_setup_readback(integration)
                self._complete_mutation(gate, attempt)
                completed.append(attempt)
            self._integrations_readback()
            hooks_attempt = "G05:modeled-hooks-install"
            self._authorize_mutation_attempt(gate, hooks_attempt)
            hooks_target = self._fixture_session.target("hooks-install", "beads")
            self._invoke_mutation(
                ControlledGateOperation.HOOKS_INSTALL_MUTATION,
                HooksInstallRequest(hooks_target, ".beads/hooks", self._expected_hooks()),
                HooksInstallRequest,
                hooks_target,
            )
            self._hooks_readbacks()
            self._complete_mutation(gate, hooks_attempt)
            completed.append(hooks_attempt)
            return (
                tuple(completed),
                "controlled credential-free HTTPS Dolt remote, exact intended agent integrations, "
                "actual .beads/hooks location, hook set, and core.hooksPath were read back",
            )
        raise AdapterError("controlled G01-G05 model received an out-of-scope gate")


_SECRET = re.compile(
    r"(?:ghp_|github_pat_|AKIA|-----BEGIN|https://[^/@\s]+@|op://[^\s]+)", re.I
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
# The command implementation below is an unverified design artifact, not an
# authorized execution path. Keep it unreachable until the runner, manifest
# compatibility, lifecycle ordering, and controlled tests pass review.
_LIVE_EXECUTION_AVAILABLE = False
_LIVE_UNAVAILABLE_MESSAGE = "supervised live execution is not yet approved or implemented"
_FORBIDDEN_ARGS = {
    "--force", "-f", "--overwrite", "--trust", "--UNSAFE", "--reinit-local",
    "--discard-remote", "--destroy-token", "--init-if-missing",
}
_FORBIDDEN_WORDS = {
    "reset", "clean", "remove", "uninstall", "delete", "drop", "destroy",
    "start", "stop", "restart", "reconfigure",
}
_ALLOWED_PROGRAMS = {"git", "dolt", "copier", "bd", "specify", "python3"}
_BEADS_ENV_KEYS = ("BEADS_DOLT_PORT", "BEADS_DOLT_DATABASE")
_COMMIT_MESSAGE = "chore: initialize project operating baseline"
# Canonical live-gate order. G03 lands via pjb-m0ap.3.1 (render allowlist) and
# G08 remains blocked by the completed G08-C prerequisite, but both occupy
# their fixed positions so the sequence guard is total, not per-slice.
_ORDERED_GATES = tuple(Gate)
_CONSTITUTION = """# Project Constitution

1. Contract before consequential automation.
2. Evidence and readback before completion claims.
3. Small, reversible changes; destructive recovery is forbidden.
4. Beads is the canonical project backlog.
5. Credentials and private workstation state never enter the repository.
"""


def _legacy_authorization_binding(
    authorization: object,
    *,
    identity: str,
    fingerprint: str,
    config: ImmutableLiveConfiguration,
    destination: Path,
) -> None:
    """Private future wiring only; the availability gate currently precedes it."""
    if not config.matches_destination(destination):
        raise AdapterError("live configuration does not bind the exact canonical destination")
    try:
        assert_live_authorized(
            authorization,
            named_identity=identity,
            request_fingerprint=fingerprint,
            configuration=config,
            starting_gate=Gate.PREFLIGHT,
        )
    except ValueError as error:
        raise AdapterError(str(error)) from error


def validate_command_spec(spec: CommandSpec, coverage_script: Path | None = None) -> None:
    """Reject shell, destructive, force, service-control, and unpinned commands."""
    if not spec.argv or spec.argv[0] not in _ALLOWED_PROGRAMS:
        raise AdapterError("command program is outside the provisioning allowlist")
    if any(not isinstance(arg, str) or "\x00" in arg for arg in spec.argv):
        raise AdapterError("command argv contains an invalid argument")
    if any(_SECRET.search(arg) for arg in spec.argv):
        raise AdapterError("command argv contains secret-shaped material")
    lowered = [arg.lower() for arg in spec.argv]
    if any(arg in _FORBIDDEN_ARGS or arg.startswith("--force=") for arg in lowered):
        raise AdapterError("force, overwrite, reinitialization, and unsafe flags are forbidden")
    if any(word in _FORBIDDEN_WORDS for word in lowered[1:]):
        raise AdapterError("destructive or service-control command is forbidden")
    for arg in spec.argv:
        if arg.startswith(("http://", "https://")):
            parsed = urlparse(arg)
            if parsed.username or parsed.password:
                raise AdapterError("command URL must not contain credential userinfo")
    if spec.argv[0] == "git" and "push" in lowered and any(arg.startswith("+") for arg in spec.argv):
        raise AdapterError("forced Git refspecs are forbidden")
    if spec.argv[0] == "dolt":
        query = spec.argv[-1].strip().lower()
        if "sql" not in lowered or not query.startswith("select ") or any(
            token in query for token in (" insert ", " update ", " delete ", " drop ", " alter ")
        ):
            raise AdapterError("Dolt preflight is restricted to a SELECT probe")
    if spec.argv[0] == "python3":
        if "-c" in spec.argv or coverage_script is None or len(spec.argv) != 2:
            raise AdapterError("Python execution is restricted to the approved coverage audit")
        if Path(spec.argv[1]).resolve() != coverage_script.resolve():
            raise AdapterError("Python command is not the approved coverage audit")
    if spec.beads != (spec.argv[0] == "bd"):
        raise AdapterError("Beads command classification is inconsistent")
    if spec.beads and any(key in spec.env for key in _BEADS_ENV_KEYS):
        raise AdapterError("stale Beads Dolt overrides must be absent from Beads commands")


def _parse_beads_prefix_raw(raw: str) -> str:
    """Parse ``bd config get issue_prefix --json`` into its scalar value.

    The command emits a JSON object ``{"key","schema_version","value"}``, not a
    bare scalar. Return only the ``value`` field; anything else is a mismatch.
    """
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError("Beads issue prefix readback was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise AdapterError("Beads issue prefix readback was not a JSON object")
    if payload.get("key") != "issue_prefix":
        raise AdapterError("Beads issue prefix readback carried the wrong config key")
    value = payload.get("value")
    if not isinstance(value, str) or not value:
        raise AdapterError("Beads issue prefix readback omitted a plain-string value")
    return value


def _parse_dolt_remotes_raw(raw: str) -> list[dict[str, str]]:
    """Parse ``bd dolt remote list --json`` into a list of {name, url} records.

    The command emits ``[{"name","url","sql_url","status",...}]``. Return only the
    exact ``name``/``url`` pair per record; extra or missing keys are a mismatch.
    """
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError("Dolt remote readback was not valid JSON") from exc
    if not isinstance(payload, list):
        raise AdapterError("Dolt remote readback was not a JSON array")
    remotes: list[dict[str, str]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise AdapterError("Dolt remote readback contained a non-object entry")
        name = entry.get("name")
        url = entry.get("url")
        if not isinstance(name, str) or not isinstance(url, str):
            raise AdapterError("Dolt remote readback omitted a name or url")
        remotes.append({"name": name, "url": url})
    return remotes


def _parse_beads_hooks_raw(raw: str) -> dict[str, bool]:
    """Parse ``bd hooks list --json`` into a {hook_name: Installed} map.

    The command emits ``{"hooks":[{"Name","Installed","Version","IsShim",
    "Outdated"},...]}`` with capital keys. Return name -> installed; anything
    outside the approved hook set is still surfaced so the caller can reject it.
    """
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError("Beads hooks readback was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise AdapterError("Beads hooks readback was not a JSON object")
    entries = payload.get("hooks")
    if not isinstance(entries, list):
        raise AdapterError("Beads hooks readback omitted a hooks array")
    status: dict[str, bool] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise AdapterError("Beads hooks readback contained a non-object entry")
        name = entry.get("Name")
        installed = entry.get("Installed")
        if not isinstance(name, str) or not isinstance(installed, bool):
            raise AdapterError("Beads hooks readback omitted a name or Installed flag")
        status[name] = installed
    return status


class LiveAdapter:
    """Rejected G01-G11 draft; unavailable pending supervised replacement.

    ``_ControlledLiveExecutor`` is the future internal execution seam, but this
    quarantined draft is intentionally not wired to or allowed to invoke it.
    """

    _controlled_executor_type = _ControlledLiveExecutor
    is_simulation = False

    def __init__(
        self,
        runner: SafeCommandRunner | None = None,
        config: LiveAdapterConfig | None = None,
    ) -> None:
        self.runner = runner
        self.config = config
        self.request: ProvisioningRequest | None = None
        self.origin: ParsedOrigin | None = None
        self.destination: Path | None = None
        self.fingerprint: str | None = None
        self._prepared = False
        self._metadata: dict[str, Any] | None = None
        self._manifest_reservation: tuple[str, str, str] | None = None
        self._manifest_appended: tuple[str, str, str] | None = None
        self._evidence: dict[Gate, str] = {}
        self._issues: dict[str, dict[str, Any]] = {}
        self._git_head: str | None = None
        self._completed_gates: set[Gate] = set()

    @staticmethod
    def _require_available() -> None:
        if not _LIVE_EXECUTION_AVAILABLE:
            raise AdapterError(_LIVE_UNAVAILABLE_MESSAGE)

    @property
    def template_revision(self) -> str:
        self._require_available()
        raise AdapterError(_LIVE_UNAVAILABLE_MESSAGE)

    def prepare(
        self,
        request: ProvisioningRequest,
        origin: ParsedOrigin,
        destination: Path,
        fingerprint: str,
    ) -> None:
        """Fail closed before consulting runner, config, or command paths."""
        self._require_available()
        if self.runner is None or getattr(self.runner, "is_safe_command_runner", False) is not True:
            raise AdapterError("live command runner was not safely injected")
        if type(self.config) is not ImmutableLiveConfiguration:
            raise AdapterError("live adapter requires the exact immutable configuration type")
        _legacy_authorization_binding(
            request.live_authorization,
            identity=origin.identity,
            fingerprint=fingerprint,
            config=self.config,
            destination=destination,
        )
        self._validate_config()
        if destination != destination.resolve(strict=False) or not destination.is_absolute():
            raise AdapterError("destination must be an exact canonical absolute path")
        self.request = request
        self.origin = origin
        self.destination = destination
        self.fingerprint = fingerprint
        self._prepared = True

    def _validate_config(self) -> None:
        if type(self.config) is not ImmutableLiveConfiguration:
            raise AdapterError("live adapter requires the exact immutable configuration type")
        try:
            self.config.__post_init__()
        except ValueError as error:
            raise AdapterError(f"invalid immutable live configuration: {error}") from error

    def _context(self) -> tuple[ProvisioningRequest, ParsedOrigin, Path, object]:
        self._require_available()
        if not self._prepared or not all((self.request, self.origin, self.destination, self.config)):
            raise AdapterError("live adapter is not authorized and prepared")
        # The retained draft's gate bodies below still reference the removed
        # ``LiveAdapterConfig`` surface (command_env, coverage_script,
        # template_source, manifest_path, expected_backup_user/group, and
        # extension_pins/preset_pins). They are not a usable redesign reference
        # against the current ``ImmutableLiveConfiguration``; fail closed with the
        # controlled unavailable error rather than an AttributeError on the first
        # dereferenced field.
        raise AdapterError(_LIVE_UNAVAILABLE_MESSAGE)

    def _production_executor(self):
        """Return a production executor bound to the approved project home.

        The executor is constructed from the closure-held transport capability
        (not importable) and admits only the exact production transport type.
        This is the only path by which a live gate body can reach a subprocess.
        """
        from .models import _approved_project_home

        return make_production_executor(approved_home=_approved_project_home())

    def _env(self, *, beads: bool = False) -> Mapping[str, str]:
        _, _, _, config = self._context()
        env = dict(config.command_env)
        if beads:
            for key in _BEADS_ENV_KEYS:
                env.pop(key, None)
        return MappingProxyType(env)

    def _execute(
        self,
        operation: str,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: Path | None = None,
        mutating: bool = False,
    ) -> CommandResult:
        _, _, _, config = self._context()
        args = tuple(argv)
        beads = bool(args and args[0] == "bd")
        spec = CommandSpec(operation, args, cwd, self._env(beads=beads), 60, mutating, beads)
        validate_command_spec(spec, config.coverage_script)
        assert self.runner is not None
        result = self.runner.run(spec)
        if not isinstance(result, CommandResult):
            raise AdapterError(f"{operation} runner returned an unstructured result")
        if (
            result.operation != spec.operation
            or result.argv != spec.argv
            or result.cwd != spec.cwd
        ):
            raise AdapterError(f"{operation} runner result does not match the requested command")
        if result.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", result.stderr or result.stdout or "no diagnostic")
            raise AdapterError(f"{operation} failed with exit {result.returncode}: {detail[:500]}")
        if not isinstance(result.data, Mapping):
            raise AdapterError(f"{operation} omitted structured readback data")
        return result

    @staticmethod
    def _require(data: Mapping[str, Any], key: str, expected: Any, operation: str) -> None:
        if data.get(key) != expected:
            raise AdapterError(
                f"{operation} readback mismatch for {key}: expected {expected!r}, got {data.get(key)!r}"
            )

    def _origin_probe(self, operation: str) -> None:
        request, origin, _, _ = self._context()
        result = self._execute(
            operation,
            ["git", "ls-remote", "--symref", request.origin_url, "HEAD"],
        )
        self._require(result.data, "identity", origin.identity, operation)
        self._require(result.data, "remote_url", request.origin_url, operation)
        self._require(result.data, "empty", True, operation)
        self._require(result.data, "writable", True, operation)

    def _repository_readback(self, operation: str, *, empty: bool | None = None) -> Mapping[str, Any]:
        request, origin, destination, _ = self._context()
        result = self._execute(
            operation,
            ["git", "-C", str(destination), "status", "--porcelain=v1", "--branch"],
            cwd=destination,
        )
        self._require(result.data, "identity", origin.identity, operation)
        self._require(result.data, "origin_url", request.origin_url, operation)
        self._require(result.data, "root", str(destination), operation)
        self._require(result.data, "branch", "main", operation)
        if empty is not None:
            self._require(result.data, "empty_checkout", empty, operation)
        return result.data

    def _assert_destination_absent(self) -> None:
        _, _, destination, _ = self._context()
        if destination.exists():
            raise AdapterError("destination changed or became occupied before clone")

    def _assert_manifest_available(self, *, require_absent: bool) -> tuple[dict[str, Any], str]:
        request, _, destination, config = self._context()
        metadata_database = self._metadata["dolt_database"] if require_absent and self._metadata else None
        try:
            manifest, digest = load_manifest(config.manifest_path)
            records = manifest["repositories"]
            validate_records(records)
        except (OSError, KeyError, ManifestError) as exc:
            raise AdapterError("managed-project manifest is invalid") from exc
        if require_absent and any(
            item["path"] == str(destination)
            or item.get("prefix") == request.beads_prefix
            or item["database"] == metadata_database
            for item in records
        ):
            raise AdapterError(
                "destination path, Beads prefix, or metadata database already exists in the manifest"
            )
        return manifest, digest

    def run_gate(self, gate: Gate) -> None:
        self._require_available()
        self._assert_gate_reachable(gate)
        dispatch = {
            Gate.PREFLIGHT: self._g01,
            Gate.CLONE: self._g02,
            Gate.RENDER: self._g03,
            Gate.BEADS: self._g04,
            Gate.BEADS_REMOTE: self._g05,
            Gate.MANIFEST: self._g06,
            Gate.BACKUP: self._g07,
            Gate.SPECKIT: self._g08,
            Gate.BOOTSTRAP: self._g09,
            Gate.COMMIT: self._g10,
            Gate.PUSH: self._g11,
        }
        handler = dispatch[gate]
        handler()
        self._completed_gates.add(gate)

    def _assert_gate_reachable(self, gate: Gate) -> None:
        """Fail closed unless every predecessor gate has completed its readback.

        Enforces the .3.6 ordering criterion: a gate is reachable only after
        each earlier gate's readback is asserted, so no gate may run out of
        sequence and none may pass on a bare directory-exists claim.
        """
        if gate not in _ORDERED_GATES:
            raise AdapterError(f"{gate.value} is not a recognized ordered gate")
        index = _ORDERED_GATES.index(gate)
        for predecessor in _ORDERED_GATES[:index]:
            if predecessor not in self._completed_gates:
                raise AdapterError(
                    f"{gate.value} is unreachable before {predecessor.value} completes its readback"
                )

    def gate_evidence(self, gate: Gate) -> str:
        self._require_available()
        return self._evidence.get(gate, f"{gate} passed mandatory structured readback")

    def _g01(self) -> None:
        request, _, _, _ = self._context()
        self._assert_destination_absent()
        self._assert_manifest_available(require_absent=True)
        self._origin_probe("g01.origin.read")
        result = self._execute(
            "g01.dolt.read",
            [
                "dolt", "--host", "127.0.0.1", "--port", "3307", "sql",
                "-r", "json", "-q", "SELECT 1 AS ok;",
            ],
        )
        for key, expected in (
            ("host", "127.0.0.1"), ("port", 3307), ("reachable", True),
            ("sole_approved_service", True),
        ):
            self._require(result.data, key, expected, "g01.dolt.read")
        self._require(result.data, "prefix_available", request.beads_prefix, "g01.dolt.read")
        self._evidence[Gate.PREFLIGHT] = (
            "exact origin, empty/writable route, canonical absent destination, prefix, tools, "
            "manifest, and approved 127.0.0.1:3307 service read back"
        )

    def _g02(self) -> None:
        request, origin, destination, _ = self._context()
        self._assert_destination_absent()
        # Re-read origin identity immediately before the irreversible clone
        # boundary (FR-007): a changed/ambiguous origin stops the run.
        self._origin_probe("g02.origin.preclone")
        # Clone through the production executor (credential-scoped, inode-bound
        # no-follow cwd). The executor builds and validates the exact argv and
        # the transport re-validates before spawn; no credential value enters
        # argv/env.
        executor = self._production_executor()
        clone = executor.execute(
            LiveOperation.GIT_CLONE,
            GitCloneRequest(request.origin_url, destination),
        )
        if clone.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", clone.stderr or clone.stdout or "no diagnostic")
            raise AdapterError(f"g02.clone failed with exit {clone.returncode}: {detail[:500]}")
        if not destination.is_dir() or not (destination / ".git").exists():
            raise AdapterError("clone command did not create the exact primary checkout")
        # Verify the checkout is on primary main and the remote origin resolves
        # to the exact supplied owner/repository (FR-007 identity readback).
        remote = executor.execute(
            LiveOperation.GIT_REMOTE_READBACK,
            GitRemoteReadbackRequest(destination),
        )
        if remote.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", remote.stderr or remote.stdout or "no diagnostic")
            raise AdapterError(f"g02.remote.read failed with exit {remote.returncode}: {detail[:500]}")
        remote_url = remote.stdout.strip()
        if remote_url != request.origin_url:
            raise AdapterError("clone remote origin does not match the supplied origin")
        self._repository_readback("g02.repository.read", empty=True)
        self._evidence[Gate.CLONE] = "primary main checkout and exact origin/destination identity read back"

    def _g03(self) -> None:
        request, origin, destination, config = self._context()
        self._repository_readback("g03.repository.pre-render", empty=True)
        # Resolve the approved template tag to its immutable commit in the
        # runtime-derived checkout (never a hard-coded path).
        from .models import _approved_template_source

        template_source = _approved_template_source()
        executor = self._production_executor()
        revision = executor.execute(
            LiveOperation.GIT_TEMPLATE_REVISION,
            GitTemplateRevisionRequest(template_source, config.template_tag),
        )
        if revision.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", revision.stderr or revision.stdout or "no diagnostic")
            raise AdapterError(f"g03.template.revision failed with exit {revision.returncode}: {detail[:500]}")
        resolved_commit = revision.stdout.strip()
        if resolved_commit != config.resolved_template_commit:
            raise AdapterError("template tag does not resolve to the approved immutable commit")
        answers = (
            ("repository_owner", origin.owner),
            ("repository_name", origin.repository),
            ("project_description", request.description),
            ("project_kind", request.project_kind),
            ("template_revision", config.template_tag),
        )
        rendered = executor.execute(
            LiveOperation.COPIER_RENDER,
            CopierRenderRequest(template_source, destination, config.template_tag, answers),
        )
        if rendered.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", rendered.stderr or rendered.stdout or "no diagnostic")
            raise AdapterError(f"g03.render failed with exit {rendered.returncode}: {detail[:500]}")
        # Render readback: the rendered checkout must exist and the immutable
        # revision must be recorded (FR-008/FR-009). The full matrix readback is
        # performed by the render validator in the closeout gate (G10).
        if not destination.is_dir():
            raise AdapterError("render did not produce the destination checkout")
        self._evidence[Gate.RENDER] = (
            f"approved Copier {config.template_tag}@{config.resolved_template_commit} rendered and revision read back"
        )

    def _g04(self) -> None:
        request, _, destination, _ = self._context()
        self._repository_readback("g04.repository.pre-init")
        if (destination / ".beads").exists():
            raise AdapterError("existing .beads state forbids Beads initialization")
        executor = self._production_executor()
        init = executor.execute(
            LiveOperation.BEADS_INIT,
            BeadsInitRequest(destination, request.beads_prefix),
        )
        if init.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", init.stderr or init.stdout or "no diagnostic")
            raise AdapterError(f"g04.init failed with exit {init.returncode}: {detail[:500]}")
        metadata = self.read_metadata()
        prefix = executor.execute(
            LiveOperation.BEADS_PREFIX_READ,
            BeadsPrefixReadRequest(destination),
        )
        if prefix.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", prefix.stderr or prefix.stdout or "no diagnostic")
            raise AdapterError(f"g04.prefix.read failed with exit {prefix.returncode}: {detail[:500]}")
        # The prefix readback is a JSON object; parse its value and verify it
        # equals the requested prefix (never substitute the prefix for the read
        # value, never accept a partial string match).
        prefix_value = _parse_beads_prefix_raw(prefix.stdout)
        if prefix_value != request.beads_prefix:
            raise AdapterError("Beads issue prefix readback does not match the requested prefix")
        self._metadata = metadata
        self._evidence[Gate.BEADS] = (
            f"server metadata read from .beads/metadata.json at 127.0.0.1:3307; "
            f"exact prefix and database {metadata['dolt_database']} read back"
        )

    def _expected_dolt_remote(self) -> str:
        _, origin, _, _ = self._context()
        return f"git+https://github.com/{origin.identity}.git"

    def _g05(self) -> None:
        _, _, destination, _ = self._context()
        self.read_metadata()
        expected_remote = self._expected_dolt_remote()
        executor = self._production_executor()
        before = executor.execute(
            LiveOperation.DOLT_REMOTE_LIST,
            DoltRemoteListRequest(destination),
        )
        if before.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", before.stderr or before.stdout or "no diagnostic")
            raise AdapterError(f"g05.remote.before failed with exit {before.returncode}: {detail[:500]}")
        # The before-state must show no remotes (exact empty list).
        before_remotes = _parse_dolt_remotes_raw(before.stdout)
        if before_remotes != []:
            raise AdapterError("g05.remote.before must show no existing Dolt remotes")
        add = executor.execute(
            LiveOperation.DOLT_REMOTE_ADD,
            DoltRemoteAddRequest(destination, expected_remote),
        )
        if add.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", add.stderr or add.stdout or "no diagnostic")
            raise AdapterError(f"g05.remote.add failed with exit {add.returncode}: {detail[:500]}")
        after = executor.execute(
            LiveOperation.DOLT_REMOTE_LIST,
            DoltRemoteListRequest(destination),
        )
        if after.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", after.stderr or after.stdout or "no diagnostic")
            raise AdapterError(f"g05.remote.read failed with exit {after.returncode}: {detail[:500]}")
        after_remotes = _parse_dolt_remotes_raw(after.stdout)
        if after_remotes != [{"name": "origin", "url": expected_remote}]:
            raise AdapterError("g05.remote.read did not show the exact added origin remote")
        for integration in ("claude", "codex"):
            setup = executor.execute(
                LiveOperation.BEADS_SETUP,
                BeadsSetupRequest(destination, integration, check=False),
            )
            if setup.returncode != 0:
                detail = _SECRET.sub("[REDACTED]", setup.stderr or setup.stdout or "no diagnostic")
                raise AdapterError(f"g05.setup.{integration} failed with exit {setup.returncode}: {detail[:500]}")
            check = executor.execute(
                LiveOperation.BEADS_SETUP_CHECK,
                BeadsSetupRequest(destination, integration, check=True),
            )
            if check.returncode != 0:
                detail = _SECRET.sub("[REDACTED]", check.stderr or check.stdout or "no diagnostic")
                raise AdapterError(f"g05.setup.{integration}.read failed with exit {check.returncode}: {detail[:500]}")
        install = executor.execute(
            LiveOperation.BEADS_HOOKS_INSTALL,
            BeadsHooksInstallRequest(destination),
        )
        if install.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", install.stderr or install.stdout or "no diagnostic")
            raise AdapterError(f"g05.hooks.install failed with exit {install.returncode}: {detail[:500]}")
        hooks = executor.execute(
            LiveOperation.BEADS_HOOKS_LIST,
            BeadsHooksListRequest(destination),
        )
        if hooks.returncode != 0:
            detail = _SECRET.sub("[REDACTED]", hooks.stderr or hooks.stdout or "no diagnostic")
            raise AdapterError(f"g05.hooks.read failed with exit {hooks.returncode}: {detail[:500]}")
        hook_status = _parse_beads_hooks_raw(hooks.stdout)
        expected_hooks = ("post-checkout", "post-merge", "pre-commit", "pre-push", "prepare-commit-msg")
        if tuple(sorted(hook_status)) != expected_hooks:
            raise AdapterError("g05.hooks.read did not match the exact managed hook set")
        for hook in expected_hooks:
            if hook_status[hook] is not True:
                raise AdapterError(f"g05.hooks.read showed managed hook {hook} as not installed")
        self._evidence[Gate.BEADS_REMOTE] = (
            "credential-free HTTPS Dolt origin, Claude/Codex setup, and exact managed hooks read back"
        )

    def _g06(self) -> None:
        request, _, destination, _ = self._context()
        self._manifest_reservation = None
        self._manifest_appended = None
        metadata = self.read_metadata()
        self._metadata = dict(metadata)
        self._assert_manifest_available(require_absent=True)
        self._manifest_reservation = (
            str(destination), request.beads_prefix, metadata["dolt_database"]
        )
        self._evidence[Gate.MANIFEST] = (
            "manifest reservation revalidated; append and exact readback remain required"
        )

    def append_manifest(self, record: dict[str, Any]) -> None:
        self._require_available()
        request, _, destination, config = self._context()
        metadata = self.read_metadata()
        exact = {
            "path": str(destination),
            "prefix": request.beads_prefix,
            "database": metadata["dolt_database"],
        }
        reserved = (exact["path"], exact["prefix"], exact["database"])
        if self._manifest_reservation != reserved:
            raise AdapterError("G06 manifest reservation is required before append")
        if self._manifest_appended is not None:
            raise AdapterError("G06 manifest record was already appended; retry is forbidden")
        for key, expected in exact.items():
            if record.get(key) != expected:
                raise AdapterError(f"manifest record {key} does not match authoritative readback")
        try:
            # Recheck under the append helper's lock immediately before its
            # conflict-safe atomic addition. Existing records use compatibility
            # validation; this candidate uses strict new-enrollment validation.
            committed = append_record(config.manifest_path, record)
            manifest = committed.manifest
            validate_records(manifest["repositories"])
        except (OSError, KeyError, ManifestError) as exc:
            raise AdapterError("manifest compare-and-append failed") from exc
        expected_records = [
            item for item in manifest["repositories"]
            if item["path"] != exact["path"]
            and item.get("prefix") != exact["prefix"]
            and item["database"] != exact["database"]
        ]
        if (
            committed.record != record
            or manifest["repositories"] != [*expected_records, record]
            or len(expected_records) + 1 != len(manifest["repositories"])
            or hashlib.sha256(committed.raw).hexdigest() != committed.digest
        ):
            raise AdapterError("manifest locked readback was not the exact committed append")
        self._manifest_appended = reserved
        self._evidence[Gate.MANIFEST] = (
            "one exact path/prefix/metadata-database record appended, reparsed, and globally unique; "
            "coverage is deferred until G07 validates backup state"
        )

    def _validate_backup_ownership(self, root: Path, user: str, group: str) -> None:
        try:
            uid = pwd.getpwnam(user).pw_uid
            gid = grp.getgrnam(group).gr_gid
        except KeyError as exc:
            raise AdapterError("required backup owner or group is unavailable") from exc
        try:
            root_result = root.lstat()
            paths: list[Path] = [root]
            for directory, names, files in os.walk(root, topdown=True, followlinks=False):
                current = Path(directory)
                paths.extend(current / name for name in [*names, *files])
        except OSError as exc:
            raise AdapterError("backup ownership metadata read failed") from exc
        if stat.S_ISLNK(root_result.st_mode) or not stat.S_ISDIR(root_result.st_mode):
            raise AdapterError("backup ownership root is unsafe")
        for path in paths:
            try:
                stat_result = path.lstat()
            except OSError as exc:
                raise AdapterError("backup ownership metadata read failed") from exc
            if stat.S_ISLNK(stat_result.st_mode):
                raise AdapterError("backup ownership tree contains unsafe entry")
            if stat_result.st_uid != uid or stat_result.st_gid != gid:
                raise AdapterError(f"backup ownership mismatch at {path.name}")

    @staticmethod
    def _entry_exists(path: Path) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise AdapterError("backup precondition metadata read failed") from exc
        return True

    @staticmethod
    def _read_sidecar(sidecar: Path, root: Path, uid: int, gid: int) -> None:
        """Read once through a no-follow descriptor, then verify stable identity."""
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            before = sidecar.lstat()
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise AdapterError("backup sidecar must be a regular file, not a symlink")
            if stat.S_IMODE(before.st_mode) != 0o600:
                raise AdapterError("backup sidecar mode must be 0600")
            if before.st_uid != uid or before.st_gid != gid:
                raise AdapterError("backup sidecar ownership mismatch")
            descriptor = os.open(sidecar, flags)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise AdapterError("backup sidecar must be a regular file, not a symlink")
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise AdapterError("backup sidecar changed during readback")
                raw = os.read(descriptor, 1_048_577)
                if len(raw) > 1_048_576:
                    raise AdapterError("backup sidecar readback failed")
                after_open = os.fstat(descriptor)
                try:
                    sidecar_data = json.loads(raw.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise AdapterError("backup sidecar readback failed") from exc
            finally:
                os.close(descriptor)
            after_path = sidecar.lstat()
        except AdapterError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AdapterError("backup sidecar readback failed") from exc
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns")
        if any(
            getattr(before, field) != getattr(opened, field)
            or getattr(opened, field) != getattr(after_open, field)
            for field in stable_fields
        ) or any(
            getattr(after_open, field) != getattr(after_path, field)
            for field in stable_fields
            if field != "st_mtime_ns"
        ):
            raise AdapterError("backup sidecar changed during readback")
        if not isinstance(sidecar_data, dict):
            raise AdapterError("backup sidecar must be a JSON object")
        expected_url = root.resolve(strict=False).as_uri()
        if sidecar_data.get("backup_url") != expected_url:
            raise AdapterError("backup sidecar does not point to the exact repository backup root")

    def _g07(self) -> None:
        request, _, destination, config = self._context()
        metadata = self.read_metadata()
        expected_enrollment = (
            str(destination), request.beads_prefix, metadata["dolt_database"]
        )
        if self._manifest_appended != expected_enrollment:
            raise AdapterError("G07 backup initialization requires completed G06 append and readback")
        backup_root = destination / ".beads" / "backup"
        sidecar = destination / ".beads" / "dolt-backup.json"
        try:
            assert_safe_backup_root(destination, backup_root)
        except BackupError as exc:
            raise AdapterError(str(exc)) from exc
        if self._entry_exists(backup_root) or self._entry_exists(sidecar):
            raise AdapterError("existing backup root or sidecar forbids backup initialization")
        # Recheck immediately before the first mutation; later mutation boundaries
        # repeat the same lexical no-symlink containment assertion.
        try:
            assert_safe_backup_root(destination, backup_root)
        except BackupError as exc:
            raise AdapterError(str(exc)) from exc
        self._execute(
            "g07.backup.init",
            ["bd", "backup", "init", str(backup_root)],
            cwd=destination,
            mutating=True,
        )
        try:
            assert_safe_backup_root(destination, backup_root)
        except BackupError as exc:
            raise AdapterError(f"backup root failed post-initialization safety check: {exc}") from exc
        # Native sync is a second mutation and must not rely on the previous
        # containment observation.
        try:
            assert_safe_backup_root(destination, backup_root)
        except BackupError as exc:
            raise AdapterError(f"backup root failed pre-synchronization safety check: {exc}") from exc
        self._execute(
            "g07.backup.sync", ["bd", "backup", "sync"], cwd=destination, mutating=True
        )
        try:
            assert_safe_backup_root(destination, backup_root)
        except BackupError as exc:
            raise AdapterError(f"backup root failed post-synchronization safety check: {exc}") from exc
        status = self._execute(
            "g07.backup.read", ["bd", "backup", "status", "--json"], cwd=destination
        )
        for key, expected in (
            ("backup_root", str(backup_root)), ("synchronized", True), ("fresh", True),
        ):
            self._require(status.data, key, expected, "g07.backup.read")
        try:
            uid = pwd.getpwnam(config.expected_backup_user).pw_uid
            gid = grp.getgrnam(config.expected_backup_group).gr_gid
        except KeyError as exc:
            raise AdapterError("required backup owner or group is unavailable") from exc
        self._read_sidecar(sidecar, backup_root, uid, gid)
        try:
            validate_backup_tree(backup_root)
            self._validate_backup_ownership(
                backup_root, config.expected_backup_user, config.expected_backup_group
            )
        except AdapterError:
            raise
        except (OSError, BackupError) as exc:
            raise AdapterError("backup tree validation failed") from exc
        try:
            # Repeat the full containment -> tree -> ownership -> sidecar sequence
            # immediately before coverage. This narrows, but cannot eliminate,
            # concurrent replacement races without descriptor-relative traversal.
            assert_safe_backup_root(destination, backup_root)
            validate_backup_tree(backup_root)
            self._validate_backup_ownership(
                backup_root, config.expected_backup_user, config.expected_backup_group
            )
            self._read_sidecar(sidecar, backup_root, uid, gid)
            assert_safe_backup_root(destination, backup_root)
        except AdapterError:
            raise
        except (OSError, BackupError) as exc:
            raise AdapterError("backup pre-coverage tree revalidation failed") from exc
        coverage = self._execute(
            "g07.coverage", ["python3", str(config.coverage_script)], cwd=config.coverage_script.parent
        )
        self._require(coverage.data, "covered_path", str(destination), "g07.coverage")
        self._require(
            coverage.data, "covered_database", metadata["dolt_database"], "g07.coverage"
        )
        self._require(coverage.data, "findings", [], "g07.coverage")
        self._evidence[Gate.BACKUP] = (
            "native backup sidecar, exact root, synchronization, freshness, ownership, modes, and tree "
            "safety read back before terminal manifest coverage confirmation"
        )

    def _g08(self) -> None:
        _, _, destination, config = self._context()
        if (destination / ".specify").exists():
            raise AdapterError("existing .specify state forbids SpecKit initialization")
        self._execute("g08.init", init_command(), cwd=destination, mutating=True)
        for name in COMPATIBLE_EXTENSIONS:
            pin = config.extension_pins[name]
            self._execute(
                f"g08.extension.add.{name}",
                ["specify", "extension", "add", name, "--from", pin.source],
                cwd=destination,
                mutating=True,
            )
        for name in COMPATIBLE_PRESETS:
            pin = config.preset_pins[name]
            self._execute(
                f"g08.preset.add.{name}",
                ["specify", "preset", "add", name, "--from", pin.source],
                cwd=destination,
                mutating=True,
            )
        constitution = destination / ".specify" / "memory" / "constitution.md"
        constitution.parent.mkdir(parents=True, exist_ok=True)
        constitution.write_text(_CONSTITUTION, encoding="utf-8")
        integration = self._execute(
            "g08.integration.read",
            ["specify", "integration", "status", "--json"],
            cwd=destination,
        )
        self._require(integration.data, "integration", "hermes", "g08.integration.read")
        extensions = self._execute(
            "g08.extensions.read", ["specify", "extension", "list"], cwd=destination
        )
        expected_extensions = [
            {
                "name": name,
                "source": config.extension_pins[name].source,
                "revision": config.extension_pins[name].revision,
                "enabled": True,
            }
            for name in COMPATIBLE_EXTENSIONS
        ]
        self._require(extensions.data, "extensions", expected_extensions, "g08.extensions.read")
        presets = self._execute(
            "g08.presets.read", ["specify", "preset", "list"], cwd=destination
        )
        expected_presets = [
            {
                "name": name,
                "source": config.preset_pins[name].source,
                "revision": config.preset_pins[name].revision,
                "enabled": True,
            }
            for name in COMPATIBLE_PRESETS
        ]
        self._require(presets.data, "presets", expected_presets, "g08.presets.read")
        installed = {item["name"] for item in expected_extensions + expected_presets}
        if installed & set(EXCLUDED):
            raise AdapterError("excluded SpecKit component was installed")
        self._evidence[Gate.SPECKIT] = (
            "Hermes-primary CLI init, exact immutable extension/preset revisions, exclusions, and constitution read back"
        )

    def _g09(self) -> None:
        metadata = self.read_metadata()
        self._evidence[Gate.BOOTSTRAP] = (
            f"bootstrap tracker bound to authoritative database {metadata['dolt_database']} before duplicate search"
        )

    @staticmethod
    def _issue_from_data(data: Mapping[str, Any], key: str, operation: str) -> dict[str, Any]:
        issue = data.get(key)
        if not isinstance(issue, Mapping):
            raise AdapterError(f"{operation} omitted structured issue readback")
        return dict(issue)

    def create_issue(self, marker: str, title: str) -> dict[str, Any]:
        self._require_available()
        _, _, destination, _ = self._context()
        metadata = self.read_metadata()
        external_ref = f"project-bootstrap:{marker}"
        search_operation = f"g09.issue.search.{marker}"
        search = self._execute(
            search_operation,
            ["bd", "search", "--external-contains", external_ref, "--status", "all", "--json"],
            cwd=destination,
        )
        matches = search.data.get("issues")
        if not isinstance(matches, list) or len(matches) > 1:
            raise AdapterError(f"{search_operation} returned ambiguous duplicate matches")
        if matches:
            issue = dict(matches[0])
        else:
            create_operation = f"g09.issue.create.{marker}"
            created = self._execute(
                create_operation,
                [
                    "bd", "create", title, "--type", "task", "--external-ref", external_ref,
                    "--description", f"Bootstrap marker: {external_ref}", "--json",
                ],
                cwd=destination,
                mutating=True,
            )
            issue = self._issue_from_data(created.data, "issue", create_operation)
        issue_id = issue.get("id")
        if not isinstance(issue_id, str) or not issue_id:
            raise AdapterError("bootstrap issue creation/search omitted a stable issue id")
        read_operation = f"g09.issue.read.{marker}"
        readback = self._execute(
            read_operation, ["bd", "show", issue_id, "--json"], cwd=destination
        )
        verified = self._issue_from_data(readback.data, "issue", read_operation)
        for key, expected in (
            ("id", issue_id), ("title", title), ("external_ref", external_ref),
            ("database", metadata["dolt_database"]),
        ):
            if verified.get(key) != expected:
                raise AdapterError(f"bootstrap issue readback mismatch for {key}")
        self._issues[marker] = verified
        self._evidence[Gate.BOOTSTRAP] = (
            f"{len(self._issues)} bootstrap issue(s) duplicate-searched and read back in {metadata['dolt_database']}"
        )
        return dict(verified)

    def _g10(self) -> None:
        request, _, destination, _ = self._context()
        validation = self._execute(
            "g10.validation.read",
            ["git", "-C", str(destination), "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=destination,
        )
        for key, expected in (
            ("branch", "main"), ("render_valid", True), ("json_yaml_valid", True),
            ("ci_kind", request.project_kind), ("unexpected_paths", []),
            ("secret_findings", []), ("dolt_non_ignored_dirty", []),
        ):
            self._require(validation.data, key, expected, "g10.validation.read")
        self._execute(
            "g10.stage", ["git", "-C", str(destination), "add", "--all"],
            cwd=destination, mutating=True
        )
        staged = self._execute(
            "g10.staged.read",
            ["git", "-C", str(destination), "diff", "--cached", "--name-only"],
            cwd=destination,
        )
        paths = staged.data.get("paths")
        content = staged.data.get("content")
        if not isinstance(paths, list) or not paths or not isinstance(content, str):
            raise AdapterError("staged-set readback must contain nonempty paths and exact content")
        try:
            scan_staged_content(content)
            validate_commit_message(_COMMIT_MESSAGE)
        except ValueError as exc:
            raise AdapterError(str(exc)) from exc
        committed = self._execute(
            "g10.commit",
            ["git", "-C", str(destination), "commit", "-m", _COMMIT_MESSAGE],
            cwd=destination,
            mutating=True,
        )
        head = committed.data.get("head")
        if not isinstance(head, str) or not _SHA.fullmatch(head):
            raise AdapterError("commit readback omitted a full HEAD SHA")
        self._git_head = head
        clean = self._execute(
            "g10.commit.read",
            ["git", "-C", str(destination), "status", "--porcelain=v1", "--branch"],
            cwd=destination,
        )
        self._require(clean.data, "branch", "main", "g10.commit.read")
        self._require(clean.data, "clean", True, "g10.commit.read")
        self._require(clean.data, "head", head, "g10.commit.read")
        self._evidence[Gate.COMMIT] = (
            f"render/config/hygiene/Dolt checks, nonempty staged set, conventional atomic commit, and clean HEAD {head} read back"
        )

    def _g11(self) -> None:
        self._repository_readback("g11.repository.pre-push")
        if self._git_head is None:
            raise AdapterError("Git push boundary has no verified G10 commit")
        self._evidence[Gate.PUSH] = "exact main/origin identity revalidated immediately before independent pushes"

    def push_git(self) -> None:
        self._require_available()
        _, _, destination, _ = self._context()
        assert self._git_head is not None
        self._repository_readback("g11.git.pre-push")
        self._execute(
            "g11.git.push",
            ["git", "-C", str(destination), "push", "--set-upstream", "origin", "main"],
            cwd=destination,
            mutating=True,
        )
        self._execute(
            "g11.git.fetch",
            ["git", "-C", str(destination), "fetch", "origin", "main"],
            cwd=destination,
        )
        equality = self._execute(
            "g11.git.read",
            ["git", "-C", str(destination), "rev-parse", "HEAD", "@{upstream}"],
            cwd=destination,
        )
        self._require(equality.data, "head", self._git_head, "g11.git.read")
        self._require(equality.data, "upstream", self._git_head, "g11.git.read")
        self._require(equality.data, "branch", "main", "g11.git.read")
        self._evidence[Gate.PUSH] = "Git main push completed and exact HEAD == upstream read back"

    def push_dolt(self) -> None:
        self._require_available()
        _, _, destination, _ = self._context()
        result = self._execute(
            "g11.dolt.push",
            ["bd", "dolt", "push", "--remote", "origin"],
            cwd=destination,
            mutating=True,
        )
        self._require(result.data, "remote", "origin", "g11.dolt.push")
        self._require(result.data, "push_complete", True, "g11.dolt.push")
        if "Push complete." not in result.stdout:
            raise AdapterError("Dolt push output did not contain exact 'Push complete.' evidence")
        self._evidence[Gate.PUSH] = (
            "Git HEAD == upstream and separate bd dolt push 'Push complete.' evidence read back"
        )

    def read_metadata(self) -> dict[str, Any]:
        self._require_available()
        request, _, destination, _ = self._context()
        path = destination / ".beads" / "metadata.json"
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AdapterError("Beads metadata readback failed") from exc
        if not isinstance(metadata, dict):
            raise AdapterError("Beads metadata must be a JSON object")
        for key, expected in (
            ("dolt_mode", "server"), ("dolt_server_port", 3307),
        ):
            if metadata.get(key) != expected:
                raise AdapterError(f"Beads metadata {key} does not match the approved central service")
        database = metadata.get("dolt_database")
        if not isinstance(database, str) or not database or database == request.beads_prefix:
            # Equal names are legal in Beads generally, but the provisioner must prove it
            # read a generated value rather than substituting the prefix.  The controlled
            # adapter therefore requires an independently named database readback.
            raise AdapterError("Beads metadata omitted an independently read actual dolt_database")
        self._metadata = dict(metadata)
        return dict(metadata)

    def verify_existing(self) -> bool:
        self._require_available()
        request, origin, destination, _ = self._context()
        result = self._execute(
            "existing.read",
            ["git", "-C", str(destination), "status", "--porcelain=v1", "--branch"],
            cwd=destination,
        )
        expected = {
            "complete": True,
            "identity": origin.identity,
            "origin_url": request.origin_url,
            "destination": str(destination),
            "gates": [str(gate) for gate in Gate],
            "git_sync": "succeeded",
            "dolt_sync": "succeeded",
        }
        for key, value in expected.items():
            self._require(result.data, key, value, "existing.read")
        return True

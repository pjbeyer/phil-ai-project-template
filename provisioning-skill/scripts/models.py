"""Typed, non-secret models for project provisioning."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import weakref
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, Mapping
from urllib.parse import urlparse

ProjectKind = Literal["generic", "macos-cli", "homebrew-tap"]
_PROJECT_KINDS = frozenset({"generic", "macos-cli", "homebrew-tap"})
ResultState = Literal[
    "complete", "blocked-preflight", "partial", "verified-existing", "simulation-passed",
]
SyncState = Literal["succeeded", "failed", "not-attempted", "simulated"]


class Gate(StrEnum):
    PREFLIGHT = "G01"
    CLONE = "G02"
    RENDER = "G03"
    BEADS = "G04"
    BEADS_REMOTE = "G05"
    MANIFEST = "G06"
    BACKUP = "G07"
    SPECKIT = "G08"
    BOOTSTRAP = "G09"
    COMMIT = "G10"
    PUSH = "G11"


class ConfigurationError(ValueError):
    """A live configuration or safe evidence value violated policy."""


class AuthorizationError(ValueError):
    """A live authorization did not exactly bind the attempted operation."""


_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^(?P<owner>flexapp|pjbeyer)/(?P<repository>[A-Za-z0-9][A-Za-z0-9._-]{0,99})$")
_COMPONENT_NAME = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_DATABASE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,127}$")
_VERSION_TAG = re.compile(
    r"^v?[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
_SECRET_OR_POINTER = re.compile(
    r"(?:ghp_|github_pat_|AKIA[0-9A-Z]{8,}|-----BEGIN|op://|"
    r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|"
    r"(?:token|password|passwd|secret|api[_-]?key)\s*[=:]|"
    r"https?://[^/@\s]+@|(?:^|/)(?:refs/heads|heads)/|(?:^|/)HEAD(?:$|/))",
    re.IGNORECASE,
)
_PRIVATE_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9+.-])(?:"
    r"/Users/[^\s\"'`;,)}\]]+|"
    r"/home/[^\s\"'`;,)}\]]+|"
    r"/root(?:/[^\s\"'`;,)}\]]+)?(?![A-Za-z0-9])|"
    r"/etc(?:/[^\s\"'`;,)}\]]+)?(?![A-Za-z0-9])|"
    r"/(?:private/(?:tmp|var)|tmp|var)(?:/[^\s\"'`;,)}\]]+)?|"
    r"[A-Za-z]:(?:\\|/)(?!/)[^\s\"'`;,)}\]]+"
    r")"
)
_FLOATING_REFS = frozenset(
    {
        "main",
        "origin/main",
        "refs/remotes/origin/main",
        "refs/heads/main",
        "heads/main",
        "HEAD",
        ":current:",
    }
)
# This root is policy for the fixed system account. It is intentionally absent
# from canonical fields, digests, and evidence and has no caller override. It
# is resolved at runtime so the published skill source stays machine-independent
# (FR-027/NFR-007): the PROVISIONING_APPROVED_HOME environment variable takes
# precedence over an approved config file; an unset or non-canonical value fails
# closed rather than falling back to a workstation path.
_APPROVED_PROJECT_HOME_ENV = "PROVISIONING_APPROVED_HOME"
_APPROVED_PROJECT_HOME_CONFIG_KEY = "approved_project_home"
# The template checkout is a second runtime-derived root (FR-027/NFR-007): the
# skill never hard-codes the operator's template repository path. It resolves
# from an env var or the same approved config file, fail-closed if unset.
_APPROVED_TEMPLATE_SOURCE_ENV = "PROVISIONING_TEMPLATE_SOURCE"
_APPROVED_TEMPLATE_SOURCE_CONFIG_KEY = "approved_template_source"


def _approved_project_home_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else (Path.home() / ".config")
    return base / "provisioning" / "config.json"


def _approved_project_home_from_file(path: Path, *, key: str = _APPROVED_PROJECT_HOME_CONFIG_KEY) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > 4096:
        raise ConfigurationError("approved project home config file exceeds its bounded size")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ConfigurationError("approved project home config file is not valid JSON") from error
    if not isinstance(data, dict):
        raise ConfigurationError("approved project home config file must be a JSON object")
    value = data.get(key)
    if value is None:
        return None
    if type(value) is not str:
        raise ConfigurationError("approved project home config value must be a string")
    return value


def _approved_project_home() -> Path:
    raw = os.environ.get(_APPROVED_PROJECT_HOME_ENV)
    if raw is None:
        raw = _approved_project_home_from_file(_approved_project_home_config_path())
    if raw is None:
        raise ConfigurationError(
            "approved project home is not configured "
            "(set PROVISIONING_APPROVED_HOME or "
            "approved_project_home in the provisioning config file)"
        )
    candidate = Path(os.path.expanduser(raw))
    try:
        return _canonical_absolute_path(candidate, "approved project home")
    except ConfigurationError as error:
        raise ConfigurationError(
            "approved project home must be an exact canonical absolute path"
        ) from error


def _approved_template_source() -> Path:
    """Resolve the operator's template checkout path, fail-closed if unset.

    The template source identity is allowlisted separately; this only resolves
    the local checkout directory from which the immutable tag/commit is read and
    rendered. It is runtime-derived (env var or the approved config file), never
    hard-coded, and must be an exact canonical absolute path.
    """
    raw = os.environ.get(_APPROVED_TEMPLATE_SOURCE_ENV)
    if raw is None:
        raw = _approved_project_home_from_file(_approved_project_home_config_path(), key=_APPROVED_TEMPLATE_SOURCE_CONFIG_KEY)
    if raw is None:
        raise ConfigurationError(
            "approved template source is not configured "
            "(set PROVISIONING_TEMPLATE_SOURCE or "
            "approved_template_source in the provisioning config file)"
        )
    candidate = Path(os.path.expanduser(raw))
    try:
        return _canonical_absolute_path(candidate, "approved template source")
    except ConfigurationError as error:
        raise ConfigurationError(
            "approved template source must be an exact canonical absolute path"
        ) from error


APPROVED_TEMPLATE_SOURCE_IDENTITIES = frozenset({"pjbeyer/phil-ai-project-template"})
APPROVED_TEMPLATE_MINIMUM_TAG = "v0.1.3"
APPROVED_MANIFEST_IDENTITY = "managed-projects-manifest/v1"
APPROVED_AUDIT_IDENTITY = "managed-projects-coverage-audit/v1"
APPROVED_EXECUTOR_POLICY_VERSION = "controlled-live-executor/v1"
APPROVED_COMPONENT_NAMES = frozenset(
    {
        "verify-tasks",
        "spec-validate",
        "red-team",
        "cleanup",
        "reconcile",
        "checkpoint",
        "security-review",
        "command-density",
        "explicit-task-dependencies",
        "security-governance",
    }
)
APPROVED_COMPONENT_SOURCE_IDENTITIES: Mapping[str, str] = MappingProxyType(
    {name: f"speckit/component/{name}" for name in APPROVED_COMPONENT_NAMES}
)
APPROVED_ISSUE_MARKERS = frozenset(
    {
        "scope-readme",
        "first-speckit-spec",
        "macos-cli-real-tests",
        "homebrew-first-package",
        "homebrew-actions-secret",
        "homebrew-lifecycle-tests",
    }
)
_OWNER_ROUTES: Mapping[str, PurePosixPath] = MappingProxyType(
    {"flexapp": PurePosixPath("Projects/work"), "pjbeyer": PurePosixPath("Projects/pjbeyer")}
)


def _reject_unsafe_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not value and not allow_empty):
        raise ConfigurationError(f"{label} must be a{' possibly empty' if allow_empty else ' nonempty'} plain string")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ConfigurationError(f"{label} contains control syntax")
    if _SECRET_OR_POINTER.search(value):
        raise ConfigurationError(f"{label} contains secret-shaped material or a credential pointer")
    if value.startswith("~/") or _PRIVATE_ABSOLUTE_PATH.search(value):
        raise ConfigurationError(f"{label} must not contain a private absolute path")
    parsed = urlparse(value)
    if parsed.scheme and (parsed.username or parsed.password):
        raise ConfigurationError(f"{label} must not contain URL userinfo")
    return value


def _reject_floating_ref(value: str, label: str) -> str:
    if value in _FLOATING_REFS:
        raise ConfigurationError(f"{label} must be explicit and non-floating")
    return value


def _require_version_tag(value: object, label: str) -> str:
    admitted = _reject_unsafe_text(value, label)
    if _VERSION_TAG.fullmatch(admitted) is None:
        raise ConfigurationError(f"{label} must be an explicit version-shaped non-floating tag")
    return admitted


def _require_fixed_string(value: object, expected: str, label: str) -> str:
    admitted = _reject_unsafe_text(value, label)
    if admitted != expected:
        raise ConfigurationError(f"{label} is not the fixed reviewed identity")
    return admitted


def _require_full_sha(value: object, label: str) -> str:
    if type(value) is not str or _FULL_SHA.fullmatch(value) is None:
        raise ConfigurationError(f"{label} must be a resolved full lowercase Git commit")
    return value


_VERSION_NUMERIC = re.compile(r"^v?(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)")


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = _VERSION_NUMERIC.match(value)
    if match is None:
        raise ConfigurationError("template tag is not numerically comparable")
    try:
        return (int(match["major"]), int(match["minor"]), int(match["patch"]))
    except ValueError as error:
        raise ConfigurationError("template tag version number is out of range") from error


def _require_minimum_template_tag(value: object, label: str) -> str:
    """Enforce the reviewed minimum template revision.

    The template is only usable from an approved immutable revision. Tags older
    than ``APPROVED_TEMPLATE_MINIMUM_TAG`` carry the nonexistent
    release-please-action SHA (remediated in ``v0.1.3``) and must never render.
    A pre-release/build of the floor tag is not the reviewed final tag and is
    rejected; later revisions are admitted.
    """
    admitted = _reject_unsafe_text(value, label)
    if _VERSION_TAG.fullmatch(admitted) is None:
        raise ConfigurationError(f"{label} must be an explicit version-shaped non-floating tag")
    floor = _version_tuple(APPROVED_TEMPLATE_MINIMUM_TAG)
    candidate = _version_tuple(admitted)
    if candidate < floor:
        raise ConfigurationError(f"{label} is below the reviewed minimum template revision")
    if candidate == floor and admitted not in (
        APPROVED_TEMPLATE_MINIMUM_TAG,
        APPROVED_TEMPLATE_MINIMUM_TAG.removeprefix("v"),
    ):
        raise ConfigurationError(f"{label} must be the reviewed minimum template tag or a later revision")
    return admitted


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ConfigurationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        raise ConfigurationError(f"{label} must be an exact canonical absolute Path")
    canonical = Path(str(value))
    if value != canonical:
        raise ConfigurationError(f"{label} is not canonical")
    return canonical


def _path_digest(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ComponentPin:
    """A reviewed component source identity resolved to an immutable commit."""

    name: str
    source_identity: str
    resolved_commit: str

    def __post_init__(self) -> None:
        _reject_unsafe_text(self.name, "component name")
        if _COMPONENT_NAME.fullmatch(self.name) is None or self.name not in APPROVED_COMPONENT_NAMES:
            raise ConfigurationError("component name is outside the approved immutable set")
        _require_fixed_string(
            self.source_identity,
            APPROVED_COMPONENT_SOURCE_IDENTITIES[self.name],
            f"component {self.name} source identity",
        )
        _require_full_sha(self.resolved_commit, f"component {self.name} resolved commit")

    def canonical_fields(self) -> dict[str, str]:
        return {
            "name": self.name,
            "source_identity": self.source_identity,
            "resolved_commit": self.resolved_commit,
        }


@dataclass(frozen=True, slots=True)
class RenderProvenance:
    """Non-secret provenance persisted durably before the render mutation.

    Recording this is not a claim that a render or an FR-008/FR-019 readback
    succeeded; it is only the supply-chain authority captured before G03 mutates
    any filesystem. Every value is admitted through the unsafe-text policy, so a
    secret-shaped value, credential pointer, URL userinfo, or private absolute
    path is rejected rather than persisted.
    """

    template_source_identity: str
    template_tag: str
    resolved_template_commit: str
    submitted_answers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _require_fixed_string(
            self.template_source_identity,
            next(iter(APPROVED_TEMPLATE_SOURCE_IDENTITIES)),
            "render provenance template source identity",
        )
        _require_version_tag(self.template_tag, "render provenance template tag")
        _require_minimum_template_tag(self.template_tag, "render provenance template tag")
        _require_full_sha(self.resolved_template_commit, "render provenance resolved commit")
        if type(self.submitted_answers) is not tuple or not self.submitted_answers:
            raise ConfigurationError("render provenance answers must be a nonempty tuple")
        seen: set[str] = set()
        for key, value in self.submitted_answers:
            admitted_key = _reject_unsafe_text(key, "render provenance answer key")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", admitted_key) is None:
                raise ConfigurationError("render provenance answer key has an unsafe shape")
            if admitted_key in seen:
                raise ConfigurationError("render provenance answers must be unique")
            seen.add(admitted_key)
            _reject_unsafe_text(value, f"render provenance answer {admitted_key}")

    def canonical_fields(self) -> dict[str, object]:
        return {
            "template_source_identity": self.template_source_identity,
            "template_tag": self.template_tag,
            "resolved_template_commit": self.resolved_template_commit,
            "submitted_answers": {key: value for key, value in self.submitted_answers},
        }

    @classmethod
    def capture(
        cls,
        configuration: ImmutableLiveConfiguration,
        *,
        repository_owner: str,
        repository_name: str,
        project_kind: str,
        project_description: str,
    ) -> RenderProvenance:
        """Derive the pre-render provenance record from the exact approved inputs."""
        if cls is not RenderProvenance:
            raise ConfigurationError("render provenance capture subclasses are not admitted")
        admitted_owner = _reject_unsafe_text(repository_owner, "render provenance repository owner")
        if admitted_owner not in {"flexapp", "pjbeyer"}:
            raise ConfigurationError("render provenance repository owner is outside approved routing")
        admitted_name = _reject_unsafe_text(repository_name, "render provenance repository name")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", admitted_name) is None:
            raise ConfigurationError("render provenance repository name is outside approved routing")
        if type(project_kind) is not str or project_kind not in _PROJECT_KINDS:
            raise ConfigurationError("render provenance project kind is not an approved kind")
        _reject_unsafe_text(project_description, "render provenance project description", allow_empty=True)
        submitted_answers = (
            ("repository_owner", admitted_owner),
            ("repository_name", admitted_name),
            ("project_kind", project_kind),
            ("project_description", project_description),
        )
        return cls(
            configuration.template_source_identity,
            configuration.template_tag,
            configuration.resolved_template_commit,
            submitted_answers,
        )


def _canonical_configuration_payload(configuration: ImmutableLiveConfiguration) -> str:
    """Serialize exact fields without calling an admission-checking method."""
    fields = {
        "audit_identity": configuration.audit_identity,
        "component_pins": [pin.canonical_fields() for pin in configuration.component_pins],
        "destination_route": configuration.destination_route,
        "executor_policy_version": configuration.executor_policy_version,
        "manifest_identity": configuration.manifest_identity,
        "repository_identity": configuration.repository_identity,
        "resolved_template_commit": configuration.resolved_template_commit,
        "template_source_identity": configuration.template_source_identity,
        "template_tag": configuration.template_tag,
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_authorization_payload(authorization: LiveAuthorization) -> str:
    fields = {
        "config_digest": authorization.config_digest,
        "named_identity": authorization.named_identity,
        "permitted_starting_gate": authorization.permitted_starting_gate.value,
        "request_fingerprint": authorization.request_fingerprint,
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class _ConstructionRegistry:
    """Identity-only weak registration with canonical state seals.

    This detects ordinary in-process construction bypass and post-construction
    mutation. It is not a boundary against arbitrary code able to rewrite this
    module's private registry itself.
    """

    def __init__(self) -> None:
        self._entries: dict[int, tuple[weakref.ReferenceType[object], str]] = {}
        self._pending: dict[int, weakref.ReferenceType[object]] = {}
        self._lock = threading.RLock()

    def begin(self, value: object) -> None:
        """Mark an instance created through its normal ``__new__`` path."""
        identity = id(value)

        def remove(reference: weakref.ReferenceType[object], *, key: int = identity) -> None:
            with self._lock:
                if self._pending.get(key) is reference:
                    self._pending.pop(key, None)

        reference = weakref.ref(value, remove)
        with self._lock:
            self._pending[identity] = reference

    def register_pending(self, value: object, serialized: str) -> None:
        """Seal only an instance previously marked by normal construction."""
        identity = id(value)
        with self._lock:
            reference = self._pending.get(identity)
            if reference is None or reference() is not value:
                return
            self._pending.pop(identity, None)
        self.register(value, serialized)

    def register(self, value: object, serialized: str) -> None:
        identity = id(value)

        def remove(reference: weakref.ReferenceType[object], *, key: int = identity) -> None:
            with self._lock:
                current = self._entries.get(key)
                if current is not None and current[0] is reference:
                    self._entries.pop(key, None)

        reference = weakref.ref(value, remove)
        seal = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        with self._lock:
            self._entries[identity] = (reference, seal)

    def snapshot(self, value: object, serialized: str, label: str) -> str:
        """Verify one serialized state and return its registered seal."""
        identity = id(value)
        current_seal = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        with self._lock:
            entry = self._entries.get(identity)
            if entry is None or entry[0]() is not value or not hmac.compare_digest(entry[1], current_seal):
                raise ConfigurationError(f"{label} was not genuinely constructed or its sealed state changed")
            return entry[1]

    def assert_current(self, value: object, serialized: str, label: str) -> None:
        self.snapshot(value, serialized, label)


_CONFIGURATION_REGISTRY = _ConstructionRegistry()
_AUTHORIZATION_REGISTRY = _ConstructionRegistry()
_AUTHORIZATION_CONSTRUCTION = threading.local()


def _missing_fields(value: object, names: tuple[str, ...], label: str) -> None:
    try:
        missing = tuple(name for name in names if not hasattr(value, name))
    except Exception as error:
        raise ConfigurationError(f"{label} has inaccessible required fields") from error
    if missing:
        raise ConfigurationError(f"{label} is missing required fields")


def _configuration_payload_checked(configuration: ImmutableLiveConfiguration) -> str:
    try:
        _missing_fields(
            configuration,
            (
                "audit_identity",
                "component_pins",
                "destination_route",
                "executor_policy_version",
                "manifest_identity",
                "repository_identity",
                "resolved_template_commit",
                "template_source_identity",
                "template_tag",
            ),
            "live configuration",
        )
        return _canonical_configuration_payload(configuration)
    except ConfigurationError:
        raise
    except (AttributeError, TypeError, ValueError) as error:
        raise ConfigurationError("live configuration fields are not canonical") from error


def _authorization_payload_checked(authorization: LiveAuthorization) -> str:
    try:
        _missing_fields(
            authorization,
            (
                "config_digest",
                "named_identity",
                "permitted_starting_gate",
                "request_fingerprint",
            ),
            "live authorization",
        )
        return _canonical_authorization_payload(authorization)
    except (AttributeError, ConfigurationError, TypeError, ValueError) as error:
        raise AuthorizationError("live authorization fields are not canonical") from error


def _assert_configuration_integrity(configuration: ImmutableLiveConfiguration) -> None:
    _CONFIGURATION_REGISTRY.assert_current(
        configuration,
        _configuration_payload_checked(configuration),
        "live configuration",
    )


def _assert_authorization_integrity(authorization: LiveAuthorization) -> None:
    try:
        _AUTHORIZATION_REGISTRY.assert_current(
            authorization,
            _authorization_payload_checked(authorization),
            "live authorization",
        )
    except ConfigurationError as error:
        raise AuthorizationError(str(error)) from error


def _validated_component_tuple(value: object) -> tuple[ComponentPin, ...]:
    if type(value) is not tuple:
        raise ConfigurationError("component pins must be a canonical immutable tuple")
    if any(type(pin) is not ComponentPin for pin in value):
        raise ConfigurationError("component pins must use the exact ComponentPin type")
    pins = value
    names = tuple(pin.name for pin in pins)
    if names != tuple(sorted(APPROVED_COMPONENT_NAMES)):
        raise ConfigurationError("component pin set must exactly match the approved set in canonical order")
    # Re-run validation so a forged/frozen-object mutation cannot bypass admission.
    for pin in pins:
        pin.__post_init__()
    return pins


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ImmutableLiveConfiguration:
    """Canonical policy whose destination route is derived from identity.

    Only ``create`` constructs valid instances. The hard-coded owner route is
    joined lexically to the fixed approved project home when a destination is
    checked; no private absolute path enters canonical fields, digests, or
    evidence.
    """

    repository_identity: str
    destination_route: str
    template_source_identity: str
    template_tag: str
    resolved_template_commit: str
    component_pins: tuple[ComponentPin, ...]
    manifest_identity: str = APPROVED_MANIFEST_IDENTITY
    audit_identity: str = APPROVED_AUDIT_IDENTITY
    executor_policy_version: str = APPROVED_EXECUTOR_POLICY_VERSION

    def __post_init__(self) -> None:
        match = _IDENTITY.fullmatch(_reject_unsafe_text(self.repository_identity, "repository identity"))
        if match is None:
            raise ConfigurationError("repository identity is outside approved owner routing")
        route = _reject_unsafe_text(self.destination_route, "destination route")
        route_path = PurePosixPath(route)
        expected_route = _OWNER_ROUTES[match.group("owner")] / match.group("repository")
        if route_path.is_absolute() or ".." in route_path.parts or route_path != expected_route:
            raise ConfigurationError("destination route does not exactly match the approved canonical owner route")
        _require_fixed_string(
            self.template_source_identity,
            next(iter(APPROVED_TEMPLATE_SOURCE_IDENTITIES)),
            "template source identity",
        )
        _require_version_tag(self.template_tag, "template tag")
        _require_minimum_template_tag(self.template_tag, "template tag")
        _require_full_sha(self.resolved_template_commit, "resolved template commit")
        _validated_component_tuple(self.component_pins)
        _require_fixed_string(
            self.manifest_identity,
            APPROVED_MANIFEST_IDENTITY,
            "manifest identity",
        )
        _require_fixed_string(
            self.audit_identity,
            APPROVED_AUDIT_IDENTITY,
            "audit identity",
        )
        _require_fixed_string(
            self.executor_policy_version,
            APPROVED_EXECUTOR_POLICY_VERSION,
            "executor policy version",
        )

    @classmethod
    def create(
        cls,
        *,
        repository_identity: str,
        template_source_identity: str,
        template_tag: str,
        resolved_template_commit: str,
        component_pins: Mapping[str, ComponentPin],
    ) -> ImmutableLiveConfiguration:
        """Derive fixed routing and construct the sole admitted config shape."""
        match = _IDENTITY.fullmatch(repository_identity) if type(repository_identity) is str else None
        if match is None:
            raise ConfigurationError("repository identity is outside approved owner routing")
        if type(component_pins) is not dict:
            raise ConfigurationError("component pins must be supplied as an exact plain mapping")
        if set(component_pins) != APPROVED_COMPONENT_NAMES:
            raise ConfigurationError("component pin mapping does not exactly match the approved set")
        pins = tuple(component_pins[name] for name in sorted(component_pins))
        instance = object.__new__(cls)
        object.__setattr__(instance, "repository_identity", repository_identity)
        object.__setattr__(
            instance,
            "destination_route",
            str(_OWNER_ROUTES[match.group("owner")] / match.group("repository")),
        )
        object.__setattr__(instance, "template_source_identity", template_source_identity)
        object.__setattr__(instance, "template_tag", template_tag)
        object.__setattr__(instance, "resolved_template_commit", resolved_template_commit)
        object.__setattr__(instance, "component_pins", pins)
        object.__setattr__(instance, "manifest_identity", APPROVED_MANIFEST_IDENTITY)
        object.__setattr__(instance, "audit_identity", APPROVED_AUDIT_IDENTITY)
        object.__setattr__(instance, "executor_policy_version", APPROVED_EXECUTOR_POLICY_VERSION)
        instance.__post_init__()
        _CONFIGURATION_REGISTRY.register(instance, _canonical_configuration_payload(instance))
        return instance

    @property
    def render_revision(self) -> str:
        """Rendering provenance is the verified commit, never the mutable tag."""
        return self.resolved_template_commit

    def matches_destination(self, destination: Path) -> bool:
        try:
            payload = _configuration_payload_checked(self)
            self.__post_init__()
            _CONFIGURATION_REGISTRY.assert_current(self, payload, "live configuration")
            candidate = _canonical_absolute_path(destination, "destination")
            expected = _approved_project_home().joinpath(
                *PurePosixPath(self.destination_route).parts
            )
        except (AttributeError, ConfigurationError, RuntimeError, TypeError):
            return False
        return candidate == expected

    def canonical_fields(self) -> dict[str, Any]:
        """Return only canonical, secret-free digest fields."""
        self.__post_init__()
        return {
            "audit_identity": self.audit_identity,
            "component_pins": [pin.canonical_fields() for pin in self.component_pins],
            "destination_route": self.destination_route,
            "executor_policy_version": self.executor_policy_version,
            "manifest_identity": self.manifest_identity,
            "repository_identity": self.repository_identity,
            "resolved_template_commit": self.resolved_template_commit,
            "template_source_identity": self.template_source_identity,
            "template_tag": self.template_tag,
        }


# Compatibility name for the quarantined adapter.  The old mutable/path/env
# configuration has deliberately been replaced, not extended.
LiveAdapterConfig = ImmutableLiveConfiguration


def configuration_digest(configuration: ImmutableLiveConfiguration) -> str:
    if type(configuration) is not ImmutableLiveConfiguration:
        raise ConfigurationError("configuration must use the exact immutable live configuration type")
    payload = _configuration_payload_checked(configuration)
    configuration.__post_init__()
    _CONFIGURATION_REGISTRY.assert_current(configuration, payload, "live configuration")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class _LiveAuthorizationType(type):
    """Open a one-use constructor token only for normal ``Class(...)`` calls."""

    def __call__(cls, *args: object, **kwargs: object) -> object:
        if cls is LiveAuthorization:
            if getattr(_AUTHORIZATION_CONSTRUCTION, "token", None) is not None:
                raise AuthorizationError("nested live authorization construction is forbidden")
            _AUTHORIZATION_CONSTRUCTION.token = object()
            try:
                return super().__call__(*args, **kwargs)
            finally:
                if hasattr(_AUTHORIZATION_CONSTRUCTION, "pending"):
                    del _AUTHORIZATION_CONSTRUCTION.pending
                if hasattr(_AUTHORIZATION_CONSTRUCTION, "token"):
                    del _AUTHORIZATION_CONSTRUCTION.token
        return super().__call__(*args, **kwargs)


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class LiveAuthorization(metaclass=_LiveAuthorizationType):
    """Exact reviewed authority for one identity, request, config, and gate."""

    named_identity: str
    request_fingerprint: str
    config_digest: str
    permitted_starting_gate: Gate

    def __new__(cls, *args: object, **kwargs: object) -> LiveAuthorization:
        del args, kwargs
        instance = super().__new__(cls)
        if cls is LiveAuthorization and getattr(_AUTHORIZATION_CONSTRUCTION, "token", None) is not None:
            if getattr(_AUTHORIZATION_CONSTRUCTION, "pending", None) is not None:
                raise AuthorizationError("live authorization constructor token was already consumed")
            _AUTHORIZATION_CONSTRUCTION.pending = instance
        return instance

    def __init__(
        self,
        named_identity: str,
        request_fingerprint: str,
        config_digest: str,
        permitted_starting_gate: Gate,
    ) -> None:
        if type(self) is not LiveAuthorization:
            object.__setattr__(self, "named_identity", named_identity)
            object.__setattr__(self, "request_fingerprint", request_fingerprint)
            object.__setattr__(self, "config_digest", config_digest)
            object.__setattr__(self, "permitted_starting_gate", permitted_starting_gate)
            self.__post_init__()
            return
        token = getattr(_AUTHORIZATION_CONSTRUCTION, "token", None)
        pending = getattr(_AUTHORIZATION_CONSTRUCTION, "pending", None)
        if token is None or pending is not self:
            raise AuthorizationError("live authorization must be constructed by an ordinary class call")
        del _AUTHORIZATION_CONSTRUCTION.pending
        object.__setattr__(self, "named_identity", named_identity)
        object.__setattr__(self, "request_fingerprint", request_fingerprint)
        object.__setattr__(self, "config_digest", config_digest)
        object.__setattr__(self, "permitted_starting_gate", permitted_starting_gate)
        self.__post_init__()
        _AUTHORIZATION_REGISTRY.register(self, _canonical_authorization_payload(self))

    def __post_init__(self) -> None:
        try:
            _missing_fields(
                self,
                (
                    "named_identity",
                    "request_fingerprint",
                    "config_digest",
                    "permitted_starting_gate",
                ),
                "live authorization",
            )
            if _IDENTITY.fullmatch(_reject_unsafe_text(self.named_identity, "authorization identity")) is None:
                raise AuthorizationError("authorization identity is invalid")
            _require_digest(self.request_fingerprint, "request fingerprint")
            _require_digest(self.config_digest, "configuration digest")
        except ConfigurationError as error:
            raise AuthorizationError(str(error)) from error
        if type(self.permitted_starting_gate) is not Gate:
            raise AuthorizationError("authorization starting gate must use the exact Gate type")


def assert_live_authorized(
    authorization: LiveAuthorization,
    *,
    named_identity: str,
    request_fingerprint: str,
    configuration: ImmutableLiveConfiguration,
    starting_gate: Gate,
) -> LiveAuthorization:
    """Admit one exact sealed snapshot and reject any concurrent change."""
    if type(authorization) is not LiveAuthorization:
        raise AuthorizationError("live authorization must use the exact named authorization type")
    if type(named_identity) is not str:
        raise AuthorizationError("named identity must use the exact string type")
    if _IDENTITY.fullmatch(named_identity) is None:
        raise AuthorizationError("named identity is invalid")
    if type(request_fingerprint) is not str or _DIGEST.fullmatch(request_fingerprint) is None:
        raise AuthorizationError("request fingerprint must be a lowercase SHA-256 digest")
    if type(configuration) is not ImmutableLiveConfiguration:
        raise AuthorizationError("live configuration must use the exact immutable type")
    if type(starting_gate) is not Gate:
        raise AuthorizationError("starting gate must use the exact Gate type")
    try:
        authorization_payload = _authorization_payload_checked(authorization)
        configuration_payload = _configuration_payload_checked(configuration)
        authorization.__post_init__()
        configuration.__post_init__()
        _AUTHORIZATION_REGISTRY.assert_current(
            authorization,
            authorization_payload,
            "live authorization",
        )
        _CONFIGURATION_REGISTRY.assert_current(
            configuration,
            configuration_payload,
            "live configuration",
        )
        authorization_fields = json.loads(authorization_payload)
        configuration_fields = json.loads(configuration_payload)
        current_digest = hashlib.sha256(configuration_payload.encode("utf-8")).hexdigest()
    except (AuthorizationError, ConfigurationError) as error:
        raise AuthorizationError(f"live binding is invalid: {error}") from error
    if (
        authorization_fields["named_identity"] != named_identity
        or authorization_fields["request_fingerprint"] != request_fingerprint
        or authorization_fields["config_digest"] != current_digest
        or authorization_fields["permitted_starting_gate"] != starting_gate.value
        or configuration_fields["repository_identity"] != named_identity
    ):
        raise AuthorizationError(
            "live authorization does not exactly match identity, request, configuration, and starting gate"
        )
    # Close the TOCTOU window after all comparisons and return a detached,
    # independently sealed snapshot. The caller never receives the mutable
    # object whose pre-return state was inspected.
    try:
        _AUTHORIZATION_REGISTRY.assert_current(
            authorization,
            _authorization_payload_checked(authorization),
            "live authorization",
        )
        _CONFIGURATION_REGISTRY.assert_current(
            configuration,
            _configuration_payload_checked(configuration),
            "live configuration",
        )
        accepted = LiveAuthorization(
            named_identity=authorization_fields["named_identity"],
            request_fingerprint=authorization_fields["request_fingerprint"],
            config_digest=authorization_fields["config_digest"],
            permitted_starting_gate=Gate(authorization_fields["permitted_starting_gate"]),
        )
        _assert_authorization_integrity(accepted)
    except (AuthorizationError, ConfigurationError, ValueError) as error:
        raise AuthorizationError(f"live binding changed during admission: {error}") from error
    return accepted


@dataclass(frozen=True, slots=True)
class LiveProvisioningEvidence:
    """Safe provenance/readback-shaped fields for future live work.

    This model records values only; constructing it is not a claim that a real
    source, manifest, or database readback occurred.
    """

    template_source_identity: str
    template_tag: str
    resolved_template_commit: str
    config_digest: str
    actual_database: str
    manifest_identity: str
    stable_issue_markers: tuple[str, ...]
    validated_component_pins: tuple[ComponentPin, ...]

    def __post_init__(self) -> None:
        _require_fixed_string(
            self.template_source_identity,
            next(iter(APPROVED_TEMPLATE_SOURCE_IDENTITIES)),
            "evidence template source identity",
        )
        _require_version_tag(self.template_tag, "evidence template tag")
        _require_minimum_template_tag(self.template_tag, "evidence template tag")
        _require_full_sha(self.resolved_template_commit, "evidence resolved template commit")
        _require_digest(self.config_digest, "evidence configuration digest")
        database = _reject_floating_ref(
            _reject_unsafe_text(self.actual_database, "evidence actual database"),
            "evidence actual database",
        )
        if _DATABASE.fullmatch(database) is None:
            raise ConfigurationError("evidence actual database is not a safe database identity")
        _require_fixed_string(
            self.manifest_identity,
            APPROVED_MANIFEST_IDENTITY,
            "evidence manifest identity",
        )
        if type(self.stable_issue_markers) is not tuple:
            raise ConfigurationError("evidence issue markers must be an immutable tuple")
        marker_set: set[str] = set()
        for marker in self.stable_issue_markers:
            admitted_marker = _reject_unsafe_text(marker, "evidence issue marker")
            if admitted_marker in marker_set:
                raise ConfigurationError("evidence issue markers must be unique")
            marker_set.add(admitted_marker)
            if admitted_marker not in APPROVED_ISSUE_MARKERS:
                raise ConfigurationError("evidence issue marker is not stable and approved")
        _validated_component_tuple(self.validated_component_pins)


@dataclass(frozen=True)
class ProvisioningRequest:
    origin_url: str
    beads_prefix: str
    project_kind: ProjectKind
    description: str = ""
    destination_confirmation: str | None = None
    live_authorization: LiveAuthorization | None = None
    resume_authorization: LiveAuthorization | None = None


@dataclass
class GateResult:
    gate: Gate
    status: Literal["passed", "failed", "skipped", "simulated"]
    detail: str


@dataclass
class ProvisioningEvidence:
    run_id: str
    request_fingerprint: str
    destination: str
    repository_identity: str
    state: ResultState
    template_revision: str = "not-reached"
    failed_gate: str | None = None
    gates: list[GateResult] = field(default_factory=list)
    mutation_attempts: list[str] = field(default_factory=list)
    mutations_completed: list[str] = field(default_factory=list)
    actual_database: str = "not-reached"
    git_sync: SyncState = "not-attempted"
    dolt_sync: SyncState = "not-attempted"
    resume_requirement: str | None = None
    next_action: str = ""
    simulation: bool = False
    render_provenance: RenderProvenance | None = None

    def serializable(self) -> dict:
        payload = asdict(self)
        if self.render_provenance is not None:
            payload["render_provenance"] = self.render_provenance.canonical_fields()
        return payload

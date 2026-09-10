"""Sanitized, atomically persisted provisioning evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from .models import (
    ComponentPin,
    ConfigurationError,
    Gate,
    LiveProvisioningEvidence,
    ProvisioningEvidence,
    ProvisioningRequest,
    _canonical_absolute_path,
    _reject_unsafe_text,
    _PRIVATE_ABSOLUTE_PATH,
)

SECRET = re.compile(
    r"(?:ghp_|github_pat_|AKIA[0-9A-Z]{8,}|-----BEGIN|"
    r"https?://[^/@\s]+@|op://[^\s]+|"
    r"(?:token|password|passwd|secret|api[_-]?key)\s*[=:]\s*\S*)",
    re.I,
)
PRIVATE_ABSOLUTE_PATH = _PRIVATE_ABSOLUTE_PATH
_LIVE_EVIDENCE_FIELDS = frozenset(
    {
        "template_source_identity",
        "template_tag",
        "resolved_template_commit",
        "config_digest",
        "actual_database",
        "manifest_identity",
        "stable_issue_markers",
        "validated_component_pins",
    }
)
_COMPONENT_PIN_FIELDS = frozenset({"name", "source_identity", "resolved_commit"})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_INSPECTION_STATUSES = frozenset({"passed", "failed", "not-reached"})
_INSPECTION_STATES = frozenset({"blocked-preflight", "verified-existing"})
_SYNC_STATES = frozenset({"succeeded", "failed", "not-attempted"})


@dataclass(frozen=True, slots=True)
class InspectionFinding:
    """Sanitized parser-owned result for one existing-state invariant gate."""

    gate: Gate
    status: Literal["passed", "failed", "not-reached"]
    detail: str
    observation_digest: str | None

    def __post_init__(self) -> None:
        if type(self.gate) is not Gate or self.gate is Gate.PREFLIGHT:
            raise ValueError("inspection finding must name an exact terminal gate")
        if self.status not in _INSPECTION_STATUSES:
            raise ValueError("inspection finding status is invalid")
        if type(self.detail) is not str or not self.detail:
            raise ValueError("inspection finding detail must be nonempty text")
        if redact(self.detail) != self.detail:
            raise ValueError("inspection finding detail contains unsafe material")
        if self.status == "not-reached":
            if self.observation_digest is not None:
                raise ValueError("not-reached finding cannot bind an observation")
        elif self.status == "passed":
            if (
                type(self.observation_digest) is not str
                or _DIGEST.fullmatch(self.observation_digest) is None
            ):
                raise ValueError("passed finding must bind a lowercase SHA-256 observation digest")
        elif self.observation_digest is not None and (
            type(self.observation_digest) is not str
            or _DIGEST.fullmatch(self.observation_digest) is None
        ):
            raise ValueError("failed finding observation digest is invalid")


@dataclass(frozen=True, slots=True)
class InspectionEvidence:
    """Immutable no-persist inspection result used to bind exact resume."""

    evidence_id: str
    request_fingerprint: str
    configuration_fingerprint: str
    repository_identity: str
    destination_digest: str
    state: Literal["blocked-preflight", "verified-existing"]
    next_gate: Gate | None
    findings: tuple[InspectionFinding, ...]
    git_sync: Literal["succeeded", "failed", "not-attempted"] = "not-attempted"
    dolt_sync: Literal["succeeded", "failed", "not-attempted"] = "not-attempted"

    def __post_init__(self) -> None:
        for value, label in (
            (self.evidence_id, "inspection evidence id"),
            (self.request_fingerprint, "inspection request fingerprint"),
            (self.configuration_fingerprint, "inspection configuration fingerprint"),
            (self.destination_digest, "inspection destination digest"),
        ):
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ValueError(f"{label} must be a lowercase SHA-256 digest")
        _reject_unsafe_text(self.repository_identity, "inspection repository identity")
        if self.state not in _INSPECTION_STATES:
            raise ValueError("inspection state is invalid")
        if self.next_gate is not None and (
            type(self.next_gate) is not Gate or self.next_gate is Gate.PREFLIGHT
        ):
            raise ValueError("inspection next gate must be an exact terminal gate")
        if type(self.findings) is not tuple or any(
            type(finding) is not InspectionFinding for finding in self.findings
        ):
            raise ValueError("inspection findings must use exact immutable finding types")
        terminal = tuple(Gate)[1:]
        if tuple(finding.gate for finding in self.findings) != terminal:
            raise ValueError("inspection findings must cover every terminal gate in order")
        failed = tuple(finding.gate for finding in self.findings if finding.status == "failed")
        passed_count = sum(finding.status == "passed" for finding in self.findings)
        if self.state == "verified-existing":
            if self.next_gate is not None or failed or any(
                finding.status != "passed" for finding in self.findings
            ):
                raise ValueError("verified-existing requires every invariant to pass")
            if self.git_sync != "succeeded" or self.dolt_sync != "succeeded":
                raise ValueError("verified-existing requires independent Git and Dolt synchronization")
        elif (
            len(failed) != 1
            or self.next_gate is not failed[0]
            or passed_count != terminal.index(failed[0])
            or any(
                finding.status != "not-reached"
                for finding in self.findings[passed_count + 1:]
            )
        ):
            raise ValueError("blocked inspection must name its sole first failed gate")
        if self.git_sync not in _SYNC_STATES or self.dolt_sync not in _SYNC_STATES:
            raise ValueError("inspection synchronization state is invalid")
        if self.evidence_id != inspection_evidence_id(self.canonical_payload()):
            raise ValueError("inspection evidence id does not match its exact sanitized snapshot")

    def canonical_payload(self, *, include_id: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "configuration_fingerprint": self.configuration_fingerprint,
            "destination_digest": self.destination_digest,
            "dolt_sync": self.dolt_sync,
            "findings": [
                {
                    "gate": finding.gate.value,
                    "status": finding.status,
                    "detail": finding.detail,
                    "observation_digest": finding.observation_digest,
                }
                for finding in self.findings
            ],
            "git_sync": self.git_sync,
            "next_gate": None if self.next_gate is None else self.next_gate.value,
            "repository_identity_digest": hashlib.sha256(
                self.repository_identity.encode("utf-8")
            ).hexdigest(),
            "request_fingerprint": self.request_fingerprint,
            "state": self.state,
        }
        if include_id:
            payload["evidence_id"] = self.evidence_id
        return payload

    def serializable(self) -> dict[str, Any]:
        self.__post_init__()
        return self.canonical_payload(include_id=True)


@dataclass(frozen=True, slots=True)
class ResumeAuthorization:
    """Exact authority bound to one inspected evidence snapshot and next gate."""

    evidence_id: str
    request_fingerprint: str
    configuration_fingerprint: str
    next_gate: Gate

    def __post_init__(self) -> None:
        for value, label in (
            (self.evidence_id, "resume evidence id"),
            (self.request_fingerprint, "resume request fingerprint"),
            (self.configuration_fingerprint, "resume configuration fingerprint"),
        ):
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ValueError(f"{label} must be a lowercase SHA-256 digest")
        if type(self.next_gate) is not Gate or self.next_gate is Gate.PREFLIGHT:
            raise ValueError("resume next gate must use an exact terminal Gate")

    @classmethod
    def for_inspection(cls, inspected: InspectionEvidence) -> ResumeAuthorization:
        if cls is not ResumeAuthorization or type(inspected) is not InspectionEvidence:
            raise ValueError("resume authorization requires exact approved types")
        inspected.__post_init__()
        if inspected.state != "blocked-preflight" or inspected.next_gate is None:
            raise ValueError("complete inspection has no resumable next gate")
        reached = tuple(
            finding for finding in inspected.findings if finding.status != "not-reached"
        )
        if any(finding.observation_digest is None for finding in reached):
            raise ValueError("inspection contains non-resumable unadmitted observations")
        return cls(
            inspected.evidence_id,
            inspected.request_fingerprint,
            inspected.configuration_fingerprint,
            inspected.next_gate,
        )


def inspection_evidence_id(payload: Mapping[str, Any]) -> str:
    """Hash the exact sanitized inspection snapshot without persisting it."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if redact(canonical) != canonical:
        raise ValueError("inspection evidence payload contains unsafe material")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def redact(text: str) -> str:
    """Redact secret-shaped values, pointers, userinfo URLs, and private paths."""
    redacted = SECRET.sub("[REDACTED]", text)
    return PRIVATE_ABSOLUTE_PATH.sub("[REDACTED]", redacted)


def request_fingerprint(request: ProvisioningRequest, destination: Path) -> str:
    """Hash every non-capability request field after strict safety admission."""
    if type(request) is not ProvisioningRequest:
        raise ConfigurationError("request must use the exact provisioning request type")
    canonical_destination = _canonical_absolute_path(destination, "request destination")
    try:
        capability_presence = {
            "live_authorization_present": request.live_authorization is not None,
            "resume_authorization_present": request.resume_authorization is not None,
        }
    except AttributeError as error:
        raise ConfigurationError("request is missing required capability fields") from error
    fields = {
        "origin_url": request.origin_url,
        "beads_prefix": request.beads_prefix,
        "project_kind": request.project_kind,
        "description": request.description,
        "destination_confirmation": request.destination_confirmation,
    }
    payload: dict[str, str | None] = {}
    for name, value in fields.items():
        if value is None:
            if name != "destination_confirmation":
                raise ConfigurationError(f"request {name} must be an exact string")
            payload[name] = None
            continue
        if (
            name == "destination_confirmation"
            and type(value) is str
            and value.startswith("/")
        ):
            confirmation_path = _canonical_absolute_path(
                Path(value),
                "request destination_confirmation",
            )
            if value != str(confirmation_path):
                raise ConfigurationError(
                    "request destination_confirmation must be an exact canonical absolute Path string"
                )
            # Every absolute confirmation is lexical authority and must match
            # the canonical supplied destination exactly. This comparison is
            # deliberately independent of path prefix and filesystem state.
            if str(confirmation_path) != str(canonical_destination):
                raise ConfigurationError(
                    "request destination_confirmation absolute path must exactly match request destination"
                )
            # The sole admitted leading slash is already bound above. Validate
            # every remaining character with the ordinary unsafe-text policy so
            # exact matching cannot admit shell, pointer, URL-userinfo, or
            # credential-shaped syntax from a hostile destination argument.
            _reject_unsafe_text(
                value[1:],
                "request destination_confirmation",
                allow_empty=True,
            )
            payload[name] = value
            continue
        payload[name] = _reject_unsafe_text(
            value,
            f"request {name}",
            allow_empty=name in {"description", "destination_confirmation"},
        )
    payload.update(capability_presence)
    payload["destination"] = str(canonical_destination)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def live_evidence_to_json(evidence: LiveProvisioningEvidence) -> str:
    """Serialize only the exact safe live-evidence shape."""
    if type(evidence) is not LiveProvisioningEvidence:
        raise ValueError("live evidence must use the exact safe evidence type")
    evidence.__post_init__()
    payload = {
        "template_source_identity": evidence.template_source_identity,
        "template_tag": evidence.template_tag,
        "resolved_template_commit": evidence.resolved_template_commit,
        "config_digest": evidence.config_digest,
        "actual_database": evidence.actual_database,
        "manifest_identity": evidence.manifest_identity,
        "stable_issue_markers": list(evidence.stable_issue_markers),
        "validated_component_pins": [pin.canonical_fields() for pin in evidence.validated_component_pins],
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    # Construction validates every value; this is a defense-in-depth check over
    # the exact serialized artifact.  Redacting would make evidence ambiguous,
    # so unsafe evidence is rejected rather than rewritten.
    if redact(serialized) != serialized:
        raise ValueError("serialized live evidence contains unsafe material")
    return serialized


def live_evidence_from_json(serialized: str) -> LiveProvisioningEvidence:
    """Parse and validate an exact live-evidence JSON object."""
    if type(serialized) is not str:
        raise ValueError("live evidence JSON must be text")
    try:
        payload = json.loads(serialized)
    except json.JSONDecodeError as error:
        raise ValueError("live evidence JSON is malformed") from error
    if type(payload) is not dict or set(payload) != _LIVE_EVIDENCE_FIELDS:
        raise ValueError("live evidence JSON has missing or additional fields")
    markers = payload["stable_issue_markers"]
    pins_payload = payload["validated_component_pins"]
    if type(markers) is not list or any(type(marker) is not str for marker in markers):
        raise ValueError("live evidence issue markers must be a string array")
    if type(pins_payload) is not list:
        raise ValueError("live evidence component pins must be an object array")
    pins: list[ComponentPin] = []
    for item in pins_payload:
        if type(item) is not dict or set(item) != _COMPONENT_PIN_FIELDS:
            raise ValueError("live evidence component pin has an invalid shape")
        pins.append(
            ComponentPin(
                name=item["name"],
                source_identity=item["source_identity"],
                resolved_commit=item["resolved_commit"],
            )
        )
    scalar_fields = _LIVE_EVIDENCE_FIELDS - {"stable_issue_markers", "validated_component_pins"}
    if any(type(payload[field]) is not str for field in scalar_fields):
        raise ValueError("live evidence scalar fields must be strings")
    return LiveProvisioningEvidence(
        template_source_identity=payload["template_source_identity"],
        template_tag=payload["template_tag"],
        resolved_template_commit=payload["resolved_template_commit"],
        config_digest=payload["config_digest"],
        actual_database=payload["actual_database"],
        manifest_identity=payload["manifest_identity"],
        stable_issue_markers=tuple(markers),
        validated_component_pins=tuple(pins),
    )


def evidence_root() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "hermes/project-provisioning"


def persist(
    evidence: ProvisioningEvidence,
    root: Path | None = None,
    *,
    directory_fd: int | None = None,
) -> Path:
    """Atomically persist one sanitized ledger and durably commit its directory entry.

    A controller that already owns a verified directory descriptor passes it here;
    otherwise this function opens the supplied root with no-follow semantics.
    """
    root = root or evidence_root()
    serialized = json.dumps(evidence.serializable(), sort_keys=True, indent=2)
    # Reject rather than silently rewrite: redacting would make evidence
    # ambiguous (whether a "[REDACTED]" token was original or sanitized).
    # ProvisioningEvidence construction does not validate every field, so
    # persist() is the durable boundary and fails closed on unsafe material,
    # mirroring live_evidence_to_json and RenderProvenance.__post_init__.
    if redact(serialized) != serialized:
        raise ConfigurationError("evidence contains unsafe material and was not persisted")
    payload = serialized + "\n"
    destination_name = f"{evidence.request_fingerprint}-{evidence.run_id}.json"
    opened_here = False
    if directory_fd is None:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        try:
            directory_fd = os.open(root, os.O_RDONLY | directory | nofollow)
        except OSError as error:
            raise ValueError("evidence directory secure open failed") from error
        opened_here = True
    try:
        directory_metadata = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise ValueError("evidence root is not a directory")
        temporary_name = f".evidence-{secrets.token_hex(16)}.json"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(
                temporary_name,
                destination_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        except Exception:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            raise
    finally:
        if opened_here:
            os.close(directory_fd)
    return root / destination_name

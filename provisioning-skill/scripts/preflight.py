"""Fail-closed request parsing and non-mutating provisioning preflight."""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .models import ProvisioningRequest
from .vocabulary import PROJECT_KIND_VALUES, VISIBILITY_VALUES

SUPPORTED_KINDS = PROJECT_KIND_VALUES
SUPPORTED_VISIBILITIES = VISIBILITY_VALUES
PREFIX = re.compile(r"^[a-z][a-z0-9]{1,15}$")
HTTPS = re.compile(r"^https://github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?$")
SSH = re.compile(r"^git@github\.com:([^/\s]+)/([^/\s]+?)(?:\.git)?$")


class PreflightError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedOrigin:
    owner: str
    repository: str

    @property
    def identity(self) -> str:
        return f"{self.owner}/{self.repository}"


@dataclass(frozen=True)
class NormalizedInspection:
    """Exact existing route admitted for read-only inspection."""

    origin: ParsedOrigin
    destination: Path


def parse_origin(origin_url: str) -> ParsedOrigin:
    if not origin_url or any(char.isspace() for char in origin_url):
        raise PreflightError("origin must be a GitHub URL without whitespace")
    parsed = urlparse(origin_url)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise PreflightError("origin URL must not contain credential userinfo")
    match = HTTPS.fullmatch(origin_url) or SSH.fullmatch(origin_url)
    if not match:
        raise PreflightError("origin must be an HTTPS or SSH github.com repository URL")
    return ParsedOrigin(*match.groups())


def destination_for(origin: ParsedOrigin, confirmation: str | None, home: Path | None = None) -> Path:
    home = home or Path.home()
    roots = {"flexapp": home / "Projects/work", "pjbeyer": home / "Projects/pjbeyer"}
    root = roots.get(origin.owner)
    if root is None:
        if not confirmation:
            raise PreflightError("unsupported owner requires Phil-confirmed destination")
        candidate = Path(confirmation).expanduser().resolve()
        if candidate.name != origin.repository:
            raise PreflightError("confirmed destination must end with the repository name")
        return candidate
    return (root / origin.repository).resolve()


def _normalize_common(
    request: ProvisioningRequest,
    home: Path | None = None,
) -> tuple[ParsedOrigin, Path]:
    """Normalize request fields without deciding destination lifecycle state."""
    origin = parse_origin(request.origin_url)
    if request.project_kind not in SUPPORTED_KINDS:
        raise PreflightError("unsupported project kind")
    if request.visibility not in SUPPORTED_VISIBILITIES:
        raise PreflightError("unsupported visibility")
    if not PREFIX.fullmatch(request.beads_prefix):
        raise PreflightError("Beads prefix must be 2–16 lowercase alphanumeric characters starting with a letter")
    destination = destination_for(origin, request.destination_confirmation, home)
    if any(part == ".." for part in destination.parts):
        raise PreflightError("destination traversal is forbidden")
    return origin, destination


def normalize_request(request: ProvisioningRequest, home: Path | None = None) -> tuple[ParsedOrigin, Path]:
    """Normalize a fresh provisioning request and require destination absence."""
    origin, destination = _normalize_common(request, home)
    if destination.exists():
        raise PreflightError("routed destination already exists")
    return origin, destination


def normalize_inspection_request(
    request: ProvisioningRequest,
    home: Path | None = None,
) -> tuple[ParsedOrigin, Path]:
    """Normalize an inspect-only request and require the exact route to exist.

    This function performs reads only.  It never creates, repairs, resolves by
    mutation, or otherwise changes the destination.
    """
    origin, destination = _normalize_common(request, home)
    if not destination.exists():
        raise PreflightError("routed inspection destination does not exist")
    if not destination.is_dir():
        raise PreflightError("routed inspection destination is not a directory")
    return origin, destination


def required_tools_available() -> list[str]:
    return [name for name in ("git", "bd", "copier", "specify", "python3") if not shutil.which(name)]


def clean_beads_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("BEADS_DOLT_PORT", None)
    env.pop("BEADS_DOLT_DATABASE", None)
    return env

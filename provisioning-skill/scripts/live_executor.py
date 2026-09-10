"""Closed, read-only executor seam for controlled LiveAdapter tests.

This module has no production transport.  Callers select only a closed operation
and its exact typed request; only this module constructs argv.  The injected
transport exists solely to exercise policy and raw-result handling in tests.
Local Git request construction remains testable, but local Git transport is
intentionally unavailable because a lexical cwd cannot close its TOCTOU race.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol
from urllib.parse import urlparse


class LiveExecutorError(ValueError):
    """A controlled operation or transport result violated executor policy."""


class LiveOperation(Enum):
    """The complete read-only operation set admitted by this executor slice."""

    GIT_REMOTE_PREFLIGHT = "git-remote-preflight"
    LOCAL_GIT_READBACK = "local-git-readback"
    CENTRAL_DOLT_PROBE = "central-dolt-probe"


@dataclass(frozen=True, slots=True)
class GitRemotePreflightRequest:
    """Credential-free GitHub remote to identify and inspect for empty state."""

    origin_url: str


@dataclass(frozen=True, slots=True)
class LocalGitReadbackRequest:
    """Exact approved-owner repository path to inspect without mutation."""

    owner: str
    repository: str
    path: Path


@dataclass(frozen=True, slots=True)
class CentralDoltProbeRequest:
    """Parameter-free request for the fixed central-Dolt SELECT 1 probe."""


@dataclass(frozen=True, slots=True)
class RawResult:
    """Bounded raw process fields; no caller-supplied facts or data map."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True, slots=True)
class _TransportInvocation:
    """Internal argv-only request observable by the test transport."""

    operation: LiveOperation
    argv: tuple[str, ...]
    cwd: Path | None
    env: Mapping[str, str]
    timeout_seconds: int
    shell: bool = False


class _TestTransport(Protocol):
    """Test-only raw transport seam; no production implementation exists."""

    def invoke_for_test(self, request: _TransportInvocation) -> RawResult: ...


_ALLOWED_OWNERS = frozenset({"flexapp", "pjbeyer"})
_OWNER_ROOTS = MappingProxyType({"flexapp": Path("Projects/work"), "pjbeyer": Path("Projects/pjbeyer")})
_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_GITHUB_HTTPS = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9][A-Za-z0-9-]{0,38})/"
    r"(?P<repository>[A-Za-z0-9][A-Za-z0-9._-]{0,99})(?:\.git)?$"
)
_SECRET_SHAPED = re.compile(
    r"(?:ghp_|github_pat_|AKIA[0-9A-Z]{8,}|-----BEGIN|op://|"
    r"(?:token|password|passwd|secret|api[_-]?key)\s*[=:])",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?i)(token|password|passwd|secret|api[_-]?key)\s*[=:]\s*\S*"
)
_TOKEN_VALUE = re.compile(r"(?i)(?:ghp_|github_pat_|AKIA)[A-Za-z0-9_-]*")
_OP_REFERENCE = re.compile(r"(?i)op://[^\s]*")
# A partial or malformed BEGIN marker is secret-shaped too.  Without a complete
# END header, consume through the bounded input's end rather than returning it.
_PEM_BLOCK = re.compile(
    r"-----BEGIN.*?(?:-----END[^\r\n]*-----|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_URL_USERINFO = re.compile(r"https://[^/@\s]+@", re.IGNORECASE)
_FORBIDDEN_TOKENS = frozenset(
    {
        "--force",
        "-f",
        "--overwrite",
        "--unsafe",
        "push",
        "reset",
        "clean",
        "remove",
        "uninstall",
        "delete",
        "drop",
        "destroy",
        "start",
        "stop",
        "restart",
        "reconfigure",
        "bash",
        "sh",
        "zsh",
        "sudo",
    }
)
_SHELL_METACHARACTERS = frozenset(";&|`$><\n\r")
_BEADS_ENV_KEYS = frozenset({"BEADS_DOLT_PORT", "BEADS_DOLT_DATABASE"})

TIMEOUT_SECONDS = 15
MAX_OUTPUT_CHARS = 16_384
MINIMAL_ENVIRONMENT_KEYS = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "HOME",
        "XDG_CONFIG_HOME",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_ASKPASS",
        "GIT_OPTIONAL_LOCKS",
    }
)
_ALLOWED_CONTROLLED_ENV_KEYS = MINIMAL_ENVIRONMENT_KEYS | _BEADS_ENV_KEYS
# Remote preflight starts at the filesystem root: it is absolute, always exists,
# and ``parent == self`` leaves no ancestor in which Git could discover config.
NEUTRAL_GIT_CWD = Path("/")
_FIXED_ENVIRONMENT = MappingProxyType(
    {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        # Deliberately detached from the operator's home and credential stores.
        "HOME": "/var/empty",
        "XDG_CONFIG_HOME": "/var/empty",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_OPTIONAL_LOCKS": "0",
    }
)


def _minimal_environment(controlled: Mapping[str, str], *, program: str) -> Mapping[str, str]:
    """Copy only controlled non-secret keys; clear Beads overrides only for bd."""
    environment: dict[str, str] = {}
    for key, value in controlled.items():
        if key not in _ALLOWED_CONTROLLED_ENV_KEYS or not isinstance(value, str):
            continue
        if _SECRET_SHAPED.search(value) or "\x00" in value or "\n" in value or "\r" in value:
            raise LiveExecutorError("controlled environment contains secret-shaped or invalid material")
        environment[key] = value
    if program == "bd":
        for key in _BEADS_ENV_KEYS:
            environment.pop(key, None)
    return MappingProxyType(environment)


def _redact_and_bound(value: str) -> str:
    # Bound attacker-controlled transport text before any multiline scan.  A
    # partial PEM marker inside this window is redacted through the window end.
    redacted = value[:MAX_OUTPUT_CHARS]
    redacted = _PEM_BLOCK.sub("[REDACTED]", redacted)
    redacted = _URL_USERINFO.sub("[REDACTED]", redacted)
    redacted = _SECRET_VALUE.sub("[REDACTED]", redacted)
    redacted = _TOKEN_VALUE.sub("[REDACTED]", redacted)
    redacted = _OP_REFERENCE.sub("[REDACTED]", redacted)
    return redacted


def _reject_secret_or_unsafe_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise LiveExecutorError(f"{label} must be a nonempty plain string")
    if _SECRET_SHAPED.search(value):
        raise LiveExecutorError(f"{label} contains secret-shaped material")
    if any(character in value for character in _SHELL_METACHARACTERS):
        raise LiveExecutorError(f"{label} contains shell or control syntax")
    lowered = value.lower()
    if any(token in lowered.split() for token in _FORBIDDEN_TOKENS):
        raise LiveExecutorError(f"{label} contains an unsafe flag or operation")


def _remote_argv(request: GitRemotePreflightRequest) -> tuple[tuple[str, ...], Path | None]:
    _reject_secret_or_unsafe_text(request.origin_url, "origin URL")
    parsed = urlparse(request.origin_url)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise LiveExecutorError("origin URL must not contain credential userinfo")
    match = _GITHUB_HTTPS.fullmatch(request.origin_url)
    if match is None:
        raise LiveExecutorError("origin must be a credential-free HTTPS github.com repository URL")
    owner = match.group("owner")
    repository = match.group("repository")
    if owner not in _ALLOWED_OWNERS:
        raise LiveExecutorError("origin owner is outside the approved owner set")
    if repository in {".", ".."}:
        raise LiveExecutorError("origin repository name is unsafe")
    return (
        "git",
        "-c", "credential.helper=",
        "-c", "http.extraHeader=",
        "-c", "http.followRedirects=false",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "ls-remote", "--symref",
        request.origin_url, "HEAD",
    ), NEUTRAL_GIT_CWD


def _local_git_argv(request: LocalGitReadbackRequest, home: Path) -> tuple[tuple[str, ...], Path]:
    if request.owner not in _ALLOWED_OWNERS:
        raise LiveExecutorError("local Git owner is outside the approved owner set")
    _reject_secret_or_unsafe_text(request.repository, "repository name")
    if _REPOSITORY.fullmatch(request.repository) is None or request.repository in {".", ".."}:
        raise LiveExecutorError("repository name is unsafe")
    if not isinstance(request.path, Path) or not request.path.is_absolute():
        raise LiveExecutorError("local Git path must be absolute")
    expected = home / _OWNER_ROOTS[request.owner] / request.repository
    if request.path != expected:
        raise LiveExecutorError("local Git path is outside the exact approved owner route")
    owner_root = expected.parent
    resolved_home = home.resolve(strict=False)
    resolved_owner_root = owner_root.resolve(strict=False)
    resolved_path = request.path.resolve(strict=False)
    try:
        resolved_owner_root.relative_to(resolved_home)
        resolved_path.relative_to(resolved_owner_root)
    except ValueError as error:
        raise LiveExecutorError("local Git path resolves outside the approved owner root") from error
    path_text = str(request.path)
    _reject_secret_or_unsafe_text(path_text, "local Git path")
    if ".." in request.path.parts:
        raise LiveExecutorError("local Git path traversal is forbidden")
    return (
        "git",
        "--no-optional-locks",
        "-c", "core.fsmonitor=false",
        "-C", path_text,
        "status", "--porcelain=v1", "--branch",
    ), request.path


def _dolt_argv(request: CentralDoltProbeRequest) -> tuple[tuple[str, ...], Path | None]:
    del request
    return (
        "dolt",
        "--host",
        "127.0.0.1",
        "--port",
        "3307",
        "sql",
        "-r",
        "json",
        "-q",
        "SELECT 1 AS ok;",
    ), None


def _validate_built_invocation(invocation: _TransportInvocation) -> None:
    """Defense in depth: reject shell, mutation, service control, and secrets."""
    if invocation.shell or not invocation.argv:
        raise LiveExecutorError("controlled invocations must be non-shell argv")
    if not 0 < invocation.timeout_seconds <= 30:
        raise LiveExecutorError("controlled invocation timeout is not bounded")
    lowered = tuple(argument.lower() for argument in invocation.argv)
    if any(argument in _FORBIDDEN_TOKENS for argument in lowered):
        raise LiveExecutorError("controlled invocation contains a destructive or service-control form")
    for argument in invocation.argv:
        if not isinstance(argument, str) or "\x00" in argument:
            raise LiveExecutorError("controlled invocation contains an invalid argument")
        if _SECRET_SHAPED.search(argument):
            raise LiveExecutorError("controlled invocation contains secret-shaped material")
        # The sole semicolon is part of the exact, internal SELECT 1 literal;
        # all caller-controlled values are validated before argv construction.
        if (
            any(character in argument for character in _SHELL_METACHARACTERS)
            and not (
                invocation.operation is LiveOperation.CENTRAL_DOLT_PROBE
                and argument == "SELECT 1 AS ok;"
            )
        ):
            raise LiveExecutorError("controlled invocation contains shell syntax")
    if set(invocation.env) - _ALLOWED_CONTROLLED_ENV_KEYS:
        raise LiveExecutorError("controlled invocation environment is outside the allowlist")
    if invocation.operation is LiveOperation.GIT_REMOTE_PREFLIGHT:
        # Root terminates repository/config discovery.  The exact fixed env is
        # built from an allowlist (therefore no ambient GIT_DIR/GIT_WORK_TREE)
        # and disables both system and global Git config.
        if (
            invocation.cwd != NEUTRAL_GIT_CWD
            or not invocation.cwd.is_absolute()
            or invocation.cwd.parent != invocation.cwd
            or set(invocation.env) != MINIMAL_ENVIRONMENT_KEYS
            or invocation.env.get("GIT_CONFIG_NOSYSTEM") != "1"
            or invocation.env.get("GIT_CONFIG_GLOBAL") != "/dev/null"
            or "GIT_DIR" in invocation.env
            or "GIT_WORK_TREE" in invocation.env
        ):
            raise LiveExecutorError("remote Git preflight isolation is not fail closed")
    if invocation.argv[0] == "bd" and set(invocation.env) & _BEADS_ENV_KEYS:
        raise LiveExecutorError("Beads Dolt overrides must be absent from bd operations")


class ControlledLiveExecutor:
    """Map closed read-only operations to hard-coded argv for test transport.

    There is intentionally no ``run(argv)`` method and no production transport.
    A separately reviewed internal factory must own any future construction.
    """

    def __init__(self, *, transport: _TestTransport, approved_home: Path) -> None:
        if not isinstance(approved_home, Path) or not approved_home.is_absolute():
            raise LiveExecutorError("approved home must be an absolute path")
        if ".." in approved_home.parts:
            raise LiveExecutorError("approved home path traversal is forbidden")
        # The controlled executor drives only the test transport. A production
        # transport exposes `invoke`, not `invoke_for_test`; fail fast with a
        # typed error rather than an AttributeError at execute() time.
        if not hasattr(transport, "invoke_for_test"):
            raise LiveExecutorError(
                "controlled executor requires a test transport (invoke_for_test)"
            )
        self._transport = transport
        self._approved_home = approved_home

    def execute(
        self,
        operation: LiveOperation,
        parameters: GitRemotePreflightRequest | LocalGitReadbackRequest | CentralDoltProbeRequest,
    ) -> RawResult:
        """Exercise an admitted read-only operation through the test-only seam.

        Local Git readback deliberately stops after validating and building its
        fixed request.  Lexical/resolved-path checks cannot prevent symlink
        replacement between validation and process startup.  Transport remains
        unavailable until a separately reviewed production transport provides
        an inode-bound, no-follow working-directory capability.
        """
        if type(operation) is not LiveOperation:
            raise LiveExecutorError("unknown live operation")

        if operation is LiveOperation.GIT_REMOTE_PREFLIGHT:
            if type(parameters) is not GitRemotePreflightRequest:
                raise LiveExecutorError("live operation received the wrong request type")
            argv, cwd = _remote_argv(parameters)
        elif operation is LiveOperation.LOCAL_GIT_READBACK:
            if type(parameters) is not LocalGitReadbackRequest:
                raise LiveExecutorError("live operation received the wrong request type")
            # Keep the hard-coded construction seam testable, but do not hand a
            # lexical path to any transport: validation cannot close the TOCTOU.
            _local_git_argv(parameters, self._approved_home)
            raise LiveExecutorError(
                "local Git readback requires an inode-bound no-follow cwd capability "
                "and is intentionally unavailable"
            )
        elif operation is LiveOperation.CENTRAL_DOLT_PROBE:
            if type(parameters) is not CentralDoltProbeRequest:
                raise LiveExecutorError("live operation received the wrong request type")
            argv, cwd = _dolt_argv(parameters)
        else:  # pragma: no cover - guarded by exact enum admission above
            raise LiveExecutorError("unknown live operation")

        invocation = _TransportInvocation(
            operation=operation,
            argv=argv,
            cwd=cwd,
            env=_minimal_environment(_FIXED_ENVIRONMENT, program=argv[0]),
            timeout_seconds=TIMEOUT_SECONDS,
            shell=False,
        )
        _validate_built_invocation(invocation)
        result = self._transport.invoke_for_test(invocation)
        if type(result) is not RawResult:
            raise LiveExecutorError("test transport must return the exact raw result type")
        if (
            isinstance(result.returncode, bool)
            or not isinstance(result.returncode, int)
            or not isinstance(result.stdout, str)
            or not isinstance(result.stderr, str)
        ):
            raise LiveExecutorError("test transport returned invalid raw result fields")
        return RawResult(
            returncode=result.returncode,
            stdout=_redact_and_bound(result.stdout),
            stderr=_redact_and_bound(result.stderr),
        )

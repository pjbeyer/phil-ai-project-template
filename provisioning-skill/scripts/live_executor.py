"""Closed executor seams: a test transport and a production transport.

Callers select only a closed ``LiveOperation`` and its exact typed request; only
this module constructs argv, and every invocation is re-validated before spawn.

Two seams live here:

- ``ControlledLiveExecutor`` drives an injected test transport (``invoke_for_test``)
  to exercise policy and raw-result handling without spawning a subprocess.
- ``ProductionLiveExecutor`` drives the capability-gated production transport in
  ``production_transport.py`` (the only module permitted to import ``subprocess``);
  it is constructible only via that module's reviewed factory, never by a public
  CLI path. The TOCTOU-safe cwd pinning is implemented there.
"""
from __future__ import annotations

import os
import pwd
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
    """The complete operation set admitted by this executor slice.

    Read-only ops (preflight/probe/readback) are safe under the test transport.
    ``GIT_CLONE`` is the first mutating op: it builds a validated argv but is
    intentionally unavailable under the test transport (no in-memory transport
    can perform a real clone); only the separately-reviewed production transport
    executes it.
    """

    GIT_REMOTE_PREFLIGHT = "git-remote-preflight"
    LOCAL_GIT_READBACK = "local-git-readback"
    CENTRAL_DOLT_PROBE = "central-dolt-probe"
    DOLT_DATABASE_READBACK = "dolt-database-readback"
    DOLT_COMMIT = "dolt-commit"
    GIT_CLONE = "git-clone"
    GIT_REMOTE_READBACK = "git-remote-readback"
    GIT_TEMPLATE_REVISION = "git-template-revision"
    COPIER_RENDER = "copier-render"
    BEADS_INIT = "beads-init"
    BEADS_PREFIX_READ = "beads-prefix-read"
    DOLT_REMOTE_LIST = "dolt-remote-list"
    DOLT_REMOTE_ADD = "dolt-remote-add"
    BEADS_SETUP = "beads-setup"
    BEADS_SETUP_CHECK = "beads-setup-check"
    BEADS_HOOKS_INSTALL = "beads-hooks-install"
    BEADS_HOOKS_LIST = "beads-hooks-list"
    BEADS_BACKUP_INIT = "beads-backup-init"
    BEADS_BACKUP_SYNC = "beads-backup-sync"
    BEADS_BACKUP_STATUS = "beads-backup-status"
    COVERAGE_AUDIT = "coverage-audit"
    SPECKIT_INIT = "speckit-init"
    SPECKIT_EXTENSION_ADD = "speckit-extension-add"
    SPECKIT_INTEGRATION_READ = "speckit-integration-read"
    BD_SEARCH_ISSUES = "bd-search-issues"
    BD_CREATE_ISSUE = "bd-create-issue"
    BD_SHOW_ISSUE = "bd-show-issue"
    GIT_STATUS_ALL = "git-status-all"
    GIT_ADD_ALL = "git-add-all"
    GIT_DIFF_CACHED_NAMES = "git-diff-cached-names"
    GIT_DIFF_CACHED_TEXT = "git-diff-cached-text"
    GIT_COMMIT = "git-commit"
    GIT_REV_PARSE_HEAD = "git-rev-parse-head"
    GIT_STATUS_BRANCH = "git-status-branch"
    GIT_PUSH = "git-push"
    GIT_LS_REMOTE_MAIN = "git-ls-remote-main"
    BD_DOLT_PUSH = "bd-dolt-push"
    GIT_ORIGIN_ANONYMOUS_LS_REMOTE = "git-origin-anonymous-ls-remote"
    GIT_ORIGIN_AUTHENTICATED_LS_REMOTE = "git-origin-authenticated-ls-remote"


@dataclass(frozen=True, slots=True)
class GitRemotePreflightRequest:
    """Credential-free GitHub remote to identify and inspect for empty state."""

    origin_url: str


@dataclass(frozen=True, slots=True)
class GitOriginVisibilityRequest:
    """A credential-free GitHub origin URL whose visibility is to be resolved.

    One request type serves both probe regimes; the operation label chooses
    anonymous (credential-detached) versus authenticated (credential-chain)
    resolution. The URL carries no userinfo and names only approved owners.
    """

    origin_url: str


@dataclass(frozen=True, slots=True)
class LocalGitReadbackRequest:
    """Exact approved-owner repository path to inspect without mutation."""

    owner: str
    repository: str
    path: Path


@dataclass(frozen=True, slots=True)
class GitCloneRequest:
    """Clone an empty, approved origin into the canonical absent destination.

    The origin must be a credential-free HTTPS github.com URL under an approved
    owner; the destination must be an absolute, traversal-free path that does
    not yet exist. Authentication is delegated to the operator's credential
    helper (never a credential value in argv/env).
    """

    origin_url: str
    destination: Path


@dataclass(frozen=True, slots=True)
class GitRemoteReadbackRequest:
    """Read the remote origin URL of a local checkout for identity verification."""

    path: Path


@dataclass(frozen=True, slots=True)
class GitTemplateRevisionRequest:
    """Read the resolved commit of the approved template tag in a local checkout."""

    path: Path
    tag: str


@dataclass(frozen=True, slots=True)
class CopierRenderRequest:
    """Render the approved immutable template revision into the destination.

    ``template_source`` is the local checkout of the allowlisted template;
    ``destination`` is the cloned (empty) primary checkout. Answers are the
    non-secret, pre-validated render values; the tag is the immutable revision
    to render. No credential or private path may appear in any answer.
    """

    template_source: Path
    destination: Path
    tag: str
    answers: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class BeadsInitRequest:
    """Initialize Beads once in approved external server mode."""

    destination: Path
    prefix: str


@dataclass(frozen=True, slots=True)
class BeadsPrefixReadRequest:
    """Read the configured issue prefix back from the initialized repository."""

    destination: Path


@dataclass(frozen=True, slots=True)
class DoltRemoteListRequest:
    """List the repository's Dolt remotes (credential-free readback)."""

    destination: Path


@dataclass(frozen=True, slots=True)
class DoltRemoteAddRequest:
    """Add the credential-free HTTPS Git-backed Dolt origin remote."""

    destination: Path
    remote_url: str


@dataclass(frozen=True, slots=True)
class BeadsSetupRequest:
    """Run or check the intended Beads agent setup for one integration."""

    destination: Path
    integration: str
    check: bool


@dataclass(frozen=True, slots=True)
class BeadsHooksInstallRequest:
    """Install the managed Beads hooks."""

    destination: Path


@dataclass(frozen=True, slots=True)
class BeadsHooksListRequest:
    """Read back the managed Beads hooks."""

    destination: Path


@dataclass(frozen=True, slots=True)
class CentralDoltProbeRequest:
    """Parameter-free request for the fixed central-Dolt SELECT 1 probe."""


@dataclass(frozen=True, slots=True)
class DoltDatabaseReadbackRequest:
    """Name one central-Dolt database whose exact Beads schema is read back.

    The database value is validated as a safe generated identity before any
    argv is built; it is never interpolated into a shell.  The readback lists
    the database's tables on the fixed central server and requires the
    provisioner to observe the authoritative schema there, independently of the
    ``.beads/metadata.json`` the init wrote.
    """

    database: str


@dataclass(frozen=True, slots=True)
class DoltCommitRequest:
    """Commit pending working-set changes on one central-Dolt database.

    ``bd init`` seeds the ``config`` table (issue prefix, compaction knobs) but
    leaves that write uncommitted, which the G07 coverage audit (a clean
    working set is the established managed-repo convention) correctly flags.
    ``bd dolt commit`` is a silent no-op in external-server mode, so this
    operation drives the raw ``dolt commit -A`` against the fixed central
    server with an explicit, fixed author. ``database`` is the safely generated
    identity; ``message`` carries no shell/forbidden material.
    """

    database: str
    message: str


@dataclass(frozen=True, slots=True)
class BeadsBackupInitRequest:
    """Initialize the native backup destination at <repo>/.beads/backup."""

    destination: Path


@dataclass(frozen=True, slots=True)
class BeadsBackupSyncRequest:
    """Run the native backup sync against the configured destination."""

    destination: Path


@dataclass(frozen=True, slots=True)
class BeadsBackupStatusRequest:
    """Read native backup status as JSON for exact readback."""

    destination: Path


@dataclass(frozen=True, slots=True)
class CoverageAuditRequest:
    """Run the existing read-only coverage audit from its own scripts directory.

    ``scripts_dir`` is the runtime-derived ``<hermes_home>/scripts`` directory,
    ``hermes_home`` the operator's Hermes home, and ``state_home`` the operator's
    XDG state base. None is hard-coded; each is validated before the audit argv/env
    is built. The audit is read-only with respect to repositories, Dolt data, Cron
    configuration, credentials, and external systems.
    """

    scripts_dir: Path
    hermes_home: Path
    state_home: Path


@dataclass(frozen=True, slots=True)
class SpeckitInitRequest:
    """Initialize Hermes-primary SpecKit via the current ``specify`` CLI.

    The destination must be the cloned (rendered) checkout; the CLI scaffolds
    ``.specify`` there. No hand-copied files may substitute for CLI init (FR-012).
    The argv is fixed: `init --here --integration hermes --script sh
    --non-interactive`.
    """

    destination: Path


@dataclass(frozen=True, slots=True)
class SpeckitExtensionAddRequest:
    """Install one live-approved extension via the bundled default catalog.

    ``extension`` must be an exact member of the first-party allowlist
    (``agent-context``); community/unvetted names are rejected here even if a
    caller managed to reach this request type.
    """

    destination: Path
    extension: str


@dataclass(frozen=True, slots=True)
class SpeckitIntegrationReadRequest:
    """Read the current project's integration status as exact JSON readback."""

    destination: Path


@dataclass(frozen=True, slots=True)
class BdSearchIssuesRequest:
    """Search the project's own Beads tracker for one stable bootstrap identity.

    ``title`` is the stable duplicate-search key; the built argv scopes it with
    the ``project-bootstrap:`` external-ref prefix so only bootstrap issues match.
    """

    destination: Path
    title: str


@dataclass(frozen=True, slots=True)
class BdCreateIssueRequest:
    """Create one bootstrap issue in the project's own Beads tracker.

    ``marker`` must be an approved bootstrap marker; the builder derives the
    stable ``project-bootstrap:<marker>`` external ref and the description.
    """

    destination: Path
    marker: str
    title: str


@dataclass(frozen=True, slots=True)
class BdShowIssueRequest:
    """Read back one issue by its exact tracker id."""

    destination: Path
    issue_id: str


@dataclass(frozen=True, slots=True)
class GitStatusAllRequest:
    """Read the checkout's full porcelain status (all files, untracked included)."""

    destination: Path


@dataclass(frozen=True, slots=True)
class GitAddAllRequest:
    """Stage every change in the checkout (``git add --all``)."""

    destination: Path


@dataclass(frozen=True, slots=True)
class GitDiffCachedNamesRequest:
    """List the staged file paths (name-only)."""

    destination: Path


@dataclass(frozen=True, slots=True)
class GitDiffCachedTextRequest:
    """Read the full staged diff text for the secret scan."""

    destination: Path


@dataclass(frozen=True, slots=True)
class GitCommitRequest:
    """Create the atomic conventional-commit atomically on the staged set.

    ``message`` is the fixed provisioning commit message, re-validated here.
    """

    destination: Path
    message: str


@dataclass(frozen=True, slots=True)
class GitRevParseHeadRequest:
    """Read the exact full HEAD commit SHA."""

    destination: Path


@dataclass(frozen=True, slots=True)
class GitStatusBranchRequest:
    """Read the post-commit porcelain status with branch/head context."""

    destination: Path


@dataclass(frozen=True, slots=True)
class GitPushRequest:
    """Push the committed ``main`` to the exact approved ``origin`` upstream.

    Authentication is delegated to the operator's credential helper via the
    credential-chain environment regime (T080); no credential value enters
    argv/env. ``--force``
    is structurally unreachable (never in the module-built argv).
    """

    destination: Path


@dataclass(frozen=True, slots=True)
class GitLsRemoteMainRequest:
    """Read the live remote ``refs/heads/main`` SHA to prove HEAD == upstream."""

    destination: Path


@dataclass(frozen=True, slots=True)
class BdDoltPushRequest:
    """Push the project's Dolt commits to its configured ``origin`` remote."""

    destination: Path


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
# argv[0] program allowlist: the only executables a built invocation may name.
# Mirrors the rejected draft's `_ALLOWED_PROGRAMS`, retained here as a hard
# re-validation gate so a forged `_TransportInvocation` cannot run an arbitrary
# program through the production transport.
_ALLOWED_PROGRAMS = frozenset({"git", "dolt", "copier", "bd", "specify", "python3"})
# First-party, CLI-bundled SpecKit extension allowlist (FR-012 corrected).
# `agent-context` is authored by spec-kit-core and installs from the default
# catalog; community/unvetted names must never reach `specify extension add`.
_APPROVED_SPECKIT_EXTENSIONS = frozenset({"agent-context"})
# Stable bootstrap issue markers (FR-016); mirrors models.APPROVED_ISSUE_MARKERS
# at the command-construction boundary so a marker can never reach `bd create`
# without being one of the approved stable identities.
_APPROVED_BOOTSTRAP_MARKERS = frozenset(
    {
        "scope-readme",
        "first-speckit-spec",
        "macos-cli-real-tests",
        "homebrew-first-package",
        "homebrew-actions-secret",
        "homebrew-lifecycle-tests",
        "coding-agent-plugin-skeleton",
    }
)
# Floating refs must never be rendered or resolved as an immutable revision.
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

TIMEOUT_SECONDS = 15
# Server-mutating Beads/Dolt operations talk to the shared central Dolt server
# over the network and are measurably slow: `bd init --server --external`
# takes ~2 minutes against 127.0.0.1:3307 (measured 2026-09-13), far beyond the
# 15s default for local probes. These get a dedicated bounded budget so a live
# run is not aborted by a fixed short cap; the value is still hard-bounded so a
# hung operation cannot stall the run indefinitely.
SERVER_MUTATION_TIMEOUT_SECONDS = 300
MAX_OUTPUT_CHARS = 16_384
# Operations that talk to the shared central Dolt server and are measured slow
# (remote SQL, external-server Beads init/setup/backup, issue create/search,
# and remote/Dolt sync). They use the longer server budget above; local-only
# operations keep the short TIMEOUT_SECONDS. The authenticated BD_DOLT_PUSH is
# credential-chain (its own branch) but is listed here too so the timeout is
# consistent if routing ever changes.
_SERVER_MUTATION_OPERATIONS = frozenset({
    LiveOperation.BEADS_INIT,
    LiveOperation.BEADS_SETUP,
    LiveOperation.BEADS_SETUP_CHECK,
    LiveOperation.BEADS_HOOKS_INSTALL,
    LiveOperation.BEADS_HOOKS_LIST,
    LiveOperation.BEADS_BACKUP_INIT,
    LiveOperation.BEADS_BACKUP_SYNC,
    LiveOperation.BEADS_BACKUP_STATUS,
    LiveOperation.DOLT_REMOTE_LIST,
    LiveOperation.DOLT_REMOTE_ADD,
    LiveOperation.DOLT_COMMIT,
    LiveOperation.BD_SEARCH_ISSUES,
    LiveOperation.BD_CREATE_ISSUE,
    LiveOperation.BD_SHOW_ISSUE,
    LiveOperation.COVERAGE_AUDIT,
})
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
# The coverage audit is the sole bounded env-surface expansion: it must read the
# real Hermes home + XDG state base to resolve the shared manifest, Cron jobs, and
# its own state readback. These are non-secret location values, never credentials.
_AUDIT_ENV_KEYS = frozenset({"HERMES_HOME", "XDG_STATE_HOME", "DOLT_ROOT_PATH"})
_ALLOWED_CONTROLLED_ENV_KEYS = MINIMAL_ENVIRONMENT_KEYS | _BEADS_ENV_KEYS | _AUDIT_ENV_KEYS
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

# The three operations that must actually authenticate to a private origin:
# the authenticated origin-visibility probe, clone, and push. Everything else
# (including GIT_REMOTE_PREFLIGHT and the anonymous visibility probe) stays on
# the detached _FIXED_ENVIRONMENT.
_CREDENTIAL_CHAIN_OPERATIONS = frozenset(
    {
        LiveOperation.GIT_ORIGIN_AUTHENTICATED_LS_REMOTE,
        LiveOperation.GIT_CLONE,
        LiveOperation.GIT_PUSH,
        # Both authenticate to the private origin over HTTPS during the run:
        # GIT_LS_REMOTE_MAIN reads origin/main back for the pre/post-push proof,
        # and BD_DOLT_PUSH pushes the Dolt data ref to the `git+https` remote.
        LiveOperation.GIT_LS_REMOTE_MAIN,
        LiveOperation.BD_DOLT_PUSH,
    }
)

# The credential-chain regime must not accept caller-supplied env keys at all:
# unlike the detached regime (which tolerates the wider MINIMAL_ENVIRONMENT_KEYS
# because every value is re-derived from _FIXED_ENVIRONMENT), the credential
# regime resolves discovery from the real account HOME, so any ambient override
# of the config/discovery/askpass keys is a credential-helper injection channel.
_CREDENTIAL_CHAIN_ENV_KEYS = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "HOME",
        "GIT_TERMINAL_PROMPT",
        "GIT_OPTIONAL_LOCKS",
    }
)
# Phil-approved token passthrough (2026-09-13): his credential helper
# ``git-credential-gh-env`` reads account-scoped GitHub tokens from the process
# environment only (never Keychain/1Password/gh). For the three credential-chain
# git operations to authenticate, exactly these three account tokens are
# permitted to cross the child environment boundary. This is a named, bounded
# exception to the closed key set: the keys are fixed (no ambient overrides),
# values must match the github_pat_ token shape, and they are only admitted on
# credential-chain operations, never echoed in argv/stderr/stdout.
_CREDENTIAL_CHAIN_TOKEN_KEYS = frozenset(
    {
        "GH_TOKEN_PJBEYER",
        "GH_TOKEN_PJB_FLEX",
        "GH_TOKEN_FLEXAPP",
    }
)
# The credential-chain regime trusts PATH to resolve ``git`` (and, transitively,
# ``git-remote-https`` / the credential helper), so PATH is pinned to an exact
# value at the validation boundary — a forged PATH that shadows ``git`` with a
# malicious binary must not survive re-validation.
_CREDENTIAL_CHAIN_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

def _credential_chain_home() -> str:
    """Return the operator's account home from the passwd database.

    Deliberately NOT ``os.environ["HOME"]`` or ``Path.home()`` (which falls back
    to os.environ): both are taintable by anything that can set env on the
    Hermes process, and an attacker-chosen HOME places a ``credential.helper``
    definition (and ``~/.gitconfig`` discovery) under their control. The passwd
    database is authoritative for the invoking uid and is not env-influenced.
    """
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError as error:
        raise LiveExecutorError("could not resolve account home from passwd database") from error
    if not home or home in {"/", "/nonexistent", "/usr/sbin"}:
        raise LiveExecutorError("resolved account home is not a usable directory")
    return home


def _credential_chain_environment() -> Mapping[str, str]:
    """Build the credential-chain regime for the authenticated git operations.

    Distinct from ``_FIXED_ENVIRONMENT``: it preserves the operator's real
    account ``HOME`` (from the passwd database, not os.environ) and omits every
    credential-suppression guard present in the fixed env (no
    ``GIT_ASKPASS=/usr/bin/false``, no ``GIT_CONFIG_GLOBAL=/dev/null``, no
    ``GIT_CONFIG_NOSYSTEM=1``), so git resolves the operator's configured
    ``credential.helper`` chain. It is still built exclusively from the
    credential-chain key set, still carries no credential value (a home path is
    not secret-shaped), and the shared validator re-checks every value before
    spawn and pins the exact key set per operation.
    """
    home = _credential_chain_home()
    environment = {
        "PATH": _CREDENTIAL_CHAIN_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": home,
        # Anti-prompt guards only — these do NOT block the credential.helper
        # chain (that is what GIT_ASKPASS=/usr/bin/false and GIT_CONFIG_GLOBAL=
        # /dev/null were suppressing, and both are deliberately absent here).
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    # Phil-approved token passthrough (2026-09-13): inject exactly the three
    # account-scoped GitHub tokens his env-based credential helper needs, read
    # from the ambient process environment and admitted only when token-shaped.
    # The values are never echoed (argv/stderr/stdout redaction covers them).
    for key in _CREDENTIAL_CHAIN_TOKEN_KEYS:
        value = os.environ.get(key)
        if value is not None and _TOKEN_VALUE.fullmatch(value):
            environment[key] = value
    if set(environment) - (_CREDENTIAL_CHAIN_ENV_KEYS | _CREDENTIAL_CHAIN_TOKEN_KEYS):
        raise LiveExecutorError("credential-chain environment key set is not closed")
    for key, value in environment.items():
        if (
            not isinstance(value, str)
            or "\x00" in value
            or "\n" in value
            or "\r" in value
        ):
            raise LiveExecutorError(
                f"credential-chain environment {key!r} contains invalid material"
            )
        # Token values are shape-validated on admission; every other value must
        # be free of secret-shaped material (a token cannot smuggle in via a
        # non-token key).
        if key not in _CREDENTIAL_CHAIN_TOKEN_KEYS and _SECRET_SHAPED.search(value):
            raise LiveExecutorError(
                f"credential-chain environment {key!r} contains secret-shaped or invalid material"
            )
    return MappingProxyType(environment)



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


def _neutral_local_environment() -> Mapping[str, str]:
    """Local mutation/readback environment for non-networking tools.

    Local tools (``dolt``, ``copier``, ``specify``, ``bd``, and local git
    readback) need a writable account HOME to create their own config dirs
    (``~/.dolt``, ``~/.config``) and a PATH that includes the operator's local
    bin (``specify`` lives outside the Homebrew prefix). It remains
    credential-free: git's global/system config are isolated
    (``GIT_CONFIG_GLOBAL=/dev/null``, ``GIT_CONFIG_NOSYSTEM=1``), so git cannot
    discover the operator's ``credential.helper``, and the provisioning commit's
    author identity is supplied inline via ``-c`` rather than read from
    ``~/.gitconfig``. No credential value enters this environment; the shared
    validator re-checks every key and value before spawn.
    """
    home = _credential_chain_home()
    environment = {
        "PATH": f"{_CREDENTIAL_CHAIN_PATH}:{home}/.local/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    for key, value in environment.items():
        if (
            not isinstance(value, str)
            or _SECRET_SHAPED.search(value)
            or "\x00" in value
            or "\n" in value
            or "\r" in value
        ):
            raise LiveExecutorError(
                f"neutral local environment {key!r} contains secret-shaped or invalid material"
            )
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


def _validate_origin_url_argument(argument: str) -> None:
    """Re-validate an origin-URL argv slot at the validator boundary.

    Shared by the authenticated-probe and GIT_CLONE argv pins so a forged URL
    (credential userinfo, unapproved owner, non-GitHub host, ssh scheme, or
    ``.``/``..`` repository name) cannot slide past a shape-only pin. Mirrors
    the validation the builders perform, without trusting that a builder ran.
    """
    _reject_secret_or_unsafe_text(argument, "origin URL")
    parsed_url = urlparse(argument)
    if parsed_url.username or parsed_url.password or "@" in parsed_url.netloc:
        raise LiveExecutorError("origin URL must not contain credential userinfo")
    url_match = _GITHUB_HTTPS.fullmatch(argument)
    if url_match is None:
        raise LiveExecutorError("origin must be a credential-free HTTPS github.com repository URL")
    if url_match.group("owner") not in _ALLOWED_OWNERS:
        raise LiveExecutorError("origin owner is outside the approved owner set")
    if url_match.group("repository") in {".", ".."}:
        raise LiveExecutorError("origin repository name is unsafe")


def _validate_checkout_path_argument(argument: str) -> None:
    """Re-validate a destination-style argv slot against the approved route.

    Anchors to the authoritative approved project home — the same source the
    executor binds (``models._approved_project_home()``) — and proves the
    resolved path is that home's direct ``Projects/<owner-root>/<repo>`` child,
    mirroring ``_local_git_argv``'s resolve-containment proof. A lexical
    ``Projects/<owner-root>`` suffix is NOT sufficient: a forged path like
    ``/tmp/evil/Projects/pjbeyer/r`` would pass a suffix-only check and let git
    authenticate to an attacker-controlled repository. The home is resolved
    authoritatively (env/config), never from the invocation.
    """
    _reject_secret_or_unsafe_text(argument, "checkout destination")
    path = Path(argument)
    if not path.is_absolute():
        raise LiveExecutorError("checkout destination must be an absolute path")
    if ".." in path.parts:
        raise LiveExecutorError("checkout destination path traversal is forbidden")
    from .models import _approved_project_home

    approved_home = _approved_project_home()
    resolved_home = approved_home.resolve(strict=False)
    resolved_path = path.resolve(strict=False)
    try:
        relative = resolved_path.relative_to(resolved_home)
    except ValueError as error:
        raise LiveExecutorError(
            "checkout destination resolves outside the approved project home"
        ) from error
    owner_dirs = frozenset(Path(root).parts[-1] for root in _OWNER_ROOTS.values())
    if (
        len(relative.parts) != 3
        or relative.parts[0] != "Projects"
        or relative.parts[1] not in owner_dirs
    ):
        raise LiveExecutorError("checkout destination is outside the approved owner route")


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


def _origin_visibility_argv(
    request: GitOriginVisibilityRequest,
    *,
    detached: bool = True,
) -> tuple[tuple[str, ...], Path | None]:
    """Build the origin-visibility ``git ls-remote`` argv.

    Validation mirrors ``_remote_argv`` (credential-free approved HTTPS origin).
    ``detached=True`` (the anonymous probe) adds ``credential.helper=`` and
    ``http.extraHeader=`` so no ambient auth can leak into the read; the
    credential-chain regime runs on ``detached=False``, which omits both so git
    resolves the operator's configured ``credential.helper``. Exit 0 on a public
    (or principal-readable) origin; nonzero on a private/unreachable one — the
    adapter's parser maps the pair of exit codes to a closed visibility result.
    """
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
    argv: list[str] = ["git"]
    if detached:
        argv += ["-c", "credential.helper=", "-c", "http.extraHeader="]
    argv += [
        "-c", "http.followRedirects=false",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "ls-remote", "--symref",
        request.origin_url, "HEAD",
    ]
    return tuple(argv), NEUTRAL_GIT_CWD


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


def _git_clone_argv(request: GitCloneRequest) -> tuple[tuple[str, ...], Path | None]:
    """Build the exact, credential-free clone argv for an approved origin.

    The destination must be absolute, traversal-free, and not yet exist (the
    adapter asserts absence before calling this). The clone is a full checkout
    of the empty origin's primary branch; ``--no-tags`` avoids pulling any
    mutable tag surface. Authentication is delegated to the operator's
    credential helper via the credential-chain environment regime (T080); no
    credential value enters argv/env.

    The clone runs from ``NEUTRAL_GIT_CWD`` (filesystem root) so the child
    never inherits the Hermes process cwd: the destination is an absolute path
    in argv, and ``parent == self`` at root leaves no ancestor in which Git
    could discover a repository-level config. Credential-helper discovery is
    driven by the preserved ``HOME`` env, not by the working directory.
    """
    if not isinstance(request.destination, Path) or not request.destination.is_absolute():
        raise LiveExecutorError("clone destination must be an absolute path")
    if ".." in request.destination.parts:
        raise LiveExecutorError("clone destination path traversal is forbidden")
    path_text = str(request.destination)
    _reject_secret_or_unsafe_text(path_text, "clone destination")
    _reject_secret_or_unsafe_text(request.origin_url, "clone origin URL")
    parsed = urlparse(request.origin_url)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise LiveExecutorError("clone origin URL must not contain credential userinfo")
    match = _GITHUB_HTTPS.fullmatch(request.origin_url)
    if match is None:
        raise LiveExecutorError("clone origin must be a credential-free HTTPS github.com repository URL")
    owner = match.group("owner")
    repository = match.group("repository")
    if owner not in _ALLOWED_OWNERS:
        raise LiveExecutorError("clone origin owner is outside the approved owner set")
    if repository in {".", ".."}:
        raise LiveExecutorError("clone origin repository name is unsafe")
    return (
        "git",
        "clone",
        "--origin",
        "origin",
        "--no-tags",
        request.origin_url,
        path_text,
    ), NEUTRAL_GIT_CWD


def _git_remote_readback_argv(request: GitRemoteReadbackRequest) -> tuple[tuple[str, ...], Path]:
    """Read the local checkout's origin remote URL (identity readback)."""
    if not isinstance(request.path, Path) or not request.path.is_absolute():
        raise LiveExecutorError("remote readback path must be absolute")
    if ".." in request.path.parts:
        raise LiveExecutorError("remote readback path traversal is forbidden")
    path_text = str(request.path)
    _reject_secret_or_unsafe_text(path_text, "remote readback path")
    return (
        "git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-C",
        path_text,
        "remote",
        "get-url",
        "origin",
    ), request.path


def _git_template_revision_argv(request: GitTemplateRevisionRequest) -> tuple[tuple[str, ...], Path]:
    """Resolve the approved template tag to its immutable commit in the checkout."""
    if not isinstance(request.path, Path) or not request.path.is_absolute():
        raise LiveExecutorError("template revision path must be absolute")
    if ".." in request.path.parts:
        raise LiveExecutorError("template revision path traversal is forbidden")
    path_text = str(request.path)
    _reject_secret_or_unsafe_text(path_text, "template revision path")
    _reject_secret_or_unsafe_text(request.tag, "template revision tag")
    # The tag must be an explicit version-shaped non-floating ref; reject any
    # shell metacharacter or floating ref before it reaches git.
    if request.tag in _FLOATING_REFS:
        raise LiveExecutorError("template revision tag must be explicit and non-floating")
    return (
        "git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-C",
        path_text,
        "rev-parse",
        f"{request.tag}^{{commit}}",
    ), request.path


def _copier_render_argv(request: CopierRenderRequest) -> tuple[tuple[str, ...], Path]:
    """Build the exact Copier render argv from pre-validated non-secret answers."""
    if not isinstance(request.template_source, Path) or not request.template_source.is_absolute():
        raise LiveExecutorError("render template source must be absolute")
    if not isinstance(request.destination, Path) or not request.destination.is_absolute():
        raise LiveExecutorError("render destination must be absolute")
    for label, path in (("template source", request.template_source), ("destination", request.destination)):
        if ".." in path.parts:
            raise LiveExecutorError(f"render {label} path traversal is forbidden")
        _reject_secret_or_unsafe_text(str(path), f"render {label} path")
    _reject_secret_or_unsafe_text(request.tag, "render template tag")
    if request.tag in _FLOATING_REFS:
        raise LiveExecutorError("render template tag must be explicit and non-floating")
    if type(request.answers) is not tuple or not request.answers:
        raise LiveExecutorError("render answers must be a nonempty tuple")
    seen: set[str] = set()
    argv: list[str] = [
        "copier", "copy", "--defaults", "--skip-tasks", "--vcs-ref", request.tag,
    ]
    for key, value in request.answers:
        if type(key) is not str or type(value) is not str:
            raise LiveExecutorError("render answers must be plain strings")
        _reject_secret_or_unsafe_text(key, "render answer key")
        # An empty answer value is safe and legitimate (e.g. an omitted
        # project_description); it carries no secret, shell, or forbidden-token
        # form. Non-empty values are still fully validated by the shared guard.
        if value:
            _reject_secret_or_unsafe_text(value, "render answer value")
        if key in seen:
            raise LiveExecutorError("render answer keys must be unique")
        seen.add(key)
        argv.extend(("--data", f"{key}={value}"))
    argv.extend((str(request.template_source), str(request.destination)))
    return tuple(argv), request.destination


def _beads_destination_argv(request: object, *, destination: Path, args: tuple[str, ...]) -> tuple[tuple[str, ...], Path]:
    """Validate a bd destination and build a fixed argv in that checkout."""
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise LiveExecutorError("beads destination must be absolute")
    if ".." in destination.parts:
        raise LiveExecutorError("beads destination path traversal is forbidden")
    path_text = str(destination)
    _reject_secret_or_unsafe_text(path_text, "beads destination")
    return ("bd", *args), destination


def _beads_init_argv(request: BeadsInitRequest) -> tuple[tuple[str, ...], Path]:
    _reject_secret_or_unsafe_text(request.prefix, "beads prefix")
    if re.fullmatch(r"[a-z][a-z0-9]{1,15}", request.prefix) is None:
        raise LiveExecutorError("beads prefix must be 2-16 lowercase alphanumeric starting with a letter")
    return _beads_destination_argv(
        request,
        destination=request.destination,
        args=(
            "init", "--server", "--external", "--server-host", "127.0.0.1",
            "--server-port", "3307", "--prefix", request.prefix,
            "--non-interactive", "--role", "maintainer", "--skip-agents", "--skip-hooks",
        ),
    )


def _beads_prefix_read_argv(request: BeadsPrefixReadRequest) -> tuple[tuple[str, ...], Path]:
    return _beads_destination_argv(
        request, destination=request.destination, args=("config", "get", "issue_prefix", "--json")
    )


def _dolt_remote_list_argv(request: DoltRemoteListRequest) -> tuple[tuple[str, ...], Path]:
    return _beads_destination_argv(
        request, destination=request.destination, args=("dolt", "remote", "list", "--json")
    )


def _dolt_remote_add_argv(request: DoltRemoteAddRequest) -> tuple[tuple[str, ...], Path]:
    _reject_secret_or_unsafe_text(request.remote_url, "dolt remote url")
    parsed = urlparse(request.remote_url)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise LiveExecutorError("dolt remote url must not contain credential userinfo")
    if not request.remote_url.startswith("git+https://github.com/"):
        raise LiveExecutorError("dolt remote url must be a credential-free git+https github URL")
    return _beads_destination_argv(
        request, destination=request.destination, args=("dolt", "remote", "add", "origin", request.remote_url)
    )


def _beads_setup_argv(request: BeadsSetupRequest) -> tuple[tuple[str, ...], Path]:
    _reject_secret_or_unsafe_text(request.integration, "beads integration")
    if request.integration not in ("claude", "codex"):
        raise LiveExecutorError("beads integration is outside the approved set")
    args = ("setup", request.integration)
    if request.check:
        args = args + ("--check",)
    return _beads_destination_argv(request, destination=request.destination, args=args)


def _beads_hooks_install_argv(request: BeadsHooksInstallRequest) -> tuple[tuple[str, ...], Path]:
    return _beads_destination_argv(request, destination=request.destination, args=("hooks", "install"))


def _beads_hooks_list_argv(request: BeadsHooksListRequest) -> tuple[tuple[str, ...], Path]:
    return _beads_destination_argv(request, destination=request.destination, args=("hooks", "list", "--json"))


def _backup_root(request: BeadsBackupInitRequest) -> Path:
    if not isinstance(request.destination, Path) or not request.destination.is_absolute():
        raise LiveExecutorError("backup destination must be an absolute path")
    if ".." in request.destination.parts:
        raise LiveExecutorError("backup destination path traversal is forbidden")
    _reject_secret_or_unsafe_text(str(request.destination), "backup destination")
    return request.destination / ".beads" / "backup"


def _beads_backup_init_argv(request: BeadsBackupInitRequest) -> tuple[tuple[str, ...], Path]:
    backup_root = _backup_root(request)
    _reject_secret_or_unsafe_text(str(backup_root), "backup root path")
    return _beads_destination_argv(
        request, destination=request.destination, args=("backup", "init", str(backup_root))
    )


def _beads_backup_sync_argv(request: BeadsBackupSyncRequest) -> tuple[tuple[str, ...], Path]:
    return _beads_destination_argv(
        request, destination=request.destination, args=("backup", "sync")
    )


def _beads_backup_status_argv(request: BeadsBackupStatusRequest) -> tuple[tuple[str, ...], Path]:
    return _beads_destination_argv(
        request, destination=request.destination, args=("backup", "status", "--json")
    )


def _coverage_audit_argv(request: CoverageAuditRequest) -> tuple[tuple[str, ...], Path]:
    if not isinstance(request.scripts_dir, Path) or not request.scripts_dir.is_absolute():
        raise LiveExecutorError("coverage audit scripts dir must be an absolute path")
    if not isinstance(request.hermes_home, Path) or not request.hermes_home.is_absolute():
        raise LiveExecutorError("coverage audit hermes home must be an absolute path")
    if not isinstance(request.state_home, Path) or not request.state_home.is_absolute():
        raise LiveExecutorError("coverage audit state home must be an absolute path")
    for label, path in (
        ("coverage audit scripts dir", request.scripts_dir),
        ("coverage audit hermes home", request.hermes_home),
        ("coverage audit state home", request.state_home),
    ):
        if ".." in path.parts:
            raise LiveExecutorError(f"{label} path traversal is forbidden")
        _reject_secret_or_unsafe_text(str(path), label)
    script = request.scripts_dir / "audit_beads_cron_coverage.py"
    if script.parent != request.scripts_dir:
        raise LiveExecutorError("coverage audit script must live directly in the scripts dir")
    _reject_secret_or_unsafe_text(str(script), "coverage audit script")
    return ("python3", str(script)), request.scripts_dir


def _speckit_destination(request: object, destination: Path) -> Path:
    """Validate a SpecKit destination checkout (absolute, traversal-free)."""
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise LiveExecutorError("specify destination must be an absolute path")
    if ".." in destination.parts:
        raise LiveExecutorError("specify destination path traversal is forbidden")
    _reject_secret_or_unsafe_text(str(destination), "specify destination")
    return destination


def _speckit_init_argv(request: SpeckitInitRequest) -> tuple[tuple[str, ...], Path]:
    destination = _speckit_destination(request, request.destination)
    return (
        "specify",
        "init",
        "--here",
        "--force",
        "--integration",
        "hermes",
        "--script",
        "sh",
        "--non-interactive",
    ), destination


def _speckit_extension_add_argv(
    request: SpeckitExtensionAddRequest,
) -> tuple[tuple[str, ...], Path]:
    destination = _speckit_destination(request, request.destination)
    _reject_secret_or_unsafe_text(request.extension, "specify extension")
    # First-party allowlist only; community/unvetted names are rejected here.
    if request.extension not in _APPROVED_SPECKIT_EXTENSIONS:
        raise LiveExecutorError(
            "specify extension is outside the first-party live-installable allowlist"
        )
    return ("specify", "extension", "add", request.extension), destination


def _speckit_integration_read_argv(
    request: SpeckitIntegrationReadRequest,
) -> tuple[tuple[str, ...], Path]:
    destination = _speckit_destination(request, request.destination)
    return ("specify", "integration", "status", "--json"), destination


def _bd_destination(request: object, destination: Path) -> Path:
    """Validate a Beads tracker destination (absolute, traversal-free)."""
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise LiveExecutorError("beads destination must be an absolute path")
    if ".." in destination.parts:
        raise LiveExecutorError("beads destination path traversal is forbidden")
    _reject_secret_or_unsafe_text(str(destination), "beads destination")
    return destination


def _bd_search_issues_argv(request: BdSearchIssuesRequest) -> tuple[tuple[str, ...], Path]:
    destination = _bd_destination(request, request.destination)
    _reject_secret_or_unsafe_text(request.title, "bd search title")
    return (
        "bd",
        "search",
        "--query",
        request.title,
        "--external-contains",
        "project-bootstrap:",
        "--status",
        "all",
        "--json",
    ), destination


def _bd_create_issue_argv(request: BdCreateIssueRequest) -> tuple[tuple[str, ...], Path]:
    destination = _bd_destination(request, request.destination)
    _reject_secret_or_unsafe_text(request.marker, "bd create marker")
    if request.marker not in _APPROVED_BOOTSTRAP_MARKERS:
        raise LiveExecutorError("bd create marker is outside the approved bootstrap marker set")
    _reject_secret_or_unsafe_text(request.title, "bd create title")
    external_ref = f"project-bootstrap:{request.marker}"
    return (
        "bd",
        "create",
        request.title,
        "--type",
        "task",
        "--external-ref",
        external_ref,
        "--description",
        f"Bootstrap marker: {external_ref}",
        "--json",
    ), destination


def _bd_show_issue_argv(request: BdShowIssueRequest) -> tuple[tuple[str, ...], Path]:
    destination = _bd_destination(request, request.destination)
    _reject_secret_or_unsafe_text(request.issue_id, "bd show issue id")
    return ("bd", "show", request.issue_id, "--json"), destination


def _git_checkout_destination(request: object, destination: Path) -> Path:
    """Validate a git checkout destination (absolute, traversal-free)."""
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise LiveExecutorError("git checkout destination must be an absolute path")
    if ".." in destination.parts:
        raise LiveExecutorError("git checkout destination path traversal is forbidden")
    _reject_secret_or_unsafe_text(str(destination), "git checkout destination")
    return destination


def _git_status_all_argv(request: GitStatusAllRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return (
        "git", "--no-optional-locks", "-C", str(destination),
        "status", "--porcelain=v1", "--branch", "--untracked-files=all",
    ), destination


def _git_add_all_argv(request: GitAddAllRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return ("git", "--no-optional-locks", "-C", str(destination), "add", "--all"), destination


def _git_diff_cached_names_argv(request: GitDiffCachedNamesRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return (
        "git", "--no-optional-locks", "-C", str(destination),
        "diff", "--cached", "--name-only",
    ), destination


def _git_diff_cached_text_argv(request: GitDiffCachedTextRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return (
        "git", "--no-optional-locks", "-C", str(destination),
        "diff", "--cached",
    ), destination


def _git_commit_argv(request: GitCommitRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    _reject_secret_or_unsafe_text(request.message, "commit message")
    return (
        "git", "--no-optional-locks", "-C", str(destination),
        "-c", "user.name=Phil Beyer",
        "-c", "user.email=6152278+pjbeyer@users.noreply.github.com",
        "commit", "-m", request.message,
    ), destination


def _git_rev_parse_head_argv(request: GitRevParseHeadRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return (
        "git", "--no-optional-locks", "-C", str(destination), "rev-parse", "HEAD",
    ), destination


def _git_status_branch_argv(request: GitStatusBranchRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return (
        "git", "--no-optional-locks", "-C", str(destination),
        "status", "--porcelain=v1", "--branch",
    ), destination


def _git_push_argv(request: GitPushRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return (
        "git", "--no-optional-locks", "-C", str(destination),
        "push", "--set-upstream", "origin", "main",
    ), destination


def _git_ls_remote_main_argv(request: GitLsRemoteMainRequest) -> tuple[tuple[str, ...], Path]:
    destination = _git_checkout_destination(request, request.destination)
    return (
        "git", "--no-optional-locks", "-C", str(destination),
        "ls-remote", "origin", "refs/heads/main",
    ), destination


def _bd_dolt_push_argv(request: BdDoltPushRequest) -> tuple[tuple[str, ...], Path]:
    destination = _bd_destination(request, request.destination)
    return ("bd", "dolt", "push", "--remote", "origin"), destination


def _dolt_argv(request: CentralDoltProbeRequest) -> tuple[tuple[str, ...], Path | None]:
    del request
    return (
        "dolt",
        "--host",
        "127.0.0.1",
        "--port",
        "3307",
        "--no-tls",
        "sql",
        "-r",
        "json",
        "-q",
        "SELECT 1 AS ok;",
    ), None


def _dolt_database_readback_argv(
    request: DoltDatabaseReadbackRequest,
) -> tuple[tuple[str, ...], Path | None]:
    """List one central-dolt database's tables for independence verification.

    The database identity is re-validated here (defense in depth) as a safe
    generated name before it is placed into the fixed-quote-free argv.  The
    query is a fixed ``SHOW TABLES`` on the safe identity; no caller-controlled
    SQL reaches the server. Backticks and the trailing semicolon are omitted
    because the identity is already constrained to ``[A-Za-z][A-Za-z0-9_]+``
    (no quoting needed) and ``;`` is a shell metacharacter the validator
    would flag.
    """
    database = request.database
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,127}", database) is None:
        raise LiveExecutorError("dolt database readback received an unsafe identity")
    return (
        "dolt",
        "--host",
        "127.0.0.1",
        "--port",
        "3307",
        "--no-tls",
        "sql",
        "-r",
        "json",
        "-q",
        f"SHOW TABLES FROM {database}",
    ), None


# Fixed, module-constructed author for the raw-Dolt commit. `dolt commit --author`
# requires the `Name <email>` format; the angle brackets are shell
# metacharacters that the shared validator otherwise rejects, so this exact
# literal is the ONLY value admitted for the DOLT_COMMIT author slot (exempted
# in _validate_built_invocation). It mirrors the git provisioning commit
# identity (live_executor._git_commit_argv) and carries no credential.
_DOLT_COMMIT_AUTHOR = "Phil Beyer <6152278+pjbeyer@users.noreply.github.com>"


def _dolt_commit_argv(
    request: DoltCommitRequest,
) -> tuple[tuple[str, ...], Path | None]:
    """Commit pending working-set changes on one central-Dolt database.

    ``database`` is re-validated as a safe generated identity; ``message`` is
    checked for shell/forbidden/secret material. argv is fixed and exact:
    ``dolt --host 127.0.0.1 --port 3307 --no-tls --use-db <db> commit -A
    -m <message> --author <_DOLT_COMMIT_AUTHOR>``. ``commit -A`` stages and
    commits the working set without touching service control or remote state.
    """
    database = request.database
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,127}", database) is None:
        raise LiveExecutorError("dolt commit received an unsafe database identity")
    _reject_secret_or_unsafe_text(request.message, "dolt commit message")
    return (
        "dolt",
        "--host",
        "127.0.0.1",
        "--port",
        "3307",
        "--no-tls",
        "--use-db",
        database,
        "commit",
        "-A",
        "-m",
        request.message,
        "--author",
        _DOLT_COMMIT_AUTHOR,
    ), None


def _assert_exact_push_shape(invocation: _TransportInvocation) -> None:
    """Pin the two approved push argv to their exact module-constructed shapes.

    The operation label on ``_TransportInvocation`` is caller-suppliable, so it
    alone must not admit a push argv the builders never constructed. Reject any
    deviation from the exact tokens (dynamic ``-C <destination>`` value aside)
    so a forged ``git push --delete``/``--force-with-lease`` labeled GIT_PUSH
    cannot pass re-validation.
    """
    if invocation.operation is LiveOperation.GIT_PUSH:
        argv = invocation.argv
        if len(argv) != 8 or argv[0] != "git" or argv[1] != "--no-optional-locks" or argv[2] != "-C":
            raise LiveExecutorError("git push argv does not match the exact constructed shape")
        if argv[4:] != ("push", "--set-upstream", "origin", "main"):
            raise LiveExecutorError("git push argv does not match the exact constructed shape")
        return
    if invocation.operation is LiveOperation.BD_DOLT_PUSH:
        if invocation.argv != ("bd", "dolt", "push", "--remote", "origin"):
            raise LiveExecutorError("bd dolt push argv does not match the exact constructed shape")
        return
    raise LiveExecutorError("push exception is not admitted for this operation")


def _validate_built_invocation(invocation: _TransportInvocation) -> None:
    """Defense in depth: reject shell, mutation, service control, and secrets."""
    if invocation.shell or not invocation.argv:
        raise LiveExecutorError("controlled invocations must be non-shell argv")
    if not 0 < invocation.timeout_seconds <= SERVER_MUTATION_TIMEOUT_SECONDS:
        raise LiveExecutorError("controlled invocation timeout is not bounded")
    # argv[0] must be a provisioner-allowed program. This closes the reviewer
    # finding that a hand-built invocation could run an arbitrary program.
    if invocation.argv[0] not in _ALLOWED_PROGRAMS:
        raise LiveExecutorError("controlled invocation program is outside the allowlist")
    lowered = tuple(argument.lower() for argument in invocation.argv)
    # The fixed SpecKit init argv carries `--script sh` where "sh" is a data
    # value selecting the scaffolded script dialect (argv[0] is ``specify``, not
    # a shell program); it is never a shell invocation. Permit it only in that
    # exact, module-constructed form.
    speckit_script_value = (
        invocation.operation is LiveOperation.SPECKIT_INIT and lowered[0] == "specify"
    )
    # The fixed SpecKit init argv also carries `--force`, which merges SpecKit's
    # scaffold into the already-populated checkout (G03 Copier render + G04 Beads
    # init precede G08). It is the documented canonical form for `specify init
    # --here` into a non-empty directory and is admitted ONLY as the exact,
    # standalone `--force` token on SPECKIT_INIT — never an attached `--force=…`
    # or `-f…` form, which stay hard-blocked below.
    speckit_force_value = (
        invocation.operation is LiveOperation.SPECKIT_INIT and lowered[0] == "specify"
    )
    # The narrow remote-write exception (approved 2026-09-11): the literal token
    # `push` is permitted ONLY for the two exact module-constructed push argv
    # (`git push --set-upstream origin main`, `bd dolt push --remote origin`).
    # No other operation may carry `push`, and `--force`/`-f` stay hard-blocked
    # by their own tokens below. This is the sole gate on remote-write verbs.
    push_value = invocation.operation in (
        LiveOperation.GIT_PUSH,
        LiveOperation.BD_DOLT_PUSH,
    )
    # The push exception is exact-shape pinned: the operation label is
    # caller-suppliable, so it alone must not admit an unexpected argv. A
    # hand-built `git push --delete origin main` labeled GIT_PUSH must fail.
    if push_value:
        _assert_exact_push_shape(invocation)
    if any(
        argument in _FORBIDDEN_TOKENS
        and not (speckit_script_value and argument == "sh")
        and not (speckit_force_value and argument == "--force")
        and not (push_value and argument == "push")
        for argument in lowered
    ):
        raise LiveExecutorError("controlled invocation contains a destructive or service-control form")
    for argument in invocation.argv:
        if not isinstance(argument, str) or "\x00" in argument:
            raise LiveExecutorError("controlled invocation contains an invalid argument")
        if _SECRET_SHAPED.search(argument):
            raise LiveExecutorError("controlled invocation contains secret-shaped material")
        # Any dangerous flag prefix in an attached form (`--force=…`, `-f…`)
        # is rejected here even when the whole-word scan above misses it.
        # The exact standalone `--force` token is admitted only on SPECKIT_INIT
        # (see speckit_force_value); attached `--force=…`/`-f…` stay blocked.
        if (
            argument.startswith(("--force", "-f"))
            and not (speckit_force_value and argument == "--force")
        ) or "\x00" in argument:
            raise LiveExecutorError("controlled invocation contains a destructive or service-control form")
        # The sole semicolon is part of the exact, internal SELECT 1 literal;
        # all caller-controlled values are validated before argv construction.
        # Likewise the DOLT_COMMIT author literal is fixed module state: `dolt
        # commit --author` requires `Name <email>`, whose angle brackets are
        # shell metacharacters, so ONLY this exact constant is exempted.
        if (
            any(character in argument for character in _SHELL_METACHARACTERS)
            and not (
                invocation.operation is LiveOperation.CENTRAL_DOLT_PROBE
                and argument == "SELECT 1 AS ok;"
            )
            and not (
                invocation.operation is LiveOperation.DOLT_COMMIT
                and argument == _DOLT_COMMIT_AUTHOR
            )
        ):
            raise LiveExecutorError("controlled invocation contains shell syntax")
    token_keys_present = set(invocation.env) & _CREDENTIAL_CHAIN_TOKEN_KEYS
    if token_keys_present and invocation.operation not in _CREDENTIAL_CHAIN_OPERATIONS:
        # Account tokens may ride only the credential-chain regime; detached
        # operations (preflight, anonymous visibility probe) stay credential-free.
        raise LiveExecutorError("credential token keys are not admitted on a detached operation")
    if set(invocation.env) - (
        _ALLOWED_CONTROLLED_ENV_KEYS
        | _CREDENTIAL_CHAIN_TOKEN_KEYS
    ):
        raise LiveExecutorError("controlled invocation environment is outside the allowlist")
    # Re-check every env value for secret-shaped / control material so the
    # transport's re-validation is self-contained (not trusting upstream alone).
    for key, value in invocation.env.items():
        if not isinstance(value, str):
            raise LiveExecutorError("controlled invocation environment value is not a string")
        if key in _CREDENTIAL_CHAIN_TOKEN_KEYS:
            # Account tokens are admitted only in exact github_pat_ shape; never
            # echoed (argv/stderr/stdout redaction already covers token-shaped text).
            if not _TOKEN_VALUE.fullmatch(value):
                raise LiveExecutorError("credential token value is not token-shaped")
            continue
        if _SECRET_SHAPED.search(value) or "\x00" in value or "\n" in value or "\r" in value:
            raise LiveExecutorError("controlled invocation environment contains secret-shaped material")
    if invocation.operation in (
        LiveOperation.GIT_REMOTE_PREFLIGHT,
        LiveOperation.GIT_ORIGIN_ANONYMOUS_LS_REMOTE,
    ):
        # Root terminates repository/config discovery.  The exact fixed env is
        # built from an allowlist (therefore no ambient GIT_DIR/GIT_WORK_TREE)
        # and disables both system and global Git config. The anonymous
        # visibility probe shares this credential-detached regime (SC-014): a
        # forged invocation must not run it with ambient credentials.
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
    elif invocation.operation in _CREDENTIAL_CHAIN_OPERATIONS:
        # The credential-chain regime is held to a symmetric, closed standard:
        # its exact key set admits no ambient override of config/discovery/
        # askpass (GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM, GIT_ASKPASS,
        # XDG_CONFIG_HOME), and no GIT_DIR/GIT_WORK_TREE may redirect discovery.
        # A forged invocation must not smuggle a credential.helper injection
        # channel into the regime that is supposed to resolve from real HOME
        # discovery only.
        admitted_keys = _CREDENTIAL_CHAIN_ENV_KEYS | _CREDENTIAL_CHAIN_TOKEN_KEYS
        if set(invocation.env) - admitted_keys:
            raise LiveExecutorError("credential-chain environment is not the closed key set")
        # The key set is closed, but the VALUES of PATH and HOME are also
        # caller-falsifiable on a forged invocation: PATH must remain the exact
        # pinned path (a shadowed ``git`` resolves a malicious binary), and HOME
        # must remain the authoritative passwd home (a substituted HOME re-opens
        # the credential.helper injection channel). Pin both exactly.
        if invocation.env.get("PATH") != _CREDENTIAL_CHAIN_PATH:
            raise LiveExecutorError("credential-chain PATH is not the pinned value")
        if invocation.env.get("HOME") != _credential_chain_home():
            raise LiveExecutorError("credential-chain HOME is not the authoritative account home")
        if "GIT_DIR" in invocation.env or "GIT_WORK_TREE" in invocation.env:
            raise LiveExecutorError("credential-chain environment must not redirect discovery")
        if "_CREDENTIAL_CHAIN_DISALLOWED" in invocation.env:  # pragma: no cover - defensive
            raise LiveExecutorError("credential-chain environment carries a disallowed key")
        # Pin each credential-chain operation's exact argv, re-validating the
        # dynamic slots (origin URL, destination) at the validator boundary so a
        # forged invocation labeled GIT_CLONE/GIT_PUSH/authenticated-probe cannot
        # smuggle an attacker origin or checkout path past a shape-only check.
        if invocation.operation is LiveOperation.GIT_ORIGIN_AUTHENTICATED_LS_REMOTE:
            argv = invocation.argv
            if (
                len(argv) != 11
                or argv[0] != "git"
                or argv[1:7]
                != (
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "protocol.allow=never",
                    "-c",
                    "protocol.https.allow=always",
                )
                or argv[7:9] != ("ls-remote", "--symref")
                or argv[10] != "HEAD"
            ):
                raise LiveExecutorError(
                    "authenticated origin-visibility argv does not match the exact constructed shape"
                )
            # argv[9] is the origin URL; re-reject secret-shaped/userinfo-bearing
            # material and re-confirm the approved HTTPS owner/repository.
            _validate_origin_url_argument(argv[9])
        elif invocation.operation is LiveOperation.GIT_CLONE:
            argv = invocation.argv
            if (
                len(argv) != 7
                or argv[0:5] != ("git", "clone", "--origin", "origin", "--no-tags")
            ):
                raise LiveExecutorError("git clone argv does not match the exact constructed shape")
            # Clone runs from the neutral filesystem root (parent==self), so no
            # ancestor repository config can be discovered. A forged cwd would
            # let git resolve a repo-level config under the attacker's control.
            if invocation.cwd != NEUTRAL_GIT_CWD:
                raise LiveExecutorError("git clone must run from the neutral root cwd")
            _validate_origin_url_argument(argv[5])
            _validate_checkout_path_argument(argv[6])
        elif invocation.operation is LiveOperation.GIT_PUSH:
            # _assert_exact_push_shape already pinned len==8 plus argv[0:3] and
            # argv[4:]; re-validate the dynamic `-C <destination>` slot and its
            # agreement with the working directory, so a forged push cannot run
            # inside an attacker-controlled repository whose `origin` remote
            # points at an attacker URL (credential exfiltration).
            if invocation.cwd is None:
                raise LiveExecutorError("git push requires a checkout cwd")
            if invocation.argv[3] != str(invocation.cwd):
                raise LiveExecutorError("git push -C destination does not match the invocation cwd")
            _validate_checkout_path_argument(invocation.argv[3])
    if invocation.argv[0] == "bd" and set(invocation.env) & _BEADS_ENV_KEYS:
        raise LiveExecutorError("Beads Dolt overrides must be absent from bd operations")


class ControlledLiveExecutor:
    """Map closed operations to hard-coded argv for the test transport.

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
        parameters: GitRemotePreflightRequest | LocalGitReadbackRequest | CentralDoltProbeRequest | GitCloneRequest,
    ) -> RawResult:
        """Exercise an admitted operation through the test-only seam.

        Local Git readback and clone deliberately stop after validating and
        building their fixed request.  Lexical/resolved-path checks cannot
        prevent symlink replacement between validation and process startup.
        Transport remains unavailable until a separately reviewed production
        transport provides an inode-bound, no-follow working-directory
        capability.
        """
        if operation in (
            LiveOperation.LOCAL_GIT_READBACK,
            LiveOperation.GIT_CLONE,
            LiveOperation.GIT_REMOTE_READBACK,
            LiveOperation.GIT_TEMPLATE_REVISION,
            LiveOperation.COPIER_RENDER,
            LiveOperation.BEADS_INIT,
            LiveOperation.BEADS_PREFIX_READ,
            LiveOperation.DOLT_REMOTE_LIST,
            LiveOperation.DOLT_REMOTE_ADD,
            LiveOperation.DOLT_COMMIT,
            LiveOperation.BEADS_SETUP,
            LiveOperation.BEADS_SETUP_CHECK,
            LiveOperation.BEADS_HOOKS_INSTALL,
            LiveOperation.BEADS_HOOKS_LIST,
            LiveOperation.BEADS_BACKUP_INIT,
            LiveOperation.BEADS_BACKUP_SYNC,
            LiveOperation.BEADS_BACKUP_STATUS,
            LiveOperation.COVERAGE_AUDIT,
            LiveOperation.SPECKIT_INIT,
            LiveOperation.SPECKIT_EXTENSION_ADD,
            LiveOperation.SPECKIT_INTEGRATION_READ,
            LiveOperation.BD_SEARCH_ISSUES,
            LiveOperation.BD_CREATE_ISSUE,
            LiveOperation.BD_SHOW_ISSUE,
            LiveOperation.GIT_STATUS_ALL,
            LiveOperation.GIT_ADD_ALL,
            LiveOperation.GIT_DIFF_CACHED_NAMES,
            LiveOperation.GIT_DIFF_CACHED_TEXT,
            LiveOperation.GIT_COMMIT,
            LiveOperation.GIT_REV_PARSE_HEAD,
            LiveOperation.GIT_STATUS_BRANCH,
            LiveOperation.GIT_PUSH,
            LiveOperation.GIT_LS_REMOTE_MAIN,
            LiveOperation.BD_DOLT_PUSH,
        ):
            # Build and validate the exact argv, but do not hand it to the test
            # transport: an in-memory transport cannot perform a real clone/render
            # or a safe local readback, and a lexical path cannot close the TOCTOU.
            _build_invocation(operation, parameters, self._approved_home)
            raise LiveExecutorError(
                f"{operation.value} requires the production transport and is intentionally unavailable"
            )
        invocation = _build_invocation(operation, parameters, self._approved_home)
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


class _ProductionTransport(Protocol):
    """The production transport seam: a bounded, re-validating subprocess runner."""

    def invoke(self, request: _TransportInvocation) -> RawResult: ...


class ProductionLiveExecutor:
    """Map closed operations to argv and run them through the production transport.

    Construction is capability-gated: only the internal factory in
    ``production_transport.py`` holds the transport token, and this executor
    admits only the exact production transport type. Every invocation is
    re-validated by the transport before spawn.
    """

    def __init__(self, *, transport: _ProductionTransport, approved_home: Path) -> None:
        if not isinstance(approved_home, Path) or not approved_home.is_absolute():
            raise LiveExecutorError("approved home must be an absolute path")
        if ".." in approved_home.parts:
            raise LiveExecutorError("approved home path traversal is forbidden")
        # Admit only the exact production transport. The `_is_production_transport`
        # class marker is forgeable and therefore defense-in-depth only (it avoids
        # a circular import, not a hostile caller); the real admission control is
        # the closure-held capability token held solely by the reviewed entry-point
        # factory in production_transport.py, which this executor reaches only via
        # `_production_executor`.
        if getattr(transport, "_is_production_transport", False) is not True:
            raise LiveExecutorError("production executor requires the production transport")
        self._transport = transport
        self._approved_home = approved_home

    def execute(
        self,
        operation: LiveOperation,
        parameters: GitRemotePreflightRequest | LocalGitReadbackRequest | CentralDoltProbeRequest | GitCloneRequest,
    ) -> RawResult:
        invocation = _build_invocation(operation, parameters, self._approved_home)
        result = self._transport.invoke(invocation)
        if type(result) is not RawResult:
            raise LiveExecutorError("production transport must return the exact raw result type")
        if (
            isinstance(result.returncode, bool)
            or not isinstance(result.returncode, int)
            or not isinstance(result.stdout, str)
            or not isinstance(result.stderr, str)
        ):
            raise LiveExecutorError("production transport returned invalid raw result fields")
        return RawResult(
            returncode=result.returncode,
            stdout=_redact_and_bound(result.stdout),
            stderr=_redact_and_bound(result.stderr),
        )


def _build_invocation(
    operation: LiveOperation,
    parameters: GitRemotePreflightRequest | LocalGitReadbackRequest | CentralDoltProbeRequest | GitCloneRequest,
    approved_home: Path,
) -> _TransportInvocation:
    """Build and validate the exact argv for an admitted operation."""
    if type(operation) is not LiveOperation:
        raise LiveExecutorError("unknown live operation")

    if operation is LiveOperation.GIT_REMOTE_PREFLIGHT:
        if type(parameters) is not GitRemotePreflightRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _remote_argv(parameters)
    elif operation is LiveOperation.GIT_ORIGIN_ANONYMOUS_LS_REMOTE:
        if type(parameters) is not GitOriginVisibilityRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _origin_visibility_argv(parameters)
    elif operation is LiveOperation.GIT_ORIGIN_AUTHENTICATED_LS_REMOTE:
        if type(parameters) is not GitOriginVisibilityRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _origin_visibility_argv(parameters, detached=False)
    elif operation is LiveOperation.LOCAL_GIT_READBACK:
        if type(parameters) is not LocalGitReadbackRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _local_git_argv(parameters, approved_home)
    elif operation is LiveOperation.CENTRAL_DOLT_PROBE:
        if type(parameters) is not CentralDoltProbeRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _dolt_argv(parameters)
    elif operation is LiveOperation.DOLT_DATABASE_READBACK:
        if type(parameters) is not DoltDatabaseReadbackRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _dolt_database_readback_argv(parameters)
    elif operation is LiveOperation.DOLT_COMMIT:
        if type(parameters) is not DoltCommitRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _dolt_commit_argv(parameters)
    elif operation is LiveOperation.GIT_CLONE:
        if type(parameters) is not GitCloneRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_clone_argv(parameters)
    elif operation is LiveOperation.GIT_REMOTE_READBACK:
        if type(parameters) is not GitRemoteReadbackRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_remote_readback_argv(parameters)
    elif operation is LiveOperation.GIT_TEMPLATE_REVISION:
        if type(parameters) is not GitTemplateRevisionRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_template_revision_argv(parameters)
    elif operation is LiveOperation.COPIER_RENDER:
        if type(parameters) is not CopierRenderRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _copier_render_argv(parameters)
    elif operation is LiveOperation.BEADS_INIT:
        if type(parameters) is not BeadsInitRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_init_argv(parameters)
    elif operation is LiveOperation.BEADS_PREFIX_READ:
        if type(parameters) is not BeadsPrefixReadRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_prefix_read_argv(parameters)
    elif operation is LiveOperation.DOLT_REMOTE_LIST:
        if type(parameters) is not DoltRemoteListRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _dolt_remote_list_argv(parameters)
    elif operation is LiveOperation.DOLT_REMOTE_ADD:
        if type(parameters) is not DoltRemoteAddRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _dolt_remote_add_argv(parameters)
    elif operation is LiveOperation.BEADS_SETUP:
        if type(parameters) is not BeadsSetupRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_setup_argv(parameters)
    elif operation is LiveOperation.BEADS_SETUP_CHECK:
        if type(parameters) is not BeadsSetupRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_setup_argv(parameters)
    elif operation is LiveOperation.BEADS_HOOKS_INSTALL:
        if type(parameters) is not BeadsHooksInstallRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_hooks_install_argv(parameters)
    elif operation is LiveOperation.BEADS_HOOKS_LIST:
        if type(parameters) is not BeadsHooksListRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_hooks_list_argv(parameters)
    elif operation is LiveOperation.BEADS_BACKUP_INIT:
        if type(parameters) is not BeadsBackupInitRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_backup_init_argv(parameters)
    elif operation is LiveOperation.BEADS_BACKUP_SYNC:
        if type(parameters) is not BeadsBackupSyncRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_backup_sync_argv(parameters)
    elif operation is LiveOperation.BEADS_BACKUP_STATUS:
        if type(parameters) is not BeadsBackupStatusRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _beads_backup_status_argv(parameters)
    elif operation is LiveOperation.COVERAGE_AUDIT:
        if type(parameters) is not CoverageAuditRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _coverage_audit_argv(parameters)
    elif operation is LiveOperation.SPECKIT_INIT:
        if type(parameters) is not SpeckitInitRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _speckit_init_argv(parameters)
    elif operation is LiveOperation.SPECKIT_EXTENSION_ADD:
        if type(parameters) is not SpeckitExtensionAddRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _speckit_extension_add_argv(parameters)
    elif operation is LiveOperation.SPECKIT_INTEGRATION_READ:
        if type(parameters) is not SpeckitIntegrationReadRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _speckit_integration_read_argv(parameters)
    elif operation is LiveOperation.BD_SEARCH_ISSUES:
        if type(parameters) is not BdSearchIssuesRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _bd_search_issues_argv(parameters)
    elif operation is LiveOperation.BD_CREATE_ISSUE:
        if type(parameters) is not BdCreateIssueRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _bd_create_issue_argv(parameters)
    elif operation is LiveOperation.BD_SHOW_ISSUE:
        if type(parameters) is not BdShowIssueRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _bd_show_issue_argv(parameters)
    elif operation is LiveOperation.GIT_STATUS_ALL:
        if type(parameters) is not GitStatusAllRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_status_all_argv(parameters)
    elif operation is LiveOperation.GIT_ADD_ALL:
        if type(parameters) is not GitAddAllRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_add_all_argv(parameters)
    elif operation is LiveOperation.GIT_DIFF_CACHED_NAMES:
        if type(parameters) is not GitDiffCachedNamesRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_diff_cached_names_argv(parameters)
    elif operation is LiveOperation.GIT_DIFF_CACHED_TEXT:
        if type(parameters) is not GitDiffCachedTextRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_diff_cached_text_argv(parameters)
    elif operation is LiveOperation.GIT_COMMIT:
        if type(parameters) is not GitCommitRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_commit_argv(parameters)
    elif operation is LiveOperation.GIT_REV_PARSE_HEAD:
        if type(parameters) is not GitRevParseHeadRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_rev_parse_head_argv(parameters)
    elif operation is LiveOperation.GIT_STATUS_BRANCH:
        if type(parameters) is not GitStatusBranchRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_status_branch_argv(parameters)
    elif operation is LiveOperation.GIT_PUSH:
        if type(parameters) is not GitPushRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_push_argv(parameters)
    elif operation is LiveOperation.GIT_LS_REMOTE_MAIN:
        if type(parameters) is not GitLsRemoteMainRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _git_ls_remote_main_argv(parameters)
    elif operation is LiveOperation.BD_DOLT_PUSH:
        if type(parameters) is not BdDoltPushRequest:
            raise LiveExecutorError("live operation received the wrong request type")
        argv, cwd = _bd_dolt_push_argv(parameters)
    else:  # pragma: no cover - guarded by exact enum admission above
        raise LiveExecutorError("unknown live operation")

    if operation is LiveOperation.COVERAGE_AUDIT:
        environment = dict(_FIXED_ENVIRONMENT)
        environment["HERMES_HOME"] = str(parameters.hermes_home)
        environment["XDG_STATE_HOME"] = str(parameters.state_home)
        # dolt needs a writable config root (`$DOLT_ROOT_PATH/.dolt`). Under the
        # detached fixed env (HOME=/var/empty) it otherwise fails
        # `mkdir /var/empty/.dolt: operation not permitted`, which breaks every
        # audit dolt query. Point it at the audit's own XDG state subdir
        # (`<state_home>/hermes`, already writable and used for STATE_FILE) so
        # dolt writes a fresh isolated config there — never /var/empty and never
        # the operator's real ~/.dolt. HOME stays /var/empty (credential-detached).
        environment["DOLT_ROOT_PATH"] = str(parameters.state_home / "hermes")
        for value in environment.values():
            if _SECRET_SHAPED.search(value) or "\x00" in value or "\n" in value or "\r" in value:
                raise LiveExecutorError("coverage audit environment contains invalid material")
        env = MappingProxyType(environment)
        timeout = 30
    elif operation in _CREDENTIAL_CHAIN_OPERATIONS:
        # The authenticated git operations (visibility probe, clone, push,
        # origin/main readback, Dolt push) resolve the operator's
        # credential.helper chain. Built exclusively from the credential-chain
        # key set plus the Phil-approved token passthrough; still re-checked by
        # the shared validator before spawn.
        env = _credential_chain_environment()
        # BD_DOLT_PUSH talks to the shared central Dolt server over the network
        # and is measurably slow (~12.5s even as a no-op, longer on first push),
        # so it gets the server-mutation budget rather than the short local cap.
        timeout = (
            SERVER_MUTATION_TIMEOUT_SECONDS
            if operation is LiveOperation.BD_DOLT_PUSH
            else TIMEOUT_SECONDS
        )
    elif operation in (
        LiveOperation.GIT_REMOTE_PREFLIGHT,
        LiveOperation.GIT_ORIGIN_ANONYMOUS_LS_REMOTE,
    ):
        # The two anonymous remote probes stay fully credential-detached on the
        # fixed environment (HOME=/var/empty, GIT_ASKPASS=/usr/bin/false): they
        # must never touch the operator's credential store or account HOME.
        env = _minimal_environment(_FIXED_ENVIRONMENT, program=argv[0])
        timeout = TIMEOUT_SECONDS
    else:
        env = _neutral_local_environment()
        if operation in _SERVER_MUTATION_OPERATIONS:
            timeout = SERVER_MUTATION_TIMEOUT_SECONDS
        else:
            timeout = TIMEOUT_SECONDS

    invocation = _TransportInvocation(
        operation=operation,
        argv=argv,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout,
        shell=False,
    )
    _validate_built_invocation(invocation)
    return invocation

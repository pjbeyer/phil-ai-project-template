"""Open-source publish-hygiene gate (FR-029 / SC-011).

A ``visibility: open-source`` record is admitted only after this gate passes
over the full *published surface*. It is a pure, deterministic, transport-free
static scan: it rejects absolute workstation paths, credentials and
secret-shaped material, private endpoints and internal hostname inventories,
and any private manifest/evidence content before a single byte can be pushed.

The scan runs on *text* extracted from the rendered working tree, the Copier
answer metadata (including description text), the provisioning-created Git
history (commit messages and authored file names), and the Git-backed Dolt
remote content (bootstrap issue bodies). It never opens a network socket and
never follows a symlink; it is safe to run on untrusted content.

This module is intentionally self-contained: it re-declares the canonical
secret/path detectors rather than importing the live-executor's transport
module, so it carries no subprocess or network authority (NFR-007).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Secret-shaped material: classic PATs, AWS access keys, PEM blocks, 1Password
# references, label-shaped tokens, and tokenized URLs with userinfo.
_SECRET = re.compile(
    r"(?:ghp_|github_pat_|AKIA[0-9A-Z]{8,}|-----BEGIN|op://|"
    r"(?:token|password|passwd|secret|api[_-]?key)\s*[=:]|"
    r"https?://[^/@\s]+@)",
    re.IGNORECASE,
)

# Absolute workstation/private paths that must never reach a public repo.
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

# Private endpoints and internal-hostname inventory. ``127.0.0.1``, ``localhost``,
# RFC1918 private ranges, link-local, and ``.internal``/``.local`` hostnames must
# never appear in published content (FR-029: "non-credential private endpoints
# and internal hostname inventories").
_PRIVATE_ENDPOINT = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"127\.0\.0\.1|localhost|::1|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}|"
    r"0\.0\.0\.0|"
    r"[a-z0-9.-]+\.(?:internal|local)\b"
    r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)


class PublishHygieneError(ValueError):
    """Raised when published-surface content carries a rejected hazard."""


@dataclass(frozen=True)
class PublishHygieneFinding:
    """One rejected hazard on the published surface."""

    category: str
    source: str
    detail: str


@dataclass
class PublishHygieneResult:
    """Accumulated rejection findings across the published surface."""

    findings: list[PublishHygieneFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.findings

    def add(self, category: str, source: str, detail: str) -> None:
        self.findings.append(PublishHygieneFinding(category, source, detail))


def _scan_text(result: PublishHygieneResult, text: str, source: str) -> None:
    """Scan one text block for every rejected hazard class."""
    if not text:
        return
    for match in _SECRET.finditer(text):
        result.add("secret", source, match.group(0))
    for match in _PRIVATE_ABSOLUTE_PATH.finditer(text):
        result.add("private-path", source, match.group(0))
    for match in _PRIVATE_ENDPOINT.finditer(text):
        result.add("private-endpoint", source, match.group(0))


def scan_published_surface(
    *,
    rendered_texts: Iterable[tuple[str, str]] = (),
    answer_metadata: Iterable[tuple[str, str]] = (),
    git_history: Iterable[tuple[str, str]] = (),
    remote_issue_bodies: Iterable[tuple[str, str]] = (),
) -> PublishHygieneResult:
    """Scan the full published surface and reject any FR-029 hazard.

    Every iterable is of ``(source_label, text)`` pairs. The caller extracts
    text from its own surfaces (rendered files, Copier answers, commit
    messages/file names, bootstrap issue bodies); this function only classifies
    content and holds no transport/socket authority.
    """
    result = PublishHygieneResult()
    for source, text in rendered_texts:
        _scan_text(result, text, f"rendered:{source}")
    for source, text in answer_metadata:
        _scan_text(result, text, f"answer:{source}")
    for source, text in git_history:
        _scan_text(result, text, f"history:{source}")
    for source, text in remote_issue_bodies:
        _scan_text(result, text, f"remote:{source}")
    return result


def require_publish_hygiene(result: PublishHygieneResult) -> None:
    """Fail closed: raise PublishHygieneError on any rejected hazard."""
    if not result.passed:
        details = "; ".join(
            f"{f.category}@{f.source}" for f in result.findings
        )
        raise PublishHygieneError(
            f"open-source publish-hygiene gate rejected the surface: {details}"
        )


# A non-open-source visibility must never publish to a public remote. The
# origin-visibility check itself (FR-007) requires an authenticated GitHub API
# query — a transport capability that must be reviewed before it is admitted
# behind the allowlist. This predicate encodes the fail-closed contract so a
# caller can stop the run before any push when the origin's publicness is
# unknown rather than assume private.
def non_open_source_requires_private(visibility: str) -> bool:
    """True when the request must prove the origin is private before push."""
    return visibility != "open-source"


def _self_test() -> int:
    clean = scan_published_surface(
        rendered_texts=[("README.md", "A public project with no secrets.")],
        answer_metadata=[("project_description", "A benign description")],
    )
    assert clean.passed

    dirty = scan_published_surface(
        rendered_texts=[("README.md", "token=ghp_1234567890abcdefghij")],
    )
    assert not dirty.passed
    assert dirty.findings[0].category == "secret"

    dirty = scan_published_surface(
        rendered_texts=[("README.md", "see /Users/alice/private for details")],
    )
    assert not dirty.passed
    assert dirty.findings[0].category == "private-path"

    dirty = scan_published_surface(
        rendered_texts=[("README.md", "connect to 10.1.2.3:3307")],
    )
    assert not dirty.passed
    assert dirty.findings[0].category == "private-endpoint"

    dirty = scan_published_surface(
        answer_metadata=[("project_description", "op://vault/dev-token")],
    )
    assert not dirty.passed
    assert dirty.findings[0].category == "secret"

    assert non_open_source_requires_private("personal-only") is True
    assert non_open_source_requires_private("work-internal") is True
    assert non_open_source_requires_private("open-source") is False

    try:
        require_publish_hygiene(dirty)
    except PublishHygieneError:
        pass
    else:
        raise AssertionError("require_publish_hygiene did not fail closed")

    require_publish_hygiene(clean)
    print("self-test ok")
    return 0


if __name__ == "__main__":
    import sys

    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit("library module")

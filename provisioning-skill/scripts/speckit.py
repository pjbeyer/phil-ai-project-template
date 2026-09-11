"""SpecKit command contract for the supervised live adapter.

Grounded against `specify` CLI 1.0.3 (2026-09-11).

FR-012 (corrected): the live-installable pack is narrowed to the verifiably
first-party extension only. `agent-context` is authored by spec-kit-core and
installs from the default catalog bundled with the CLI, so it is pinned by the
CLI release. Every other formerly-"compatible" extension and every preset is a
community/unvetted artifact (discovery-only catalog, third-party single-author
repo) and is DEFERRED to a future vet-and-pin task; ``COMPATIBLE_PRESETS`` is
therefore empty, and the deferred names are enumerated here so a live gate can
never reintroduce one without an explicit vet.

The CLI exposes no ``--json`` on ``extension list`` / ``preset list``; readback
must therefore use ``integration status --json`` plus the on-disk state files
(``.specify/integration.json`` and ``.specify/extensions.yml``), never a
simulated "components" summary.
"""
from __future__ import annotations

# Live-installable first-party pack (pinned by the bundled CLI release).
COMPATIBLE_EXTENSIONS: tuple[str, ...] = ("agent-context",)
COMPATIBLE_PRESETS: tuple[str, ...] = ()

# Deferred until independently vetted to immutable archive revisions (F-003).
DEFERRED_EXTENSIONS: tuple[str, ...] = (
    "verify-tasks",
    "spec-validate",
    "red-team",
    "cleanup",
    "reconcile",
    "checkpoint",
    "security-review",
)
DEFERRED_PRESETS: tuple[str, ...] = (
    "command-density",
    "explicit-task-dependencies",
    "security-governance",
)

# Incompatible/never-install components: `verify` and `review` manifests, Jira
# preset (Beads is canonical).
EXCLUDED: tuple[str, ...] = ("verify", "review", "jira")


def init_command() -> list[str]:
    return ["specify", "init", "--here", "--integration", "hermes", "--script", "sh", "--non-interactive"]
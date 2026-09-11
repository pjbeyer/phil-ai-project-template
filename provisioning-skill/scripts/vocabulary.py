"""Canonical manifest-vocabulary registry (FR-030).

The single source of truth enumerating the legal values for every manifest
field. The manifest itself, its generated schema, and every audit/consumer MUST
resolve legal values from here and never re-declare local string constants
(FR-030: "the single source of truth shared by the manifest itself, its
generated schema, and every audit/consumer that validates records").

Field axes are orthogonal (owner / project_kind / visibility / expected_sync /
remote_health / restore_tier / owning-job names): a new *value* under an
existing field keeps ``manifest.version`` unchanged; a new/renamed *field* is a
version bump completed by a one-time Phil-authorized migration — never by the
provisioner. This module declares values only; it performs no migration.
"""
from __future__ import annotations

# manifest ``owner`` (GitHub owner -> manifest owner mapping lives in manifest.py,
# whose routing contract converts ``flexapp``->``work`` and ``pjbeyer``->``personal``).
OWNER_VALUES = frozenset({"personal", "work"})

# project_kind (the "what it is" axis). coding-agent-plugin added per FR-002/T076:
# an ADD of an enum VALUE keeps manifest.version unchanged.
PROJECT_KIND_VALUES = frozenset(
    {"generic", "macos-cli", "homebrew-tap", "coding-agent-plugin"}
)

# visibility (the "publication posture" axis). Never inferred from owner (FR-029).
VISIBILITY_VALUES = frozenset({"personal-only", "work-internal", "open-source"})
# Most restrictive value; default whenever a request omits visibility (FR-002).
DEFAULT_VISIBILITY = "personal-only"

# expected_sync (the "how it syncs" axis). Includes the spec-named ``backup-only``
# alias of ``backup-only-no-dolt-remote`` (FR-013/§123 prose).
EXPECTED_SYNC_VALUES = frozenset(
    {
        "manual-dolt-remote",
        "backup-only",
        "backup-only-no-dolt-remote",
        "github-upstream-pull-and-manual-dolt-remote",
        "remote-plus-backup",
    }
)

# remote_health and restore_tier axes.
REMOTE_HEALTH_VALUES = frozenset({"required", "not-configured"})
RESTORE_TIER_VALUES = frozenset({"rotating", "canonical"})

# owning-job names. The live shared manifest validates against the four
# existing health/compliance/maintenance/integrity jobs; the spec registry also
# names "Hermes: Beads GitHub sync" (data-model.md §76) which the shared
# manifest does not yet require — noted as a spec-vs-manifest discrepancy, not
# silently added here.
OWNING_JOB_VALUES = frozenset(
    {
        "Hermes: Beads health review",
        "Hermes: compliance audit",
        "Hermes: Beads Dolt maintenance",
        "Hermes: Beads Dolt integrity review",
    }
)
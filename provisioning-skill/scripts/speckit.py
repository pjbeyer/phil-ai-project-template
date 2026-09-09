"""SpecKit command contract for the supervised live adapter."""
from __future__ import annotations

COMPATIBLE_EXTENSIONS = (
    "verify-tasks", "spec-validate", "red-team", "cleanup", "reconcile", "checkpoint", "security-review",
)
COMPATIBLE_PRESETS = ("command-density", "explicit-task-dependencies", "security-governance")
EXCLUDED = ("verify", "review", "jira")


def init_command() -> list[str]:
    return ["specify", "init", "--here", "--integration", "hermes", "--script", "sh"]

"""Idempotent bootstrap issue identities for generated project trackers."""
from __future__ import annotations

from .adapters import ProvisioningAdapter
from .models import ProjectKind


def desired_issues(kind: ProjectKind) -> list[tuple[str, str]]:
    issues = [
        ("scope-readme", "Define initial project scope and README"),
        ("first-speckit-spec", "Create the first SpecKit feature specification"),
    ]
    if kind == "macos-cli":
        issues.append(("macos-cli-real-tests", "Add real CLI behavior tests before release"))
    if kind == "homebrew-tap":
        issues.extend([
            ("homebrew-first-package", "Add the first Formula or Cask"),
            ("homebrew-actions-secret", "Confirm Homebrew Actions secret out of band"),
            ("homebrew-lifecycle-tests", "Add real Homebrew package lifecycle verification"),
        ])
    return issues


def ensure_bootstrap_issues(adapter: ProvisioningAdapter, kind: ProjectKind) -> list[dict]:
    return [adapter.create_issue(marker, title) for marker, title in desired_issues(kind)]

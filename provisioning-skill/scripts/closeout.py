"""Pre-commit hygiene and commit-message validation helpers."""
from __future__ import annotations

import re

CONVENTIONAL = re.compile(r"^(feat|fix|docs|chore|refactor|style|test|ci|perf)(\([a-z0-9][a-z0-9-]*\))?: [a-z].*[^.]$")
SECRET = re.compile(r"(?:ghp_|github_pat_|AKIA|-----BEGIN|https://[^/@\s]+@)", re.I)


def validate_commit_message(message: str) -> None:
    if not CONVENTIONAL.fullmatch(message):
        raise ValueError("commit message must be conventional, imperative, and have no trailing period")


def scan_staged_content(content: str) -> None:
    if SECRET.search(content):
        raise ValueError("staged content includes a secret-shaped value or tokenized URL")

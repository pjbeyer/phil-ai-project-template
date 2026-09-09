"""Publish-hygiene gate: the skill source must be machine-independent and secret-free.

FR-027 / NFR-007: the published provisioning-skill source MUST contain no
absolute workstation path and no credential (value-shaped). This suite scans the
actual source tree and fails publication if either condition is violated.

The scan is value-sensitive, not literal-string-sensitive: the source legitimately
contains the *pattern* literals ``/Users/`` and ``token=`` inside the detector
regexes in ``scripts/models.py``. Those are the means of detection, not leaked
data, so they are excluded by matching on a value-shape (a concrete username or a
concrete assignment to a non-empty value), never on the bare token.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent

# Any absolute path under /Users/<name> where <name> is a plausible concrete
# workstation account (excludes the synthetic stand-ins the tests use, and
# excludes nothing else — a real account name is a real path and must fail).
_SYNTHETIC_ACCOUNTS = frozenset(
    {
        "synthetic-operator",
        "synthetic-tester",
        "synthetic-user",
        "synthetic-home",
        "synthetic-private",
        "synthetic-public",
        "synthetic-env-home",
        "unrelated-home",
        "alice",
        "tester",
    }
)

# Any absolute path under /Users/<name> where <name> is a concrete workstation
# account, EXCLUDING the synthetic stand-ins the tests self-declare. A real
# account name is a real path and must fail.
_SYNTHETIC_ALT = "|".join(re.escape(a) for a in sorted(_SYNTHETIC_ACCOUNTS))
_REAL_WORKSTATION_PATH = re.compile(
    rf"/Users/(?!(?:{_SYNTHETIC_ALT})(?:/|[\"'`\s;,)\]}}]))"
    rf"[A-Za-z][A-Za-z0-9._-]{{1,}}(?:/|[\"'`\s;,)\]}}])"
)

# Secret-shaped material that binds a concrete value, not a bare keyword.
_GITHUB_TOKEN_VALUE = re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")
_AWS_KEY_VALUE = re.compile(r"AKIA[0-9A-Z]{16}")
_PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
# Only flag a secret-shape KEY when it is bound to a quoted string value. A real
# credential in source is a string literal; bare identifiers on the RHS
# (``token: object``, ``token = getattr(...)``) and unquoted synthetic test
# canaries (``token=synthetic-marker``) are never credentials.
_SECRET_ASSIGNMENT_VALUE = re.compile(
    r"(?:token|password|passwd|secret|api[_-]?key)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    re.IGNORECASE,
)
# A 1Password pointer; exclude the synthetic vaults the tests self-declare so the
# gate does not flag its own fixtures.
_OP_POINTER = re.compile(r"op://(?!Synthetic)(?!synthetic)[A-Za-z0-9._/-]+")

_SYNTHETIC_ACCOUNTS = frozenset(
    {
        "synthetic-operator",
        "synthetic-tester",
        "synthetic-user",
        "synthetic-home",
        "synthetic-private",
        "unrelated-home",
        "alice",
        "tester",
    }
)

_TEXT_SUFFIXES = {".py", ".md", ".txt", ".yml", ".yaml", ".json", ".toml"}


def _scan_texts(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in _TEXT_SUFFIXES:
            continue
        if any(seg in {".git", "__pycache__", ".pytest_cache"} for seg in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, label in (
                (_REAL_WORKSTATION_PATH, "real workstation path"),
                (_GITHUB_TOKEN_VALUE, "GitHub token value"),
                (_AWS_KEY_VALUE, "AWS access key value"),
                (_PRIVATE_KEY_BLOCK, "private key block"),
                (_SECRET_ASSIGNMENT_VALUE, "secret-shaped assignment value"),
                (_OP_POINTER, "1Password pointer"),
            ):
                match = pattern.search(line)
                if match is not None:
                    findings.append(
                        f"{path.relative_to(root)}:{lineno}: {label}: {match.group(0)!r}"
                    )
    return findings


class PublishHygieneTests(unittest.TestCase):
    def test_source_contains_no_real_workstation_path(self) -> None:
        findings = [f for f in _scan_texts(_SKILL_ROOT) if "workstation path" in f]
        self.assertEqual(findings, [], "real workstation paths present:\n" + "\n".join(findings))

    def test_source_contains_no_secret_shaped_value(self) -> None:
        findings = [f for f in _scan_texts(_SKILL_ROOT) if "workstation path" not in f]
        self.assertEqual(findings, [], "secret-shaped values present:\n" + "\n".join(findings))

    def test_approved_home_is_environment_derived_not_hard_coded(self) -> None:
        models = (_SKILL_ROOT / "scripts" / "models.py").read_text(encoding="utf-8")
        self.assertIn("PROVISIONING_APPROVED_HOME", models)
        self.assertIn("os.environ", models)
        # The old hard-coded constant must be gone.
        self.assertNotIn('_APPROVED_PROJECT_HOME = Path("', models)


if __name__ == "__main__":
    unittest.main()

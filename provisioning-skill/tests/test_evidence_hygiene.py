"""Evidence/hygiene gate (T014 + T058): request/evidence output must be secret-free,
userinfo-free, private-path-free, and the skill must carry no subprocess
implementation or public live CLI selector.

Two halves:

1. Behavioral — request normalization and evidence persistence reject or
   sanitize secret-shaped values, URL userinfo, credential pointers, and
   absolute private paths before they reach any serialized or on-disk artifact.

2. Wiring — a deterministic source scan proves the skill ships no subprocess /
   socket / urllib / os.system transport and that the public CLI constructs only
   ``FakeAdapter`` (no live selector reachable).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.evidence import redact, request_fingerprint
from scripts.models import (
    ConfigurationError,
    ProvisioningEvidence,
    ProvisioningRequest,
)
from scripts.preflight import PreflightError, parse_origin

_SKILL_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _SKILL_ROOT / "scripts"
_CLI_MAIN = (_SCRIPTS_DIR / "provision_project.py").read_text(encoding="utf-8")

# Transport/code-exec primitives that must never appear in the shipped skill
# source. The adapters legitimately *document* the absence of these; matching is
# therefore done on the import/call surface, not prose.
#
# Slice A (pjb-m0ap.3.8) introduces exactly one permitted subprocess module:
# ``production_transport.py``. It is capability-gated, is the only module that
# may import ``subprocess``, and is never reachable from the public CLI. Every
# other script must remain transport-free.
_FORBIDDEN_IMPORTS = (
    "import subprocess",
    "from subprocess",
    "import socket",
    "from socket",
    "import urllib.request",
    "from urllib.request",
    "import urllib",
    "import os.system",
    "import runpy",
    "import ctypes",
    "import importlib",
)

# The single permitted subprocess host (Slice A). subprocess imports elsewhere
# remain forbidden.
_SUBPROCESS_ALLOWED_MODULE = "production_transport.py"


def _source_texts() -> list[Path]:
    suffixes = {".py"}
    found: list[Path] = []
    for path in sorted(_SCRIPTS_DIR.rglob("*")):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        if "__pycache__" in path.parts:
            continue
        found.append(path)
    return found


class EvidenceHygieneTests(unittest.TestCase):
    # -- Behavioral: request normalization rejects unsafe inputs -----------

    def test_request_normalization_rejects_userinfo_and_secret_shaped_origin(self) -> None:
        for origin in (
            "https://token@github.com/pjbeyer/demo.git",
            "https://ghp_abc123@github.com/pjbeyer/demo.git",
            "https://user:pass@github.com/pjbeyer/demo.git",
        ):
            with self.subTest(origin=origin), self.assertRaises(PreflightError):
                parse_origin(origin)

    def test_request_normalization_rejects_private_absolute_path_confirmation(self) -> None:
        # A private absolute path can never equal the canonical owner-routed
        # destination, so request_fingerprint must reject it (the mismatch check
        # is itself the private-path guard).
        request = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git", "demo", "generic", "",
            destination_confirmation="/Users/synthetic-private/project",
        )
        with self.assertRaises(ConfigurationError):
            request_fingerprint(request, Path("/example/Projects/pjbeyer/demo"))

    def test_request_fingerprint_never_admits_secret_material(self) -> None:
        # A secret-shaped description must be rejected rather than hashed into a
        # fingerprint someone could later treat as durable authority.
        request = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git", "demo", "generic",
            "token=synthetic-sensitive-value",
        )
        with self.assertRaises(ConfigurationError):
            request_fingerprint(request, Path("/example/Projects/pjbeyer/demo"))

    # -- Behavioral: evidence output never leaks secret material ----------

    def test_evidence_persist_rejects_secret_shaped_detail(self) -> None:
        # The durable evidence-output boundary is persist(): it REJECTS
        # secret-shaped material (fail-closed) rather than silently rewriting
        # to an ambiguous "[REDACTED]" token — mirroring live_evidence_to_json
        # and RenderProvenance.__post_init__. (T046 SHOULD-FIX regression.)
        from scripts.evidence import persist
        from scripts.models import Gate, GateResult

        evidence = ProvisioningEvidence(
            run_id="a" * 32,
            request_fingerprint="b" * 64,
            destination="[REDACTED]",
            repository_identity="pjbeyer/demo",
            state="partial",
            gates=[GateResult(Gate.RENDER, "failed", "token=synthetic-sensitive-value")],
            simulation=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigurationError):
                persist(evidence, Path(tmp))

    def test_persist_rejects_secret_shaped_value(self) -> None:
        from scripts.evidence import persist
        from scripts.models import Gate, GateResult

        evidence = ProvisioningEvidence(
            run_id="c" * 32,
            request_fingerprint="d" * 64,
            destination="[REDACTED]",
            repository_identity="pjbeyer/demo",
            state="partial",
            gates=[GateResult(Gate.RENDER, "failed", "op://synthetic/canary-item")],
            simulation=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigurationError):
                persist(evidence, Path(tmp))

    def test_redact_catches_userinfo_pointer_and_secret_shapes(self) -> None:
        for unsafe in (
            "token=synthetic-sensitive-value",
            "op://synthetic/canary-item",
            "https://user:pass@github.com/x",
            "/Users/synthetic-private/project",
        ):
            with self.subTest(unsafe=unsafe):
                self.assertNotEqual(redact(unsafe), unsafe)

    # -- Wiring: no subprocess / no public live CLI selector --------------

    def test_no_forbidden_transport_imports_in_shipped_scripts(self) -> None:
        findings: list[str] = []
        for path in _source_texts():
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                for forbidden in _FORBIDDEN_IMPORTS:
                    if forbidden in line:
                        # subprocess is permitted only in the single gated
                        # production-transport module (Slice A).
                        if forbidden.startswith(("import subprocess", "from subprocess")) and path.name == _SUBPROCESS_ALLOWED_MODULE:
                            continue
                        findings.append(f"{path.name}:{lineno}: {forbidden}")
        self.assertEqual(
            findings, [], "forbidden transport/code-exec imports present:\n" + "\n".join(findings)
        )

    def test_public_cli_constructs_only_fake_adapter(self) -> None:
        # The public CLI (main) must construct exactly FakeAdapter — never a
        # LiveAdapter or any live-capable selector.
        self.assertIn("FakeAdapter()", _CLI_MAIN)
        self.assertNotIn("LiveAdapter(", _CLI_MAIN)
        # No argument to main() can select a live adapter.
        self.assertNotIn("--adapter", _CLI_MAIN)
        self.assertNotIn("--live", _CLI_MAIN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
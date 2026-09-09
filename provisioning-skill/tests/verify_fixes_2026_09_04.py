#!/usr/bin/env python3
"""One-shot verification of pjb-9rdk and pjb-9p78 remediations (run, don't import)."""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

failures = []

# pjb-9rdk: CLI output is machine-readable JSON and contains the evidence note.
proc = subprocess.run(
    [sys.executable, "-m", "scripts.provision_project",
     "--origin-url", "https://github.com/example/demo.git",
     "--beads-prefix", "demo", "--project-kind", "generic"],
    capture_output=True, text=True, timeout=120, cwd=str(HERE),
)
payload = json.loads(proc.stdout)
if payload.get("evidence_note") != (
    "simulation evidence is intentionally not persisted; this run wrote no on-disk ledger"
):
    failures.append("9rdk: evidence_note missing or wrong: %r" % payload.get("evidence_note"))
if proc.returncode != 2:
    failures.append("9rdk: exit code %d != 2" % proc.returncode)
print("9rdk: note=%r exit=%d" % (payload.get("evidence_note"), proc.returncode))

# pjb-9p78: private-path regex redacts POSIX roots but not benign text.
from scripts.models import _PRIVATE_ABSOLUTE_PATH as P  # noqa: E402

cases = {
    "/home/alice/secret.txt": True,
    "/root/.ssh/id_ed25519": True,
    "/etc/passwd copy": True,
    "/Users/synthetic-user/file": True,
    "/var/log/system.log": True,
    "https://example.com/home/page": False,
    "go home/now": False,
    "the /etcetera problem": False,
}
bad = [k for k, want in cases.items() if bool(P.search(k)) != want]
if bad:
    failures.append("9p78: regex mismatches: %s" % bad)
print("9p78: %d/%d cases correct" % (len(cases) - len(bad), len(cases)))

if failures:
    print("FAILURES:")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("ALL VERIFICATIONS PASS")

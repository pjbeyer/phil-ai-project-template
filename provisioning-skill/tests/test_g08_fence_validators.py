"""Deterministic negative tests: the controlled G09/G10 predecessor validators
must reject forged evidence that flips the live-G08 (SPECKIT) fence to "passed".

This closes the review gap (Concern J): a forged predecessor that claims live G08
passed must be rejected by the structural status-sequence check, not merely by
the controllers never producing it.
"""

from __future__ import annotations

import unittest

from scripts._controlled_g09 import _validate_g09_evidence
from scripts._controlled_g10 import _validate_g10_evidence
from scripts.models import Gate, GateResult, ProvisioningEvidence

G06 = "G06:controlled-manifest-append"
G07_INIT = "G07:controlled-backup-init"
G07_SYNC = "G07:controlled-backup-sync"
G09_ATTEMPT = "G09:controlled-bootstrap"
G10_ATTEMPT = "G10:controlled-commit"
AUTHORITY = ("/tmp/controlled-fixture/repository", "demo", "demo_database")


def g09_gates(flip_speckit: bool = False) -> list[GateResult]:
    speckit = "passed" if flip_speckit else "skipped"
    return [
        GateResult(Gate.MANIFEST, "passed", "g06"),
        GateResult(Gate.BACKUP, "passed", "g07"),
        GateResult(Gate.SPECKIT, speckit, "g08"),
        GateResult(Gate.BOOTSTRAP, "passed", "g09"),
    ]


def g10_gates(flip_speckit: bool = False) -> list[GateResult]:
    speckit = "passed" if flip_speckit else "skipped"
    return [
        GateResult(Gate.MANIFEST, "passed", "g06"),
        GateResult(Gate.BACKUP, "passed", "g07"),
        GateResult(Gate.SPECKIT, speckit, "g08"),
        GateResult(Gate.BOOTSTRAP, "passed", "g09"),
        GateResult(Gate.COMMIT, "passed", "g10"),
    ]


def g09_evidence(flip_speckit: bool = False) -> ProvisioningEvidence:
    attempts = [G06, G07_INIT, G07_SYNC, G09_ATTEMPT]
    return ProvisioningEvidence(
        run_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        request_fingerprint="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        destination="[REDACTED]",
        repository_identity="controlled-fixture/g09",
        state="partial",
        failed_gate=None,
        gates=g09_gates(flip_speckit),
        mutation_attempts=attempts,
        mutations_completed=attempts,
        actual_database="demo_database",
        simulation=True,
    )


def g10_evidence(flip_speckit: bool = False) -> ProvisioningEvidence:
    attempts = [G06, G07_INIT, G07_SYNC, G09_ATTEMPT, G10_ATTEMPT]
    return ProvisioningEvidence(
        run_id="cccccccccccccccccccccccccccccccc",
        request_fingerprint="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        destination="[REDACTED]",
        repository_identity="controlled-fixture/g10",
        state="partial",
        failed_gate=None,
        gates=g10_gates(flip_speckit),
        mutation_attempts=attempts,
        mutations_completed=attempts,
        actual_database="demo_database",
        simulation=True,
    )


class ValidatorAcceptsWellFormedEvidence(unittest.TestCase):
    def test_g09_validator_accepts_well_formed(self) -> None:
        self.assertIsNotNone(_validate_g09_evidence(g09_evidence(), AUTHORITY))

    def test_g10_validator_accepts_well_formed(self) -> None:
        self.assertIsNotNone(_validate_g10_evidence(g10_evidence(), AUTHORITY))


class ForgedSpeckitPassedIsRejected(unittest.TestCase):
    def test_g09_validator_rejects_speckit_passed(self) -> None:
        with self.assertRaises(Exception):
            _validate_g09_evidence(g09_evidence(flip_speckit=True), AUTHORITY)

    def test_g10_validator_rejects_speckit_passed(self) -> None:
        with self.assertRaises(Exception):
            _validate_g10_evidence(g10_evidence(flip_speckit=True), AUTHORITY)


if __name__ == "__main__":
    unittest.main()
"""Sequence-guard regressions for the live gate dispatch (pjb-m0ap.3.6).

Asserts the .3.6 ordering criterion in isolation: a gate is reachable only after
every predecessor gate has completed its readback. Tests construct a bare
``LiveAdapter`` (no runner/config, no quarantine flag involved) and exercise the
pure ``_assert_gate_reachable`` seam directly, so the order guarantee is proven
without invoking Git, Copier, Dolt, Beads, a service, a credential, a network
origin, or a subprocess.
"""

from __future__ import annotations

import unittest

from scripts.adapters import AdapterError, LiveAdapter
from scripts.models import Gate


class GateOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = LiveAdapter()

    def test_first_gate_is_reachable_with_no_predecessors(self) -> None:
        # G01 has no predecessors; it must be reachable from the empty set.
        self.adapter._assert_gate_reachable(Gate.PREFLIGHT)

    def test_each_gate_can_complete_in_sequence(self) -> None:
        gate = Gate.PREFLIGHT
        self.adapter._completed_gates.add(gate)
        for successor in Gate:
            if successor is Gate.PREFLIGHT:
                continue
            # Complete the predecessor immediately before reaching the successor.
            self.adapter._assert_gate_reachable(successor)
            self.adapter._completed_gates.add(successor)

    def test_out_of_order_gate_is_rejected(self) -> None:
        # G02 without G01 must be rejected.
        with self.assertRaisesRegex(AdapterError, "unreachable before G01"):
            self.adapter._assert_gate_reachable(Gate.CLONE)

    def test_skipping_a_middle_gate_blocks_later_gates(self) -> None:
        # G01 and G02 done, but G03 skipped: G04 must still be unreachable.
        self.adapter._completed_gates.add(Gate.PREFLIGHT)
        self.adapter._completed_gates.add(Gate.CLONE)
        with self.assertRaisesRegex(AdapterError, "unreachable before G03"):
            self.adapter._assert_gate_reachable(Gate.BEADS)

    def test_final_gate_requires_every_predecessor(self) -> None:
        # G11 requires G01..G10 all present.
        for gate in Gate:
            if gate is not Gate.PUSH:
                self.adapter._completed_gates.add(gate)
        self.adapter._assert_gate_reachable(Gate.PUSH)

    def test_completed_set_only_adds_after_success(self) -> None:
        # A reached gate is not marked complete until its readback asserts; the
        # guard itself never mutates the completed set.
        before = set(self.adapter._completed_gates)
        self.adapter._assert_gate_reachable(Gate.PREFLIGHT)
        self.assertEqual(self.adapter._completed_gates, before)


if __name__ == "__main__":
    unittest.main()

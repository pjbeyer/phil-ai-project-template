"""State-machine failure, simulation, and bootstrap idempotency tests."""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scripts.adapters import AdapterError, FakeAdapter, LiveAdapter
from scripts.evidence import request_fingerprint
from scripts.models import Gate, ProvisioningRequest
from scripts.preflight import normalize_request
from scripts.provision_project import POST_PREFLIGHT, Provisioner, main


class StateMachineTests(unittest.TestCase):
    def test_unprepared_live_adapter_fails_closed_without_runner(self) -> None:
        """The legacy quarantine runner seam is gone; the adapter no longer takes `runner=`.

        An unprepared adapter (no config) fails closed with a controlled
        AdapterError on `prepare`/`_context`, and never mutates its own state.
        The production path is `_production_executor()`; there is no injected
        command runner.
        """
        adapter = LiveAdapter()
        self.assertIsNone(adapter.config)
        initial_state = {
            "request": adapter.request,
            "origin": adapter.origin,
            "destination": adapter.destination,
            "fingerprint": adapter.fingerprint,
            "_prepared": adapter._prepared,
            "_metadata": adapter._metadata,
            "_evidence": dict(adapter._evidence),
            "_issues": {key: dict(value) for key, value in adapter._issues.items()},
            "_git_head": adapter._git_head,
        }
        request = ProvisioningRequest(
            "https://github.com/pjbeyer/live-boundary-test.git", "livebound", "generic",
            live_authorization="pjbeyer/live-boundary-test:not-a-real-fingerprint",
        )
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            origin, destination = normalize_request(request, home)
            fingerprint = request_fingerprint(request, destination)
            with self.assertRaisesRegex(AdapterError, "exact immutable configuration type"):
                adapter.prepare(request, origin, destination, fingerprint)
        final_state = {
            "request": adapter.request,
            "origin": adapter.origin,
            "destination": adapter.destination,
            "fingerprint": adapter.fingerprint,
            "_prepared": adapter._prepared,
            "_metadata": adapter._metadata,
            "_evidence": dict(adapter._evidence),
            "_issues": {key: dict(value) for key, value in adapter._issues.items()},
            "_git_head": adapter._git_head,
        }
        self.assertEqual(final_state, initial_state)

    def setUp(self) -> None:
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.request = ProvisioningRequest(
            "https://github.com/pjbeyer/provisioning-test.git", "pvtest", "generic"
        )

    def test_fake_run_is_explicit_simulation_not_production_success(self) -> None:
        adapter = FakeAdapter()
        result = Provisioner(adapter, Path(self.root.name)).run(
            self.request, home=Path(self.root.name)
        )
        self.assertEqual(result.state, "simulation-passed")
        self.assertEqual(result.git_sync, "simulated")
        self.assertEqual(result.dolt_sync, "simulated")
        self.assertEqual(
            [call for call in adapter.calls if call.startswith("G")],
            [str(Gate.PREFLIGHT), *map(str, POST_PREFLIGHT)],
        )
        self.assertTrue(result.simulation)
        self.assertEqual(result.mutations_completed, [])
        statuses = {str(gate.gate): gate.status for gate in result.gates}
        self.assertEqual(statuses[str(Gate.PREFLIGHT)], "simulated")
        self.assertIn("no live probe or mutation was performed", result.gates[0].detail)
        self.assertEqual(
            [statuses[str(gate)] for gate in POST_PREFLIGHT],
            ["simulated"] * len(POST_PREFLIGHT),
        )
        self.assertIn("not a provisioned repository", result.next_action)

    def test_fake_adapter_cannot_disable_simulation_mode(self) -> None:
        with self.assertRaises(TypeError):
            FakeAdapter(is_simulation=False)
        adapter = FakeAdapter()
        with self.assertRaises(AttributeError):
            adapter.is_simulation = False
        result = Provisioner(adapter, Path(self.root.name)).run(self.request, home=Path(self.root.name))
        self.assertEqual(result.state, "simulation-passed")
        self.assertTrue(result.simulation)
        self.assertEqual(result.mutations_completed, [])

    def test_adapter_hybrids_cannot_claim_live_success(self) -> None:
        class FakeLiveHybrid(FakeAdapter, LiveAdapter):
            pass

        result = Provisioner(FakeLiveHybrid(), Path(self.root.name)).run(
            self.request, home=Path(self.root.name), existing=True
        )
        self.assertEqual(result.state, "blocked-preflight")
        self.assertFalse(result.simulation)
        self.assertEqual(result.mutations_completed, [])
        self.assertIn("unrecognized adapter", result.gates[0].detail)

    def test_fake_adapter_subclass_or_class_patch_cannot_claim_live_success(self) -> None:
        class MisrepresentedFake(FakeAdapter):
            is_simulation = False

        for adapter in (MisrepresentedFake(existing_valid=True),):
            result = Provisioner(adapter, Path(self.root.name)).run(
                self.request, home=Path(self.root.name), existing=True
            )
            self.assertEqual(result.state, "blocked-preflight")
            self.assertFalse(result.simulation)
            self.assertEqual(result.mutations_completed, [])
            self.assertIn("unrecognized adapter", result.gates[0].detail)

        original = FakeAdapter.is_simulation
        try:
            FakeAdapter.is_simulation = False
            result = Provisioner(FakeAdapter(), Path(self.root.name)).run(
                self.request, home=Path(self.root.name)
            )
            self.assertEqual(result.state, "simulation-passed")
            self.assertTrue(result.simulation)
            self.assertEqual(result.mutations_completed, [])
        finally:
            FakeAdapter.is_simulation = original

    def test_cli_simulation_is_machine_readable_and_nonzero(self) -> None:
        # Use the same canonical spelling returned by preflight so the absolute
        # destination confirmation remains an exact lexical match.
        destination = Path(self.root.name).resolve() / "cli-simulation"
        stdout = StringIO()
        argv = [
            "--origin-url", "https://github.com/example/cli-simulation.git",
            "--beads-prefix", "clisim",
            "--project-kind", "generic",
            "--destination-confirmation", str(destination),
        ]
        with patch("scripts.provision_project.required_tools_available", return_value=[]):
            with redirect_stdout(stdout):
                exit_code = main(argv)

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["state"], "simulation-passed")
        self.assertTrue(payload["simulation"])
        self.assertEqual(payload["mutations_completed"], [])
        self.assertEqual(payload["git_sync"], "simulated")
        self.assertEqual(payload["dolt_sync"], "simulated")
        self.assertEqual(payload["gates"][0]["status"], "simulated")
        self.assertIn("no live probe or mutation was performed", payload["gates"][0]["detail"])
        self.assertEqual(
            [gate["status"] for gate in payload["gates"][1:]],
            ["simulated"] * len(POST_PREFLIGHT),
        )
        self.assertTrue(
            all("no live mutation performed" in gate["detail"] for gate in payload["gates"][1:])
        )

    def test_existing_simulation_is_not_claimed_as_verified(self) -> None:
        adapter = FakeAdapter(existing_valid=True)
        result = Provisioner(adapter, Path(self.root.name)).run(
            self.request, home=Path(self.root.name), existing=True
        )
        self.assertEqual(result.state, "blocked-preflight")
        self.assertTrue(result.simulation)
        self.assertEqual(result.mutations_completed, [])
        self.assertEqual(adapter.calls, ["inspect-existing"])

    def test_each_post_preflight_failure_is_partial_without_replay(self) -> None:
        for failed_gate in POST_PREFLIGHT:
            with self.subTest(gate=failed_gate):
                adapter = FakeAdapter(failures={str(failed_gate)})
                result = Provisioner(adapter, Path(self.root.name)).run(
                    self.request, home=Path(self.root.name)
                )
                self.assertEqual(result.state, "partial")
                self.assertTrue(result.simulation)
                self.assertEqual(result.mutations_completed, [])
                self.assertEqual(result.failed_gate, str(failed_gate))
                self.assertEqual(result.resume_requirement, "phil-authorization-required")
                self.assertEqual(
                    [call for call in adapter.calls if call.startswith("G")],
                    [str(Gate.PREFLIGHT), *map(str, POST_PREFLIGHT[: POST_PREFLIGHT.index(failed_gate) + 1])],
                )
                completed_gates = POST_PREFLIGHT[: POST_PREFLIGHT.index(failed_gate)]
                completed_results = [
                    gate for gate in result.gates if gate.gate in completed_gates
                ]
                self.assertEqual(
                    [gate.status for gate in completed_results],
                    ["simulated"] * len(completed_gates),
                )
                self.assertEqual(result.gates[-1].status, "failed")

    def test_preflight_failure_has_no_post_preflight_calls(self) -> None:
        adapter = FakeAdapter(failures={str(Gate.PREFLIGHT)})
        result = Provisioner(adapter, Path(self.root.name)).run(
            self.request, home=Path(self.root.name)
        )
        self.assertEqual(result.state, "blocked-preflight")
        self.assertEqual(result.failed_gate, str(Gate.PREFLIGHT))
        self.assertEqual(adapter.calls, [str(Gate.PREFLIGHT)])

    def test_live_authorization_fails_closed_in_simulation(self) -> None:
        adapter = FakeAdapter()
        request = ProvisioningRequest(
            self.request.origin_url,
            self.request.beads_prefix,
            self.request.project_kind,
            live_authorization="https://github.com/pjbeyer/provisioning-test.git",
        )
        result = Provisioner(adapter, Path(self.root.name)).run(
            request, home=Path(self.root.name)
        )
        self.assertEqual(result.state, "blocked-preflight")
        self.assertTrue(result.simulation)
        self.assertIn("live adapter", result.gates[0].detail)
        self.assertEqual(adapter.calls, [])

    def test_homebrew_bootstrap_issue_set_is_idempotent(self) -> None:
        adapter = FakeAdapter()
        request = ProvisioningRequest(
            "https://github.com/pjbeyer/tap-test.git", "taptest", "homebrew-tap"
        )
        Provisioner(adapter, Path(self.root.name)).run(request, home=Path(self.root.name))
        self.assertEqual(len(adapter.issues), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)

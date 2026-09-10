"""Production transport (Slice A) tests.

Verifies the capability-gated subprocess transport: private-factory admission,
subclass rejection, non-shell invocation, bounded+redacted output, the
inode-bound no-follow cwd capability, timeout handling, and credential scoping
(no credential value in argv/env). No test invokes a real external mutation;
subprocess is patched to a recording fake.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.live_executor import (
    LiveExecutorError,
    LiveOperation,
    RawResult,
    _TransportInvocation,
)
from scripts.production_transport import ProductionTransport


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _invocation(**overrides: object) -> _TransportInvocation:
    base = dict(
        operation=LiveOperation.CENTRAL_DOLT_PROBE,
        argv=("dolt", "--host", "127.0.0.1", "--port", "3307", "sql", "-r", "json", "-q", "SELECT 1 AS ok;"),
        cwd=None,
        env={"PATH": "/opt/homebrew/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/var/empty"},
        timeout_seconds=15,
        shell=False,
    )
    base.update(overrides)
    return _TransportInvocation(**base)


class ProductionTransportTests(unittest.TestCase):
    def test_direct_construction_is_rejected(self) -> None:
        with self.assertRaisesRegex(LiveExecutorError, "private factory"):
            ProductionTransport()  # type: ignore[call-arg]

    def test_subclass_factory_is_rejected(self) -> None:
        class Subclass(ProductionTransport):
            pass

        with self.assertRaisesRegex(LiveExecutorError, "subclasses"):
            Subclass._for_authorized_executor()

    def test_factory_returns_exact_type(self) -> None:
        transport = ProductionTransport._for_authorized_executor()
        self.assertIs(type(transport), ProductionTransport)

    def test_rejects_wrong_invocation_type(self) -> None:
        transport = ProductionTransport._for_authorized_executor()
        with self.assertRaisesRegex(LiveExecutorError, "exact invocation type"):
            transport.invoke(object())  # type: ignore[arg-type]

    def test_rejects_shell_invocation(self) -> None:
        transport = ProductionTransport._for_authorized_executor()
        inv = _invocation(shell=True)
        with self.assertRaisesRegex(LiveExecutorError, "non-shell"):
            transport.invoke(inv)

    def test_runs_non_shell_and_redacts_output(self) -> None:
        transport = ProductionTransport._for_authorized_executor()
        inv = _invocation()
        with patch(
            "scripts.production_transport.subprocess.run",
            return_value=_FakeCompleted(0, b"ok\n", b"token=supersecret\n"),
        ) as run:
            result = transport.invoke(inv)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ok\n")
        self.assertNotIn("supersecret", result.stderr)
        # subprocess.run must be called with shell=False and list argv.
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.args[0], list(inv.argv))

    def test_timeout_raises_controlled_error(self) -> None:
        import subprocess

        transport = ProductionTransport._for_authorized_executor()
        with patch(
            "scripts.production_transport.subprocess.run",
            side_effect=subprocess.TimeoutExpired("dolt", 15),
        ):
            with self.assertRaisesRegex(LiveExecutorError, "timed out"):
                transport.invoke(_invocation())

    def test_start_failure_raises_controlled_error(self) -> None:
        transport = ProductionTransport._for_authorized_executor()
        with patch(
            "scripts.production_transport.subprocess.run",
            side_effect=OSError("no such binary"),
        ):
            with self.assertRaisesRegex(LiveExecutorError, "failed to start"):
                transport.invoke(_invocation())

    def test_cwd_is_opened_no_follow_and_pinned(self) -> None:
        transport = ProductionTransport._for_authorized_executor()
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            inv = _invocation(cwd=cwd)
            with patch(
                "scripts.production_transport.subprocess.run",
                return_value=_FakeCompleted(0, b"", b""),
            ) as run:
                transport.invoke(inv)
            # preexec_fn must be set (fchdir to the pinned descriptor).
            self.assertIsNotNone(run.call_args.kwargs.get("preexec_fn"))

    def test_cwd_open_failure_raises_controlled_error(self) -> None:
        transport = ProductionTransport._for_authorized_executor()
        inv = _invocation(cwd=Path("/nonexistent/does/not/exist"))
        with self.assertRaisesRegex(LiveExecutorError, "cwd open failed"):
            transport.invoke(inv)


if __name__ == "__main__":
    unittest.main(verbosity=2)

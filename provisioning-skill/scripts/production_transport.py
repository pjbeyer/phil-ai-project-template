"""Credential-scoped production subprocess transport (Slice A).

This is the only module in the shipped skill permitted to import ``subprocess``.
It is gated behind a private capability token so no public CLI path can construct
it; the closed ``LiveOperation`` enum and typed requests in ``live_executor.py``
are the only inputs it accepts, and every invocation is re-validated before it
runs.

Credential scoping: this transport never obtains, holds, or passes a credential
value. Git resolves credentials through the operator's configured
``credential.helper`` chain (``osxkeychain`` → ``git-credential-gh-env``); any
non-git secret arrives only via the operator's already-resolved environment,
which is still passed through the minimal-env allowlist and secret-shaped
rejection in ``live_executor.py`` before a subprocess is spawned. A missing or
invalid credential surfaces as a nonzero exit, never as a secret leak.

The inode-bound no-follow cwd capability closes the ``LOCAL_GIT_READBACK``
TOCTOU: the working directory is opened with ``O_NOFOLLOW | O_DIRECTORY`` and
pinned by inode, then the child ``fchdir``s to that descriptor before exec, so
a symlink swap between validation and process startup cannot redirect the child.
This relies on ``preexec_fn``, which is safe only in a single-threaded parent;
the provisioner's executor is single-threaded at this boundary.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from .live_executor import (
    LiveExecutorError,
    RawResult,
    _TransportInvocation,
    _redact_and_bound,
    _validate_built_invocation,
)


class _ProductionTransportCapability:
    """Private construction token; only the internal factory holds it."""


_PRODUCTION_TRANSPORT_CAPABILITY = _ProductionTransportCapability()


def _open_directory_fd(path: Path) -> int:
    """Open ``path`` as a directory with no-follow semantics and pin its inode."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        raise LiveExecutorError("production transport cwd open failed") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise LiveExecutorError("production transport cwd is not a directory")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


class ProductionTransport:
    """Run a validated, non-shell invocation through a bounded subprocess.

    Reusable across invocations (the single-use property lives at the controller
    level, not here). Construction is capability-gated; ``invoke`` re-validates
    every request before spawning.
    """

    def __init__(self, *, _capability: _ProductionTransportCapability | None = None) -> None:
        if _capability is not _PRODUCTION_TRANSPORT_CAPABILITY:
            raise LiveExecutorError("production transport requires the private factory")

    @classmethod
    def _for_authorized_executor(cls) -> "ProductionTransport":
        if cls is not ProductionTransport:
            raise LiveExecutorError("production transport subclasses are not admitted")
        return cls(_capability=_PRODUCTION_TRANSPORT_CAPABILITY)

    def invoke(self, request: _TransportInvocation) -> RawResult:
        if type(request) is not _TransportInvocation:
            raise LiveExecutorError("production transport requires the exact invocation type")
        # Defense in depth: re-run the executor's validation before any spawn.
        _validate_built_invocation(request)
        if request.shell or not request.argv:
            raise LiveExecutorError("production transport requires non-shell argv")

        cwd_descriptor: int | None = None
        if request.cwd is not None:
            cwd_descriptor = _open_directory_fd(request.cwd)

        try:
            try:
                completed = subprocess.run(
                    list(request.argv),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=dict(request.env),
                    timeout=request.timeout_seconds,
                    shell=False,
                    preexec_fn=(lambda: os.fchdir(cwd_descriptor))
                    if cwd_descriptor is not None
                    else None,
                )
            except subprocess.TimeoutExpired as error:
                raise LiveExecutorError("production transport timed out") from error
            except subprocess.SubprocessError as error:
                raise LiveExecutorError("production transport failed") from error
            except OSError as error:
                raise LiveExecutorError("production transport failed to start") from error
        finally:
            if cwd_descriptor is not None:
                os.close(cwd_descriptor)

        stdout = completed.stdout.decode("utf-8", errors="replace") if completed.stdout else ""
        stderr = completed.stderr.decode("utf-8", errors="replace") if completed.stderr else ""
        return RawResult(
            returncode=completed.returncode,
            stdout=_redact_and_bound(stdout),
            stderr=_redact_and_bound(stderr),
        )

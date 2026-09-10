"""Controlled, read-only LiveAdapter executor seam tests."""
from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from unittest.mock import patch

import scripts.live_executor as live_executor
from scripts.live_executor import (
    CentralDoltProbeRequest,
    ControlledLiveExecutor,
    GitRemotePreflightRequest,
    LiveExecutorError,
    LiveOperation,
    LocalGitReadbackRequest,
    RawResult,
)


class RecordingTransport:
    """In-memory test transport; it never invokes an external command."""

    def __init__(self, result: RawResult | None = None) -> None:
        self.result = result or RawResult(0, "ok", "")
        self.calls: list[object] = []

    def invoke_for_test(self, request: object) -> RawResult:
        self.calls.append(request)
        return self.result


class ControlledLiveExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path("/Users/synthetic-tester")
        self.transport = RecordingTransport()
        self.executor = ControlledLiveExecutor(
            transport=self.transport,
            approved_home=self.home,
        )

    def invocation(self) -> object:
        self.assertEqual(len(self.transport.calls), 1)
        return self.transport.calls[0]

    def test_unknown_operation_is_rejected_without_transport(self) -> None:
        with self.assertRaisesRegex(LiveExecutorError, "unknown live operation"):
            self.executor.execute(  # type: ignore[arg-type]
                "git-remote-preflight",
                GitRemotePreflightRequest("https://github.com/pjbeyer/demo.git"),
            )
        self.assertEqual(self.transport.calls, [])

    def test_operation_requires_its_exact_typed_request(self) -> None:
        with self.assertRaisesRegex(LiveExecutorError, "request type"):
            self.executor.execute(LiveOperation.CENTRAL_DOLT_PROBE, object())  # type: ignore[arg-type]
        with self.assertRaisesRegex(LiveExecutorError, "request type"):
            self.executor.execute(
                LiveOperation.LOCAL_GIT_READBACK,
                CentralDoltProbeRequest(),  # type: ignore[arg-type]
            )
        self.assertEqual(self.transport.calls, [])

    def test_git_remote_preflight_builds_only_the_exact_read_only_argv(self) -> None:
        result = self.executor.execute(
            LiveOperation.GIT_REMOTE_PREFLIGHT,
            GitRemotePreflightRequest("https://github.com/pjbeyer/demo.git"),
        )
        request = self.invocation()
        self.assertEqual(result, RawResult(0, "ok", ""))
        self.assertEqual(
            request.argv,  # type: ignore[attr-defined]
            (
                "git",
                "-c", "credential.helper=",
                "-c", "http.extraHeader=",
                "-c", "http.followRedirects=false",
                "-c", "protocol.allow=never",
                "-c", "protocol.https.allow=always",
                "ls-remote", "--symref",
                "https://github.com/pjbeyer/demo.git", "HEAD",
            ),
        )
        self.assertEqual(request.cwd, live_executor.NEUTRAL_GIT_CWD)  # type: ignore[attr-defined]
        self.assertEqual(request.operation, LiveOperation.GIT_REMOTE_PREFLIGHT)  # type: ignore[attr-defined]
        environment = dict(request.env)  # type: ignore[attr-defined]
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_ASKPASS"], "/usr/bin/false")
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_WORK_TREE", environment)
        self.assertNotIn("GIT_CONFIG", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)

    def test_git_remote_preflight_uses_root_cwd_and_fixed_config_free_environment(self) -> None:
        self.executor.execute(
            LiveOperation.GIT_REMOTE_PREFLIGHT,
            GitRemotePreflightRequest("https://github.com/pjbeyer/demo.git"),
        )
        request = self.invocation()
        cwd = request.cwd  # type: ignore[attr-defined]
        environment = dict(request.env)  # type: ignore[attr-defined]

        self.assertEqual(cwd, Path("/"))
        self.assertTrue(cwd.is_absolute())
        self.assertEqual(cwd.parent, cwd)
        self.assertEqual(set(environment), live_executor.MINIMAL_ENVIRONMENT_KEYS)
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_WORK_TREE", environment)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_remote_invocation_validation_rejects_ancestor_search_or_missing_config_guards(self) -> None:
        argv, _ = live_executor._remote_argv(
            GitRemotePreflightRequest("https://github.com/pjbeyer/demo.git")
        )
        unsafe_cases = (
            (Path("/var/empty"), dict(live_executor._FIXED_ENVIRONMENT)),
            (
                Path("/"),
                {
                    key: value
                    for key, value in live_executor._FIXED_ENVIRONMENT.items()
                    if key != "GIT_CONFIG_NOSYSTEM"
                },
            ),
        )
        for cwd, environment in unsafe_cases:
            with self.subTest(cwd=cwd, keys=set(environment)):
                invocation = live_executor._TransportInvocation(
                    operation=LiveOperation.GIT_REMOTE_PREFLIGHT,
                    argv=argv,
                    cwd=cwd,
                    env=environment,
                    timeout_seconds=live_executor.TIMEOUT_SECONDS,
                )
                with self.assertRaisesRegex(LiveExecutorError, "remote Git preflight"):
                    live_executor._validate_built_invocation(invocation)

    def test_git_remote_preflight_failure_has_no_retry_or_unsafe_fallback(self) -> None:
        transport = RecordingTransport(RawResult(128, "", "synthetic failure"))
        executor = ControlledLiveExecutor(transport=transport, approved_home=self.home)

        result = executor.execute(
            LiveOperation.GIT_REMOTE_PREFLIGHT,
            GitRemotePreflightRequest("https://github.com/pjbeyer/demo.git"),
        )

        self.assertEqual(result, RawResult(128, "", "synthetic failure"))
        self.assertEqual(len(transport.calls), 1)
        request = transport.calls[0]
        self.assertEqual(request.cwd, live_executor.NEUTRAL_GIT_CWD)  # type: ignore[attr-defined]
        self.assertEqual(request.argv[0], "git")  # type: ignore[attr-defined]
        self.assertIn("ls-remote", request.argv)  # type: ignore[attr-defined]

    def test_local_git_readback_builds_only_the_exact_routed_argv(self) -> None:
        repository = self.home / "Projects/pjbeyer/demo"
        with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
            self.executor.execute(
                LiveOperation.LOCAL_GIT_READBACK,
                LocalGitReadbackRequest("pjbeyer", "demo", repository),
            )
        self.assertEqual(self.transport.calls, [])
        argv, cwd = live_executor._local_git_argv(
            LocalGitReadbackRequest("pjbeyer", "demo", repository),
            self.home,
        )
        self.assertEqual(
            argv,
            (
                "git",
                "--no-optional-locks",
                "-c", "core.fsmonitor=false",
                "-C", str(repository),
                "status", "--porcelain=v1", "--branch",
            ),
        )
        self.assertEqual(cwd, repository)

    def test_central_dolt_probe_is_fixed_select_one_only(self) -> None:
        self.executor.execute(
            LiveOperation.CENTRAL_DOLT_PROBE,
            CentralDoltProbeRequest(),
        )
        request = self.invocation()
        self.assertEqual(
            request.argv,  # type: ignore[attr-defined]
            (
                "dolt", "--host", "127.0.0.1", "--port", "3307", "sql",
                "-r", "json", "-q", "SELECT 1 AS ok;",
            ),
        )
        self.assertIsNone(request.cwd)  # type: ignore[attr-defined]

    def test_local_git_readback_is_fail_closed_before_transport(self) -> None:
        repository = self.home / "Projects/pjbeyer/demo"
        transport = RecordingTransport(RawResult(128, "", "synthetic failure"))
        executor = ControlledLiveExecutor(transport=transport, approved_home=self.home)

        with self.assertRaisesRegex(
            LiveExecutorError,
            "local-git-readback requires the production transport and is intentionally unavailable",
        ):
            executor.execute(
                LiveOperation.LOCAL_GIT_READBACK,
                LocalGitReadbackRequest("pjbeyer", "demo", repository),
            )

        self.assertEqual(transport.calls, [])

    def test_every_transport_invocation_is_argv_only_with_a_bounded_timeout(self) -> None:
        cases = (
            (LiveOperation.GIT_REMOTE_PREFLIGHT, GitRemotePreflightRequest("https://github.com/flexapp/demo.git")),
            (LiveOperation.CENTRAL_DOLT_PROBE, CentralDoltProbeRequest()),
        )
        for operation, parameters in cases:
            with self.subTest(operation=operation):
                transport = RecordingTransport()
                executor = ControlledLiveExecutor(transport=transport, approved_home=self.home)
                executor.execute(operation, parameters)
                request = transport.calls[0]
                self.assertFalse(request.shell)  # type: ignore[attr-defined]
                self.assertGreater(request.timeout_seconds, 0)  # type: ignore[attr-defined]
                self.assertLessEqual(request.timeout_seconds, 30)  # type: ignore[attr-defined]
                lowered = {argument.lower() for argument in request.argv}  # type: ignore[attr-defined]
                self.assertTrue(
                    lowered.isdisjoint(
                        {
                            "--force", "-f", "push", "reset", "clean", "remove",
                            "delete", "drop", "destroy", "start", "stop", "restart",
                            "reconfigure", "bash", "sh", "zsh", "sudo",
                        }
                    )
                )

    def test_rejects_userinfo_unapproved_owner_and_secret_shaped_remote_input(self) -> None:
        rejected = (
            "https://x@github.com/pjbeyer/demo.git",
            "https://u:p@github.com/pjbeyer/demo.git",
            "https://github.com/other/demo.git",
            "https://github.com/pjbeyer/github_pat_not-a-real-token.git",
            "https://github.com/pjbeyer/demo.git --force",
            "https://github.com/pjbeyer/demo.git;stop",
            "https://github.com/pjbeyer/demo.git%20--force",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(LiveExecutorError):
                self.executor.execute(
                    LiveOperation.GIT_REMOTE_PREFLIGHT,
                    GitRemotePreflightRequest(url),
                )
        self.assertEqual(self.transport.calls, [])

    def test_rejects_unapproved_or_unsafe_local_owner_and_path_inputs(self) -> None:
        rejected = (
            LocalGitReadbackRequest(
                "other", "demo", self.home / "Projects/pjbeyer/demo"
            ),
            LocalGitReadbackRequest(
                "flexapp", "demo", self.home / "Projects/pjbeyer/demo"
            ),
            LocalGitReadbackRequest("pjbeyer", "demo", Path("relative/demo")),
            LocalGitReadbackRequest(
                "pjbeyer", "--force", self.home / "Projects/pjbeyer/--force"
            ),
            LocalGitReadbackRequest(
                "pjbeyer", "demo;stop", self.home / "Projects/pjbeyer/demo;stop"
            ),
            LocalGitReadbackRequest(
                "pjbeyer", "demo", self.home / "Projects/pjbeyer/demo/../other"
            ),
            LocalGitReadbackRequest(
                "pjbeyer", "github_pat_example", self.home / "Projects/pjbeyer/github_pat_example"
            ),
        )
        for request in rejected:
            with self.subTest(request=request), self.assertRaises(LiveExecutorError):
                self.executor.execute(LiveOperation.LOCAL_GIT_READBACK, request)
        self.assertEqual(self.transport.calls, [])

    def test_rejects_existing_local_route_symlink_that_escapes_approved_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            approved_home = temporary_root / "home"
            owner_root = approved_home / "Projects/pjbeyer"
            outside = temporary_root / "outside"
            owner_root.mkdir(parents=True)
            outside.mkdir()
            route = owner_root / "demo"
            route.symlink_to(outside, target_is_directory=True)
            transport = RecordingTransport()
            executor = ControlledLiveExecutor(
                transport=transport,
                approved_home=approved_home,
            )

            with self.assertRaisesRegex(LiveExecutorError, "resolves outside"):
                live_executor._local_git_argv(
                    LocalGitReadbackRequest("pjbeyer", "demo", route),
                    approved_home,
                )

            self.assertEqual(transport.calls, [])

    def test_valid_nonexistent_local_route_builds_without_creation_but_cannot_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            approved_home = Path(temporary_directory) / "nonexistent-home"
            route = approved_home / "Projects/pjbeyer/demo"
            transport = RecordingTransport()
            executor = ControlledLiveExecutor(
                transport=transport,
                approved_home=approved_home,
            )

            argv, cwd = live_executor._local_git_argv(
                LocalGitReadbackRequest("pjbeyer", "demo", route),
                approved_home,
            )
            with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
                executor.execute(
                    LiveOperation.LOCAL_GIT_READBACK,
                    LocalGitReadbackRequest("pjbeyer", "demo", route),
                )

            self.assertFalse(route.exists())
            self.assertEqual(argv[-3:], ("status", "--porcelain=v1", "--branch"))
            self.assertEqual(cwd, route)
            self.assertEqual(transport.calls, [])

    def test_valid_existing_local_route_builds_but_still_cannot_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            approved_home = Path(temporary_directory) / "home"
            route = approved_home / "Projects/pjbeyer/demo"
            route.mkdir(parents=True)
            transport = RecordingTransport()
            executor = ControlledLiveExecutor(
                transport=transport,
                approved_home=approved_home,
            )

            argv, cwd = live_executor._local_git_argv(
                LocalGitReadbackRequest("pjbeyer", "demo", route),
                approved_home,
            )
            with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
                executor.execute(
                    LiveOperation.LOCAL_GIT_READBACK,
                    LocalGitReadbackRequest("pjbeyer", "demo", route),
                )

            self.assertEqual(argv[-3:], ("status", "--porcelain=v1", "--branch"))
            self.assertEqual(cwd, route)
            self.assertEqual(transport.calls, [])

    def test_child_environment_is_fixed_minimal_and_never_copies_ambient_secrets(self) -> None:
        ambient = {
            "AWS_SECRET_ACCESS_KEY": "ambient-aws-value",
            "GITHUB_TOKEN": "ambient-github-value",
            "DOLT_CLI_PASSWORD": "ambient-dolt-value",
            "BEADS_DOLT_PORT": "9999",
            "BEADS_DOLT_DATABASE": "ambient_database",
            "UNRELATED": "ambient-value",
        }
        with patch.dict(os.environ, ambient, clear=False):
            self.executor.execute(
                LiveOperation.GIT_REMOTE_PREFLIGHT,
                GitRemotePreflightRequest("https://github.com/pjbeyer/demo.git"),
            )
        environment = dict(self.invocation().env)  # type: ignore[attr-defined]
        self.assertEqual(set(environment), live_executor.MINIMAL_ENVIRONMENT_KEYS)
        self.assertNotIn("ambient-aws-value", environment.values())
        self.assertNotIn("ambient-github-value", environment.values())
        self.assertNotIn("ambient-dolt-value", environment.values())
        self.assertNotIn("ambient-value", environment.values())
        self.assertNotIn("9999", environment.values())
        self.assertNotIn("ambient_database", environment.values())

    def test_controlled_environment_rejects_secret_shaped_values(self) -> None:
        controlled = {
            "PATH": "/usr/bin:/bin",
            "LANG": "token=not-a-real-secret-value",
        }
        with self.assertRaisesRegex(LiveExecutorError, "secret-shaped"):
            live_executor._minimal_environment(controlled, program="git")

    def test_controlled_environment_rejects_secret_shaped_beads_overrides(self) -> None:
        controlled = {
            "PATH": "/usr/bin:/bin",
            "BEADS_DOLT_DATABASE": "password=x",
        }
        with self.assertRaisesRegex(LiveExecutorError, "secret-shaped"):
            live_executor._minimal_environment(controlled, program="git")
        with self.assertRaisesRegex(LiveExecutorError, "secret-shaped"):
            live_executor._minimal_environment(controlled, program="bd")

    def test_beads_overrides_are_removed_only_for_bd_environment_semantics(self) -> None:
        controlled = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "BEADS_DOLT_PORT": "3307",
            "BEADS_DOLT_DATABASE": "controlled_test_database",
            "GITHUB_TOKEN": "must-not-pass",
        }
        git_environment = live_executor._minimal_environment(controlled, program="git")
        beads_environment = live_executor._minimal_environment(controlled, program="bd")
        self.assertEqual(git_environment["BEADS_DOLT_PORT"], "3307")
        self.assertEqual(git_environment["BEADS_DOLT_DATABASE"], "controlled_test_database")
        self.assertNotIn("BEADS_DOLT_PORT", beads_environment)
        self.assertNotIn("BEADS_DOLT_DATABASE", beads_environment)
        self.assertNotIn("GITHUB_TOKEN", git_environment)
        self.assertNotIn("GITHUB_TOKEN", beads_environment)

    def test_returns_only_bounded_redacted_raw_process_fields(self) -> None:
        transport = RecordingTransport(
            RawResult(
                7,
                "x" * (live_executor.MAX_OUTPUT_CHARS + 20),
                "token=not-a-real-secret-value",
            )
        )
        executor = ControlledLiveExecutor(transport=transport, approved_home=self.home)
        result = executor.execute(
            LiveOperation.CENTRAL_DOLT_PROBE,
            CentralDoltProbeRequest(),
        )
        self.assertEqual([field.name for field in fields(result)], ["returncode", "stdout", "stderr"])
        self.assertLessEqual(len(result.stdout), live_executor.MAX_OUTPUT_CHARS)
        self.assertNotIn("not-a-real-secret-value", result.stderr)
        self.assertIn("[REDACTED]", result.stderr)
        self.assertFalse(live_executor._SECRET_SHAPED.search(result.stderr))
        self.assertFalse(hasattr(result, "data"))

    def test_redacts_full_op_references_and_private_key_blocks(self) -> None:
        op_reference = "op://SyntheticVault/SyntheticItem/SyntheticField"
        private_key = (
            "-----BEGIN SYNTHETIC PRIVATE KEY-----\n"
            "SYNTHETIC-KEY-MATERIAL\n"
            "-----END SYNTHETIC PRIVATE KEY-----"
        )
        transport = RecordingTransport(
            RawResult(
                1,
                f"reference {op_reference} trailing-marker",
                f"before-marker\n{private_key}\nafter-marker",
            )
        )
        executor = ControlledLiveExecutor(transport=transport, approved_home=self.home)

        result = executor.execute(
            LiveOperation.CENTRAL_DOLT_PROBE,
            CentralDoltProbeRequest(),
        )

        self.assertNotIn(op_reference, result.stdout)
        self.assertNotIn("SYNTHETIC-KEY-MATERIAL", result.stderr)
        self.assertNotIn("-----BEGIN", result.stderr)
        self.assertNotIn("-----END", result.stderr)
        self.assertIn("reference [REDACTED] trailing-marker", result.stdout)
        self.assertIn("before-marker\n[REDACTED]\nafter-marker", result.stderr)
        self.assertFalse(live_executor._SECRET_SHAPED.search(result.stdout))
        self.assertFalse(live_executor._SECRET_SHAPED.search(result.stderr))

    def test_redacts_every_secret_detector_family_from_raw_output(self) -> None:
        secret_families = (
            "ghp_",
            "github_pat_",
            "AKIA12345678",
            "password=",
            "https://synthetic-user@",
        )
        transport = RecordingTransport(
            RawResult(1, "\n".join(secret_families), "")
        )
        executor = ControlledLiveExecutor(transport=transport, approved_home=self.home)

        result = executor.execute(
            LiveOperation.CENTRAL_DOLT_PROBE,
            CentralDoltProbeRequest(),
        )

        self.assertFalse(live_executor._SECRET_SHAPED.search(result.stdout))
        self.assertIn("[REDACTED]", result.stdout)
        for marker in secret_families:
            self.assertNotIn(marker, result.stdout)
        for detector in (
            live_executor._SECRET_SHAPED,
            live_executor._SECRET_VALUE,
            live_executor._TOKEN_VALUE,
            live_executor._OP_REFERENCE,
            live_executor._PEM_BLOCK,
            live_executor._URL_USERINFO,
        ):
            self.assertIsNone(detector.search(result.stdout))

    def test_redacts_embedded_secret_labels_and_partial_pem_begin_markers(self) -> None:
        synthetic_markers = (
            "prefix-auth_token=synthetic-marker suffix",
            "before -----BEGIN SYNTHETIC MATERIAL\nline-two\nafter",
            "partial -----BEGIN",
            "prefix-api_key\n=\nsynthetic-multiline-marker",
        )
        transport = RecordingTransport(
            RawResult(
                1,
                "\n---\n".join((synthetic_markers[0], synthetic_markers[3])),
                "\n---\n".join(synthetic_markers[1:3]),
            )
        )
        executor = ControlledLiveExecutor(transport=transport, approved_home=self.home)

        result = executor.execute(
            LiveOperation.CENTRAL_DOLT_PROBE,
            CentralDoltProbeRequest(),
        )

        self.assertNotIn("synthetic-marker", result.stdout)
        self.assertNotIn("-----BEGIN", result.stderr)
        for detector in (
            live_executor._SECRET_SHAPED,
            live_executor._SECRET_VALUE,
            live_executor._TOKEN_VALUE,
            live_executor._OP_REFERENCE,
            live_executor._PEM_BLOCK,
            live_executor._URL_USERINFO,
        ):
            self.assertIsNone(detector.search(result.stdout))
            self.assertIsNone(detector.search(result.stderr))

    def test_rejects_non_raw_transport_results(self) -> None:
        class StructuredTransport:
            def invoke_for_test(self, request: object) -> object:
                del request
                return {"returncode": 0, "stdout": "", "stderr": "", "data": {"trusted": True}}

        executor = ControlledLiveExecutor(
            transport=StructuredTransport(),  # type: ignore[arg-type]
            approved_home=self.home,
        )
        with self.assertRaisesRegex(LiveExecutorError, "raw result"):
            executor.execute(
                LiveOperation.CENTRAL_DOLT_PROBE,
                CentralDoltProbeRequest(),
            )

    def test_executor_exposes_no_generic_command_or_command_spec_authority(self) -> None:
        self.assertFalse(hasattr(self.executor, "run"))
        self.assertFalse(hasattr(self.executor, "execute_argv"))
        self.assertFalse(hasattr(live_executor, "CommandSpec"))
        self.assertFalse(hasattr(live_executor, "SubprocessTransport"))
        self.assertNotIn("subprocess", live_executor.__dict__)
        self.assertEqual(
            set(LiveOperation),
            {
                LiveOperation.GIT_REMOTE_PREFLIGHT,
                LiveOperation.LOCAL_GIT_READBACK,
                LiveOperation.CENTRAL_DOLT_PROBE,
                LiveOperation.GIT_CLONE,
                LiveOperation.GIT_REMOTE_READBACK,
            },
        )

    # -- Slice B: GIT_CLONE ------------------------------------------------

    def test_git_clone_builds_exact_credential_free_argv(self) -> None:
        from scripts.live_executor import GitCloneRequest

        argv, cwd = live_executor._git_clone_argv(
            GitCloneRequest(
                "https://github.com/pjbeyer/demo.git",
                Path("/tmp/synthetic-home/Projects/pjbeyer/demo"),
            )
        )
        self.assertEqual(
            argv,
            (
                "git", "clone", "--origin", "origin", "--no-tags",
                "https://github.com/pjbeyer/demo.git",
                "/tmp/synthetic-home/Projects/pjbeyer/demo",
            ),
        )
        self.assertIsNone(cwd)

    def test_git_clone_rejects_unsafe_origin_and_destination(self) -> None:
        from scripts.live_executor import GitCloneRequest

        rejected = (
            GitCloneRequest("https://x@github.com/pjbeyer/demo.git", Path("/tmp/a/demo")),
            GitCloneRequest("https://github.com/other/demo.git", Path("/tmp/a/demo")),
            GitCloneRequest("https://github.com/pjbeyer/demo.git", Path("relative/demo")),
            GitCloneRequest("https://github.com/pjbeyer/demo.git", Path("/tmp/a/../demo")),
            GitCloneRequest("https://github.com/pjbeyer/demo.git --force", Path("/tmp/a/demo")),
            GitCloneRequest("https://github.com/pjbeyer/github_pat_x.git", Path("/tmp/a/demo")),
        )
        for request in rejected:
            with self.subTest(request=request), self.assertRaises(LiveExecutorError):
                live_executor._git_clone_argv(request)

    def test_git_clone_is_fail_closed_under_test_transport(self) -> None:
        from scripts.live_executor import GitCloneRequest

        with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
            self.executor.execute(
                LiveOperation.GIT_CLONE,
                GitCloneRequest(
                    "https://github.com/pjbeyer/demo.git",
                    Path("/tmp/synthetic-home/Projects/pjbeyer/demo"),
                ),
            )
        self.assertEqual(self.transport.calls, [])

    def test_git_clone_requires_exact_typed_request(self) -> None:
        with self.assertRaisesRegex(LiveExecutorError, "request type"):
            self.executor.execute(LiveOperation.GIT_CLONE, object())  # type: ignore[arg-type]
        self.assertEqual(self.transport.calls, [])

    def test_git_remote_readback_builds_exact_argv_and_is_fail_closed(self) -> None:
        from scripts.live_executor import GitRemoteReadbackRequest

        path = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        argv, cwd = live_executor._git_remote_readback_argv(
            GitRemoteReadbackRequest(path)
        )
        self.assertEqual(
            argv,
            (
                "git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                "-C", str(path), "remote", "get-url", "origin",
            ),
        )
        self.assertEqual(cwd, path)

        with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
            self.executor.execute(
                LiveOperation.GIT_REMOTE_READBACK,
                GitRemoteReadbackRequest(path),
            )
        self.assertEqual(self.transport.calls, [])

    def test_git_remote_readback_rejects_unsafe_path(self) -> None:
        from scripts.live_executor import GitRemoteReadbackRequest

        for path in (Path("relative/demo"), Path("/tmp/a/../demo")):
            with self.subTest(path=path), self.assertRaises(LiveExecutorError):
                live_executor._git_remote_readback_argv(GitRemoteReadbackRequest(path))

    def test_production_executor_rejects_non_production_transport(self) -> None:
        from scripts.live_executor import ProductionLiveExecutor

        class FakeTransport:
            def invoke(self, request: object) -> RawResult:
                del request
                return RawResult(0, "", "")

        with self.assertRaisesRegex(LiveExecutorError, "production transport"):
            ProductionLiveExecutor(transport=FakeTransport(), approved_home=self.home)

    def test_production_executor_runs_through_invoke_seam(self) -> None:
        from scripts.live_executor import (
            CentralDoltProbeRequest,
            ProductionLiveExecutor,
        )

        class RecordingProdTransport:
            _is_production_transport = True

            def __init__(self) -> None:
                self.calls: list[object] = []

            def invoke(self, request: object) -> RawResult:
                self.calls.append(request)
                return RawResult(0, "ok", "")

        transport = RecordingProdTransport()
        executor = ProductionLiveExecutor(transport=transport, approved_home=self.home)
        result = executor.execute(
            LiveOperation.CENTRAL_DOLT_PROBE,
            CentralDoltProbeRequest(),
        )
        self.assertEqual(result, RawResult(0, "ok", ""))
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0].operation, LiveOperation.CENTRAL_DOLT_PROBE)  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main(verbosity=2)

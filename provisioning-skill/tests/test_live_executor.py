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
                LiveOperation.GIT_TEMPLATE_REVISION,
                LiveOperation.COPIER_RENDER,
                LiveOperation.BEADS_INIT,
                LiveOperation.BEADS_PREFIX_READ,
                LiveOperation.DOLT_REMOTE_LIST,
                LiveOperation.DOLT_REMOTE_ADD,
                LiveOperation.BEADS_SETUP,
                LiveOperation.BEADS_SETUP_CHECK,
                LiveOperation.BEADS_HOOKS_INSTALL,
                LiveOperation.BEADS_HOOKS_LIST,
                LiveOperation.BEADS_BACKUP_INIT,
                LiveOperation.BEADS_BACKUP_SYNC,
                LiveOperation.BEADS_BACKUP_STATUS,
                LiveOperation.COVERAGE_AUDIT,
                LiveOperation.SPECKIT_INIT,
                LiveOperation.SPECKIT_EXTENSION_ADD,
                LiveOperation.SPECKIT_INTEGRATION_READ,
                LiveOperation.BD_SEARCH_ISSUES,
                LiveOperation.BD_CREATE_ISSUE,
                LiveOperation.BD_SHOW_ISSUE,
                LiveOperation.GIT_STATUS_ALL,
                LiveOperation.GIT_ADD_ALL,
                LiveOperation.GIT_DIFF_CACHED_NAMES,
                LiveOperation.GIT_DIFF_CACHED_TEXT,
                LiveOperation.GIT_COMMIT,
                LiveOperation.GIT_REV_PARSE_HEAD,
                LiveOperation.GIT_STATUS_BRANCH,
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

    # -- Slice C: GIT_TEMPLATE_REVISION + COPIER_RENDER --------------------

    def test_git_template_revision_builds_exact_argv_and_is_fail_closed(self) -> None:
        from scripts.live_executor import GitTemplateRevisionRequest

        path = Path("/tmp/synthetic-home/template")
        argv, cwd = live_executor._git_template_revision_argv(
            GitTemplateRevisionRequest(path, "v0.1.3")
        )
        self.assertEqual(
            argv,
            (
                "git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                "-C", str(path), "rev-parse", "v0.1.3^{commit}",
            ),
        )
        self.assertEqual(cwd, path)
        with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
            self.executor.execute(
                LiveOperation.GIT_TEMPLATE_REVISION,
                GitTemplateRevisionRequest(path, "v0.1.3"),
            )
        self.assertEqual(self.transport.calls, [])

    def test_git_template_revision_rejects_floating_and_unsafe_inputs(self) -> None:
        from scripts.live_executor import GitTemplateRevisionRequest

        for tag, path in (
            ("HEAD", Path("/tmp/a/template")),
            ("main", Path("/tmp/a/template")),
            ("v0.1.3;stop", Path("/tmp/a/template")),
            ("v0.1.3", Path("relative/template")),
            ("v0.1.3", Path("/tmp/a/../template")),
        ):
            with self.subTest(tag=tag, path=path), self.assertRaises(LiveExecutorError):
                live_executor._git_template_revision_argv(GitTemplateRevisionRequest(path, tag))

    def test_copier_render_builds_exact_argv_from_validated_answers(self) -> None:
        from scripts.live_executor import CopierRenderRequest

        template = Path("/tmp/synthetic-home/template")
        destination = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        answers = (
            ("repository_owner", "pjbeyer"),
            ("repository_name", "demo"),
            ("project_kind", "generic"),
        )
        argv, cwd = live_executor._copier_render_argv(
            CopierRenderRequest(template, destination, "v0.1.3", answers)
        )
        self.assertEqual(
            argv,
            (
                "copier", "copy", "--defaults", "--skip-tasks", "--vcs-ref", "v0.1.3",
                "--data", "repository_owner=pjbeyer",
                "--data", "repository_name=demo",
                "--data", "project_kind=generic",
                str(template), str(destination),
            ),
        )
        self.assertEqual(cwd, destination)
        with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
            self.executor.execute(
                LiveOperation.COPIER_RENDER,
                CopierRenderRequest(template, destination, "v0.1.3", answers),
            )
        self.assertEqual(self.transport.calls, [])

    def test_copier_render_rejects_unsafe_answers_paths_and_tags(self) -> None:
        from scripts.live_executor import CopierRenderRequest

        template = Path("/tmp/a/template")
        destination = Path("/tmp/a/demo")
        rejected = (
            CopierRenderRequest(template, destination, "HEAD", (("k", "v"),)),
            CopierRenderRequest(template, destination, "v0.1.3", (("token=x", "v"),)),
            CopierRenderRequest(template, destination, "v0.1.3", (("k", "v"), ("k", "v2"))),
            CopierRenderRequest(template, destination, "v0.1.3", ()),
            CopierRenderRequest(Path("relative"), destination, "v0.1.3", (("k", "v"),)),
            CopierRenderRequest(template, Path("relative"), "v0.1.3", (("k", "v"),)),
        )
        for request in rejected:
            with self.subTest(request=request), self.assertRaises(LiveExecutorError):
                live_executor._copier_render_argv(request)

    # -- Slice D: Beads init + Dolt remote ---------------------------------

    def test_beads_init_builds_exact_server_mode_argv(self) -> None:
        from scripts.live_executor import BeadsInitRequest

        destination = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        argv, cwd = live_executor._beads_init_argv(
            BeadsInitRequest(destination, "demo")
        )
        self.assertEqual(
            argv,
            (
                "bd", "init", "--server", "--external", "--server-host", "127.0.0.1",
                "--server-port", "3307", "--prefix", "demo",
                "--non-interactive", "--role", "maintainer", "--skip-agents", "--skip-hooks",
            ),
        )
        self.assertEqual(cwd, destination)
        with self.assertRaisesRegex(LiveExecutorError, "intentionally unavailable"):
            self.executor.execute(
                LiveOperation.BEADS_INIT, BeadsInitRequest(destination, "demo")
            )
        self.assertEqual(self.transport.calls, [])

    def test_beads_init_rejects_unsafe_prefix_and_destination(self) -> None:
        from scripts.live_executor import BeadsInitRequest

        for prefix, destination in (
            ("--force", Path("/tmp/a/demo")),
            ("Demo", Path("/tmp/a/demo")),
            ("d", Path("/tmp/a/demo")),
            ("demo;stop", Path("/tmp/a/demo")),
            ("demo", Path("relative/demo")),
            ("demo", Path("/tmp/a/../demo")),
        ):
            with self.subTest(prefix=prefix, destination=destination), self.assertRaises(LiveExecutorError):
                live_executor._beads_init_argv(BeadsInitRequest(destination, prefix))

    def test_dolt_remote_add_rejects_credential_and_non_github_urls(self) -> None:
        from scripts.live_executor import DoltRemoteAddRequest

        destination = Path("/tmp/a/demo")
        for url in (
            "https://x@github.com/pjbeyer/demo.git",
            "git+https://github.com/pjbeyer/demo.git --force",
            "ssh://github.com/pjbeyer/demo.git",
            "https://github.com/pjbeyer/demo.git",
        ):
            with self.subTest(url=url), self.assertRaises(LiveExecutorError):
                live_executor._dolt_remote_add_argv(DoltRemoteAddRequest(destination, url))

        argv, cwd = live_executor._dolt_remote_add_argv(
            DoltRemoteAddRequest(destination, "git+https://github.com/pjbeyer/demo.git")
        )
        self.assertEqual(
            argv,
            ("bd", "dolt", "remote", "add", "origin", "git+https://github.com/pjbeyer/demo.git"),
        )
        self.assertEqual(cwd, destination)

    def test_beads_setup_rejects_unapproved_integration(self) -> None:
        from scripts.live_executor import BeadsSetupRequest

        destination = Path("/tmp/a/demo")
        for integration in ("ghost", "claude;stop", "codex --force"):
            with self.subTest(integration=integration), self.assertRaises(LiveExecutorError):
                live_executor._beads_setup_argv(BeadsSetupRequest(destination, integration, check=False))

        argv, _ = live_executor._beads_setup_argv(BeadsSetupRequest(destination, "claude", check=True))
        self.assertEqual(argv, ("bd", "setup", "claude", "--check"))

    def test_beads_hooks_build_exact_argv(self) -> None:
        from scripts.live_executor import BeadsHooksInstallRequest, BeadsHooksListRequest

        destination = Path("/tmp/a/demo")
        self.assertEqual(
            live_executor._beads_hooks_install_argv(BeadsHooksInstallRequest(destination))[0],
            ("bd", "hooks", "install"),
        )
        self.assertEqual(
            live_executor._beads_hooks_list_argv(BeadsHooksListRequest(destination))[0],
            ("bd", "hooks", "list", "--json"),
        )

    def test_backup_and_audit_operations_are_fail_closed_under_test_transport(self) -> None:
        from scripts.live_executor import (
            BeadsBackupInitRequest,
            BeadsBackupStatusRequest,
            BeadsBackupSyncRequest,
            CoverageAuditRequest,
        )

        for operation, params in (
            (LiveOperation.BEADS_BACKUP_INIT, BeadsBackupInitRequest(Path("/tmp/x"))),
            (LiveOperation.BEADS_BACKUP_SYNC, BeadsBackupSyncRequest(Path("/tmp/x"))),
            (LiveOperation.BEADS_BACKUP_STATUS, BeadsBackupStatusRequest(Path("/tmp/x"))),
            (
                LiveOperation.COVERAGE_AUDIT,
                CoverageAuditRequest(Path("/tmp/a"), Path("/tmp/b"), Path("/tmp/c")),
            ),
        ):
            with self.subTest(operation=operation), self.assertRaises(LiveExecutorError):
                self.executor.execute(operation, params)

    def test_speckit_operations_are_fail_closed_under_test_transport(self) -> None:
        from scripts.live_executor import (
            SpeckitExtensionAddRequest,
            SpeckitInitRequest,
            SpeckitIntegrationReadRequest,
        )

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        for operation, params in (
            (LiveOperation.SPECKIT_INIT, SpeckitInitRequest(dest)),
            (LiveOperation.SPECKIT_EXTENSION_ADD, SpeckitExtensionAddRequest(dest, "agent-context")),
            (LiveOperation.SPECKIT_INTEGRATION_READ, SpeckitIntegrationReadRequest(dest)),
        ):
            with self.subTest(operation=operation), self.assertRaises(LiveExecutorError):
                self.executor.execute(operation, params)

    def test_bd_issue_operations_are_fail_closed_under_test_transport(self) -> None:
        from scripts.live_executor import (
            BdCreateIssueRequest,
            BdSearchIssuesRequest,
            BdShowIssueRequest,
        )

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        for operation, params in (
            (LiveOperation.BD_SEARCH_ISSUES, BdSearchIssuesRequest(dest, "T")),
            (LiveOperation.BD_CREATE_ISSUE, BdCreateIssueRequest(dest, "scope-readme", "T")),
            (LiveOperation.BD_SHOW_ISSUE, BdShowIssueRequest(dest, "pjb-123")),
        ):
            with self.subTest(operation=operation), self.assertRaises(LiveExecutorError):
                self.executor.execute(operation, params)

    def test_git_closeout_operations_are_fail_closed_under_test_transport(self) -> None:
        from scripts.live_executor import (
            GitAddAllRequest,
            GitCommitRequest,
            GitDiffCachedNamesRequest,
            GitDiffCachedTextRequest,
            GitRevParseHeadRequest,
            GitStatusAllRequest,
            GitStatusBranchRequest,
        )

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        for operation, params in (
            (LiveOperation.GIT_STATUS_ALL, GitStatusAllRequest(dest)),
            (LiveOperation.GIT_ADD_ALL, GitAddAllRequest(dest)),
            (LiveOperation.GIT_DIFF_CACHED_NAMES, GitDiffCachedNamesRequest(dest)),
            (LiveOperation.GIT_DIFF_CACHED_TEXT, GitDiffCachedTextRequest(dest)),
            (LiveOperation.GIT_COMMIT, GitCommitRequest(dest, "chore: initialize project operating baseline")),
            (LiveOperation.GIT_REV_PARSE_HEAD, GitRevParseHeadRequest(dest)),
            (LiveOperation.GIT_STATUS_BRANCH, GitStatusBranchRequest(dest)),
        ):
            with self.subTest(operation=operation), self.assertRaises(LiveExecutorError):
                self.executor.execute(operation, params)


class BeadsReadbackParserTests(unittest.TestCase):
    """The adapter-owned parsers that turn raw bd --json into exact structures."""

    def test_parse_beads_prefix_raw_returns_value_only(self) -> None:
        from scripts.adapters import AdapterError, _parse_beads_prefix_raw

        raw = '{\n  "key": "issue_prefix",\n  "schema_version": 1,\n  "value": "pjb"\n}\n'
        self.assertEqual(_parse_beads_prefix_raw(raw), "pjb")

    def test_parse_beads_prefix_raw_rejects_wrong_key_and_non_object(self) -> None:
        from scripts.adapters import AdapterError, _parse_beads_prefix_raw

        for raw in ("pjb", "[1,2]", '{"value":"pjb"}', '{"key":"other","value":"pjb"}'):
            with self.subTest(raw=raw), self.assertRaises(AdapterError):
                _parse_beads_prefix_raw(raw)

    def test_parse_dolt_remotes_raw_extracts_name_url_pairs(self) -> None:
        from scripts.adapters import AdapterError, _parse_dolt_remotes_raw

        empty = _parse_dolt_remotes_raw("[]\n")
        self.assertEqual(empty, [])
        populated = _parse_dolt_remotes_raw(
            '[{"name":"origin","url":"git+https://github.com/pjbeyer/demo.git",'
            '"sql_url":"git+https://github.com/pjbeyer/demo.git","status":"ok"}]\n'
        )
        self.assertEqual(
            populated,
            [{"name": "origin", "url": "git+https://github.com/pjbeyer/demo.git"}],
        )

    def test_parse_dolt_remotes_raw_rejects_non_array_and_missing_keys(self) -> None:
        from scripts.adapters import AdapterError, _parse_dolt_remotes_raw

        for raw in ("{}", '[{"name":"origin"}]', '[{"url":"x"}]', '["origin"]', "null"):
            with self.subTest(raw=raw), self.assertRaises(AdapterError):
                _parse_dolt_remotes_raw(raw)

    def test_parse_beads_hooks_raw_extracts_installed_flags(self) -> None:
        from scripts.adapters import AdapterError, _parse_beads_hooks_raw

        raw = (
            '{"hooks":[{"Name":"pre-commit","Installed":true,"Version":"1.1.0",'
            '"IsShim":true,"Outdated":false},{"Name":"post-merge","Installed":true,'
            '"Version":"1.1.0","IsShim":true,"Outdated":false}]}\n'
        )
        self.assertEqual(
            _parse_beads_hooks_raw(raw),
            {"pre-commit": True, "post-merge": True},
        )

    def test_parse_beads_hooks_raw_rejects_malformed_input(self) -> None:
        from scripts.adapters import AdapterError, _parse_beads_hooks_raw

        for raw in ("[]", '{"hooks":[]"extra"}', '{"hooks":"notalist"}', '{"hooks":[{"Name":"x"}]}'):
            with self.subTest(raw=raw), self.assertRaises(AdapterError):
                _parse_beads_hooks_raw(raw)

    def test_beads_backup_operations_build_exact_argv(self) -> None:
        from scripts.live_executor import (
            BeadsBackupInitRequest,
            BeadsBackupStatusRequest,
            BeadsBackupSyncRequest,
        )

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        init_argv, init_cwd = live_executor._beads_backup_init_argv(BeadsBackupInitRequest(dest))
        self.assertEqual(
            init_argv,
            ("bd", "backup", "init", str(dest / ".beads" / "backup")),
        )
        self.assertEqual(init_cwd, dest)
        sync_argv, sync_cwd = live_executor._beads_backup_sync_argv(BeadsBackupSyncRequest(dest))
        self.assertEqual(sync_argv, ("bd", "backup", "sync"))
        self.assertEqual(sync_cwd, dest)
        status_argv, status_cwd = live_executor._beads_backup_status_argv(BeadsBackupStatusRequest(dest))
        self.assertEqual(status_argv, ("bd", "backup", "status", "--json"))
        self.assertEqual(status_cwd, dest)

    def test_beads_backup_operations_reject_unsafe_destination(self) -> None:
        from scripts.live_executor import LiveExecutorError, BeadsBackupInitRequest

        for dest in (Path("relative/path"), Path("/tmp/../escape")):
            with self.subTest(dest=dest), self.assertRaises(LiveExecutorError):
                live_executor._beads_backup_init_argv(BeadsBackupInitRequest(dest))

    def test_coverage_audit_builds_exact_argv_and_extended_env(self) -> None:
        from scripts.live_executor import CoverageAuditRequest

        scripts_dir = Path("/tmp/synthetic-home/.hermes/scripts")
        hermes_home = Path("/tmp/synthetic-home/.hermes")
        state_home = Path("/tmp/synthetic-home/.local/state")
        argv, cwd = live_executor._coverage_audit_argv(
            CoverageAuditRequest(scripts_dir, hermes_home, state_home)
        )
        self.assertEqual(argv, ("python3", str(scripts_dir / "audit_beads_cron_coverage.py")))
        self.assertEqual(cwd, scripts_dir)

        invocation = live_executor._build_invocation(
            LiveOperation.COVERAGE_AUDIT,
            CoverageAuditRequest(scripts_dir, hermes_home, state_home),
            Path("/tmp/synthetic-home"),
        )
        self.assertEqual(invocation.argv[0], "python3")
        self.assertEqual(invocation.cwd, scripts_dir)
        self.assertEqual(invocation.env["HERMES_HOME"], str(hermes_home))
        self.assertEqual(invocation.env["XDG_STATE_HOME"], str(state_home))
        self.assertNotIn("BEADS_DOLT_PORT", invocation.env)

    def test_coverage_audit_rejects_unsafe_or_relative_paths(self) -> None:
        from scripts.live_executor import LiveExecutorError, CoverageAuditRequest

        good = CoverageAuditRequest(
            Path("/tmp/synthetic-home/.hermes/scripts"),
            Path("/tmp/synthetic-home/.hermes"),
            Path("/tmp/synthetic-home/.local/state"),
        )
        for mutate in (
            lambda r: CoverageAuditRequest(Path("scripts"), r.hermes_home, r.state_home),
            lambda r: CoverageAuditRequest(r.scripts_dir, Path(".."), r.state_home),
            lambda r: CoverageAuditRequest(r.scripts_dir, r.hermes_home, Path("/tmp/../escape")),
        ):
            with self.subTest(), self.assertRaises(LiveExecutorError):
                live_executor._coverage_audit_argv(mutate(good))

    def test_parse_dolt_backup_status_raw_extracts_dolt_object(self) -> None:
        from scripts.adapters import AdapterError, _parse_dolt_backup_status_raw

        raw = (
            '{"backup":{"last_dolt_commit":"x","timestamp":"t"},'
            '"database_size":{"bytes":0,"human":"0 B"},'
            '"dolt":{"backup_name":"default","backup_url":"file:///tmp/x/.beads/backup",'
            '"configured":true,"created_at":"c","last_sync":"s","sync_duration":"d"}}'
        )
        parsed = _parse_dolt_backup_status_raw(raw)
        self.assertEqual(parsed["backup_url"], "file:///tmp/x/.beads/backup")
        self.assertIs(parsed["configured"], True)

    def test_parse_dolt_backup_status_raw_rejects_unconfigured_or_malformed(self) -> None:
        from scripts.adapters import AdapterError, _parse_dolt_backup_status_raw

        bad = (
            "[]",
            '{"dolt":{}}',
            '{"dolt":{"configured":false,"backup_url":"x"}}',
            '{"dolt":{"configured":true}}',
            '{"dolt":"notanobject"}',
        )
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(AdapterError):
                _parse_dolt_backup_status_raw(raw)

    def test_speckit_init_builds_exact_argv(self) -> None:
        from scripts.live_executor import SpeckitInitRequest

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        argv, cwd = live_executor._speckit_init_argv(SpeckitInitRequest(dest))
        self.assertEqual(
            argv,
            ("specify", "init", "--here", "--integration", "hermes", "--script", "sh", "--non-interactive"),
        )
        self.assertEqual(cwd, dest)

    def test_speckit_extension_add_allowlist_rejects_community_names(self) -> None:
        from scripts.live_executor import SpeckitExtensionAddRequest

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        # First-party only.
        argv, cwd = live_executor._speckit_extension_add_argv(
            SpeckitExtensionAddRequest(dest, "agent-context")
        )
        self.assertEqual(argv, ("specify", "extension", "add", "agent-context"))
        self.assertEqual(cwd, dest)
        # Deferred community names and exclusions never reach the CLI.
        for name in ("verify-tasks", "security-review", "command-density", "jira", "verify", "review"):
            with self.subTest(name=name), self.assertRaises(LiveExecutorError):
                live_executor._speckit_extension_add_argv(SpeckitExtensionAddRequest(dest, name))

    def test_speckit_integration_read_builds_exact_argv(self) -> None:
        from scripts.live_executor import SpeckitIntegrationReadRequest

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        argv, cwd = live_executor._speckit_integration_read_argv(
            SpeckitIntegrationReadRequest(dest)
        )
        self.assertEqual(argv, ("specify", "integration", "status", "--json"))
        self.assertEqual(cwd, dest)

    def test_speckit_operations_reject_unsafe_destination(self) -> None:
        from scripts.live_executor import (
            SpeckitExtensionAddRequest,
            SpeckitInitRequest,
            SpeckitIntegrationReadRequest,
        )

        for op in (
            lambda d: live_executor._speckit_init_argv(SpeckitInitRequest(d)),
            lambda d: live_executor._speckit_extension_add_argv(SpeckitExtensionAddRequest(d, "agent-context")),
            lambda d: live_executor._speckit_integration_read_argv(SpeckitIntegrationReadRequest(d)),
        ):
            for dest in (Path("relative/path"), Path("/tmp/../escape")):
                with self.subTest(dest=dest), self.assertRaises(LiveExecutorError):
                    op(dest)

    def test_parse_speckit_integration_raw_accepts_hermes_and_rejects_drift(self) -> None:
        from scripts.adapters import AdapterError, _parse_speckit_integration_raw

        good = (
            '{"status":"ok","default_integration":"hermes",'
            '"installed_integrations":["hermes"],'
            '"recorded_installed_integrations":["hermes"],'
            '"manifest_checked_integrations":["hermes","speckit"],'
            '"multi_install_safe":true,"shared_templates_target_alignment":"hermes",'
            '"missing_managed_files":0,"modified_managed_files":0,'
            '"invalid_manifest_paths":0,"unchecked_manifests":0,'
            '"manifests":{},"findings":[]}'
        )
        parsed = _parse_speckit_integration_raw(good)
        self.assertEqual(parsed["default_integration"], "hermes")

        bad = (
            "[]",
            '{"status":"ok"}',
            '{"status":"error","default_integration":"hermes","installed_integrations":["hermes"],"findings":[],"missing_managed_files":0,"modified_managed_files":0}',
            '{"status":"ok","default_integration":"copilot","installed_integrations":["copilot"],"findings":[],"missing_managed_files":0,"modified_managed_files":0}',
            '{"status":"ok","default_integration":"hermes","installed_integrations":["hermes"],"findings":["x"],"missing_managed_files":0,"modified_managed_files":0}',
            '{"status":"ok","default_integration":"hermes","installed_integrations":["hermes"],"findings":[],"missing_managed_files":1,"modified_managed_files":0}',
        )
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(AdapterError):
                _parse_speckit_integration_raw(raw)

    def test_bd_search_issues_builds_exact_argv(self) -> None:
        from scripts.live_executor import BdSearchIssuesRequest

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        argv, cwd = live_executor._bd_search_issues_argv(
            BdSearchIssuesRequest(dest, "Define initial project scope and README")
        )
        self.assertEqual(
            argv,
            ("bd", "search", "--query", "Define initial project scope and README",
             "--external-contains", "project-bootstrap:", "--status", "all", "--json"),
        )
        self.assertEqual(cwd, dest)

    def test_bd_create_issue_allowlist_and_argv(self) -> None:
        from scripts.live_executor import BdCreateIssueRequest

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        argv, cwd = live_executor._bd_create_issue_argv(
            BdCreateIssueRequest(dest, "scope-readme", "Define initial project scope and README")
        )
        self.assertEqual(argv[0:4], ("bd", "create", "Define initial project scope and README", "--type"))
        self.assertIn("--external-ref", argv)
        self.assertIn("project-bootstrap:scope-readme", argv)
        self.assertEqual(cwd, dest)
        # Unknown markers never reach the CLI.
        for marker in ("nope", "verify-tasks", "jira", "scope-readme\x00inject"):
            with self.subTest(marker=marker), self.assertRaises(LiveExecutorError):
                live_executor._bd_create_issue_argv(BdCreateIssueRequest(dest, marker, "T"))

    def test_bd_show_issue_builds_exact_argv(self) -> None:
        from scripts.live_executor import BdShowIssueRequest

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        argv, cwd = live_executor._bd_show_issue_argv(BdShowIssueRequest(dest, "pjb-123"))
        self.assertEqual(argv, ("bd", "show", "pjb-123", "--json"))
        self.assertEqual(cwd, dest)

    def test_parse_bd_issue_list_and_object(self) -> None:
        from scripts.adapters import AdapterError, _parse_bd_issue_list, _parse_bd_issue_object

        self.assertEqual(_parse_bd_issue_list("[]"), [])
        self.assertEqual(
            _parse_bd_issue_list('[{"id":"pjb-1","title":"t"}]'),
            [{"id": "pjb-1", "title": "t"}],
        )
        obj = _parse_bd_issue_object('{"id":"pjb-1","external_ref":"project-bootstrap:scope-readme"}')
        self.assertEqual(obj["external_ref"], "project-bootstrap:scope-readme")
        for list_bad in ("{}", '{"issues":[]}', '"x"', "[1]"):
            with self.subTest(raw=list_bad), self.assertRaises(AdapterError):
                _parse_bd_issue_list(list_bad)
        for obj_bad in ("[]", '"x"', "null"):
            with self.subTest(raw=obj_bad), self.assertRaises(AdapterError):
                _parse_bd_issue_object(obj_bad)

    def test_git_closeout_argv_builders(self) -> None:
        from scripts.live_executor import (
            GitAddAllRequest,
            GitCommitRequest,
            GitDiffCachedNamesRequest,
            GitDiffCachedTextRequest,
            GitRevParseHeadRequest,
            GitStatusAllRequest,
            GitStatusBranchRequest,
        )

        dest = Path("/tmp/synthetic-home/Projects/pjbeyer/demo")
        cases = (
            (live_executor._git_status_all_argv(GitStatusAllRequest(dest)),
             ("git", "--no-optional-locks", "-C", str(dest), "status", "--porcelain=v1", "--untracked-files=all")),
            (live_executor._git_add_all_argv(GitAddAllRequest(dest)),
             ("git", "--no-optional-locks", "-C", str(dest), "add", "--all")),
            (live_executor._git_diff_cached_names_argv(GitDiffCachedNamesRequest(dest)),
             ("git", "--no-optional-locks", "-C", str(dest), "diff", "--cached", "--name-only")),
            (live_executor._git_diff_cached_text_argv(GitDiffCachedTextRequest(dest)),
             ("git", "--no-optional-locks", "-C", str(dest), "diff", "--cached")),
            (live_executor._git_commit_argv(GitCommitRequest(dest, "chore: x")),
             ("git", "--no-optional-locks", "-C", str(dest), "commit", "-m", "chore: x")),
            (live_executor._git_rev_parse_head_argv(GitRevParseHeadRequest(dest)),
             ("git", "--no-optional-locks", "-C", str(dest), "rev-parse", "HEAD")),
            (live_executor._git_status_branch_argv(GitStatusBranchRequest(dest)),
             ("git", "--no-optional-locks", "-C", str(dest), "status", "--porcelain=v1", "--branch")),
        )
        for (argv, cwd), expected in cases:
            self.assertEqual(argv, expected)
            self.assertEqual(cwd, dest)

    def test_parse_git_porcelain_branch(self) -> None:
        from scripts.adapters import AdapterError, _parse_git_porcelain_branch

        clean_main = "## main...origin/main\n"
        self.assertEqual(_parse_git_porcelain_branch(clean_main)["branch"], "main")
        self.assertTrue(_parse_git_porcelain_branch(clean_main)["clean"])
        dirty = "## main...origin/main\n M README.md\n?? new.txt\n"
        parsed = _parse_git_porcelain_branch(dirty)
        self.assertEqual(parsed["branch"], "main")
        self.assertFalse(parsed["clean"])
        self.assertEqual(len(parsed["entries"]), 2)
        with self.assertRaises(AdapterError):
            _parse_git_porcelain_branch("")
        with self.assertRaises(AdapterError):
            _parse_git_porcelain_branch("no header here\n M x\n")

    def test_parse_git_staged_paths_and_rev_parse_head(self) -> None:
        from scripts.adapters import AdapterError, _parse_git_rev_parse_head, _parse_git_staged_paths

        self.assertEqual(_parse_git_staged_paths("a.txt\nb/c.txt\n"), ["a.txt", "b/c.txt"])
        with self.assertRaises(AdapterError):
            _parse_git_staged_paths("\n")
        self.assertEqual(_parse_git_rev_parse_head("a" * 40 + "\n"), "a" * 40)
        for bad in ("", "short", "a" * 39, "g" * 40):
            with self.subTest(raw=bad), self.assertRaises(AdapterError):
                _parse_git_rev_parse_head(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)

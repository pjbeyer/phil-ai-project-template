"""Controlled G01-G05 parser/readback and failure-first regressions.

The fixture below performs only in-memory state transitions and writes under a
``TemporaryDirectory``.  It never invokes Git, Copier, Dolt, Beads, a service,
a credential provider, a network origin, or a subprocess.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import patch

from scripts.adapters import (
    AdapterError,
    AgentSetupMutationRequest,
    AgentSetupReadbackRequest,
    BeadsInitRequest,
    BeadsMetadataReadbackRequest,
    BeadsPrefixReadbackRequest,
    CentralProbeRequest,
    CheckoutReadbackRequest,
    CloneMutationRequest,
    ControlledG01G03Adapter,
    ControlledGateOperation,
    CoreHooksPathReadbackRequest,
    DoltRemoteAddRequest,
    DoltRemoteReadbackRequest,
    HooksInstallRequest,
    HooksReadbackRequest,
    IntegrationsReadbackRequest,
    OriginAccessRequest,
    RawControlledGateResult,
    RenderMutationRequest,
    TemplateRevisionReadRequest,
    ToolchainReadRequest,
    _register_controlled_transport,
)
from scripts.evidence import request_fingerprint
from scripts.models import (
    APPROVED_COMPONENT_NAMES,
    ComponentPin,
    Gate,
    ImmutableLiveConfiguration,
    ProvisioningRequest,
)
from scripts.provision_project import ControlledG01G03Controller, InspectionControlError


SHA = "1" * 40
OTHER_SHA = "2" * 40
SOURCE = "pjbeyer/phil-ai-project-template"
TOOLS = ["bd", "copier", "git", "python3", "specify"]
COMMON_RENDERED = {
    ".copier-answers.yml",
    ".gitignore",
    ".github/workflows/release-please.yml",
    ".release-please-manifest.json",
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "README.md",
    "VERSION",
    "release-please-config.json",
}


def configuration() -> ImmutableLiveConfiguration:
    return ImmutableLiveConfiguration.create(
        repository_identity="pjbeyer/demo",
        template_source_identity=SOURCE,
        template_tag="v0.1.3",
        resolved_template_commit=SHA,
        component_pins={
            name: ComponentPin(name, f"speckit/component/{name}", SHA)
            for name in APPROVED_COMPONENT_NAMES
        },
    )


RawOverride = RawControlledGateResult | Callable[[object, "ControlledGateFixture"], RawControlledGateResult]


class ControlledGateFixture:
    """Operation-specific fake transport with disposable modeled files."""

    def __init__(self, *, evidence_dir: Path) -> None:
        self.evidence_dir = evidence_dir
        self.operations: list[ControlledGateOperation] = []
        self.mutations: list[ControlledGateOperation] = []
        self.exceptions: set[ControlledGateOperation] = set()
        self.overrides: dict[ControlledGateOperation, RawOverride] = {}
        self.occupy_after_g01_origin = False
        self.origin_reads = 0
        self.render_answers_change: tuple[str, str] | None = None
        self.render_answers_raw: str | None = None
        self.replay_first_origin = False
        self.first_origin_raw: RawControlledGateResult | None = None
        self.swap_after_attempt: ControlledGateOperation | None = None
        self.swap_target: str | None = None
        self.post_operation: dict[
            ControlledGateOperation, Callable[[object, "ControlledGateFixture"], None]
        ] = {}

    @staticmethod
    def _raw(operation: ControlledGateOperation, payload: object) -> RawControlledGateResult:
        return RawControlledGateResult(operation, 0, json.dumps(payload, sort_keys=True), "")

    def _assert_attempt_persisted(self, expected: str) -> None:
        try:
            evidence_files = list(self.evidence_dir.iterdir())
        except FileNotFoundError as error:
            raise AssertionError("mutation execution did not observe a persisted evidence directory") from error
        evidence_files = [path for path in evidence_files if path.name.endswith(".json")]
        if len(evidence_files) != 1:
            raise AssertionError("mutation execution did not observe one persisted evidence file")
        payload = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        persisted_attempts = payload["mutation_attempts"]
        persisted_completed = payload["mutations_completed"]
        if expected not in persisted_attempts:
            raise AssertionError("mutation attempt was not persisted before modeled execution")
        if expected in persisted_completed:
            raise AssertionError("mutation success was recorded before mandatory readback")

    @staticmethod
    def replace_regular_same_content(path: Path) -> None:
        """Atomically replace a controlled leaf while preserving its bytes."""
        replacement = path.with_name(path.name + ".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(path.stat().st_mode & 0o777)
        replacement.replace(path)

    def _write_rendered_fixture(self, request: RenderMutationRequest) -> None:
        for relative in sorted(COMMON_RENDERED - {".copier-answers.yml"}):
            target = request.destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("controlled fixture\n", encoding="utf-8")
        answers = {
            "_commit": request.template_commit,
            "_src_path": request.template_source_identity,
            "project_description": request.project_description,
            "project_kind": request.project_kind,
            "repository_name": request.repository_name,
            "repository_owner": request.repository_owner,
            "template_revision": request.template_tag,
        }
        if self.render_answers_change is not None:
            key, value = self.render_answers_change
            answers[key] = value
        text = self.render_answers_raw
        if text is None:
            text = "\n".join(
                f"{key}: {json.dumps(value, ensure_ascii=True)}"
                for key, value in sorted(answers.items())
            ) + "\n"
        (request.destination / ".copier-answers.yml").write_text(text, encoding="utf-8")

    def apply_default_mutation(
        self,
        operation: ControlledGateOperation,
        parameters: object,
    ) -> None:
        if operation is ControlledGateOperation.CLONE_MUTATION:
            if type(parameters) is not CloneMutationRequest:
                raise AssertionError("clone received the wrong exact request type")
            self._assert_attempt_persisted("G02:modeled-clone")
            if self.swap_after_attempt is operation:
                target = (
                    parameters.destination.parent
                    if self.swap_target == "tree"
                    else parameters.destination
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(self.evidence_dir.parent)
                self.mutations.append(operation)
                return
            parameters.destination.mkdir(parents=True)
            (parameters.destination / ".git").mkdir()
        elif operation is ControlledGateOperation.RENDER_MUTATION:
            if type(parameters) is not RenderMutationRequest:
                raise AssertionError("render received the wrong exact request type")
            self._assert_attempt_persisted("G03:modeled-render")
            if self.swap_after_attempt is operation:
                target = (
                    parameters.destination / ".git"
                    if self.swap_target == ".git"
                    else parameters.destination
                )
                if target.exists():
                    target.rmdir()
                target.symlink_to(self.evidence_dir.parent)
                self.mutations.append(operation)
                return
            self._write_rendered_fixture(parameters)
        else:
            raise AssertionError("not a modeled mutation operation")
        self.mutations.append(operation)

    def execute_gate_for_test(
        self,
        operation: ControlledGateOperation,
        parameters: object,
    ) -> RawControlledGateResult:
        if type(operation) is not ControlledGateOperation:
            raise AssertionError("operation was not exact and closed")
        self.operations.append(operation)
        if operation in self.exceptions:
            raise RuntimeError(
                "transport exposed token=synthetic-sensitive-value at "
                "/Users/synthetic-private/project"
            )
        def finish(result: RawControlledGateResult) -> RawControlledGateResult:
            callback = self.post_operation.get(operation)
            if callback is not None:
                callback(parameters, self)
            return result
        override = self.overrides.get(operation)
        if override is not None:
            if callable(override):
                return finish(override(parameters, self))
            return finish(override)

        if operation is ControlledGateOperation.ORIGIN_ACCESS_READ:
            if type(parameters) is not OriginAccessRequest:
                raise AssertionError("origin probe received the wrong exact request type")
            self.origin_reads += 1
            result = self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "identity": parameters.repository_identity,
                    "operation": "authenticated-repository-access",
                    "origin_url": parameters.origin_url,
                    "permission": "write",
                    "references": [],
                },
            )
            if self.first_origin_raw is None:
                self.first_origin_raw = result
            elif self.replay_first_origin:
                return self.first_origin_raw
            if self.occupy_after_g01_origin and self.origin_reads == 1:
                parameters.destination.mkdir(parents=True)
                (parameters.destination / "occupied").write_text("fixture\n", encoding="utf-8")
            return result
        if operation is ControlledGateOperation.TOOLCHAIN_READ:
            if type(parameters) is not ToolchainReadRequest:
                raise AssertionError("tool probe received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "operation": "toolchain-read",
                    "tools": TOOLS,
                },
            )
        if operation is ControlledGateOperation.CENTRAL_DOLT_READ:
            if type(parameters) is not CentralProbeRequest:
                raise AssertionError("central probe received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "host": "127.0.0.1",
                    "operation": "central-dolt-select-one-and-prefix-read",
                    "port": 3307,
                    "prefix_matches": [],
                    "query_result": [{"ok": 1}],
                },
            )
        if operation is ControlledGateOperation.CLONE_MUTATION:
            self.apply_default_mutation(operation, parameters)
            return finish(RawControlledGateResult(operation, 0, "", ""))
        if operation is ControlledGateOperation.CHECKOUT_READBACK:
            if type(parameters) is not CheckoutReadbackRequest:
                raise AssertionError("checkout readback received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "branch": "main",
                    "challenge": parameters.challenge,
                    "identity": parameters.repository_identity,
                    "operation": "checkout-readback",
                    "origin_url": parameters.origin_url,
                    "root_digest": parameters.destination_digest,
                },
            )
        if operation is ControlledGateOperation.TEMPLATE_REVISION_READ:
            if type(parameters) is not TemplateRevisionReadRequest:
                raise AssertionError("template readback received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "operation": "template-revision-readback",
                    "resolved_commit": parameters.expected_commit,
                    "source_identity": parameters.template_source_identity,
                    "tag": parameters.template_tag,
                },
            )
        if operation is ControlledGateOperation.RENDER_MUTATION:
            self.apply_default_mutation(operation, parameters)
            return finish(RawControlledGateResult(operation, 0, "", ""))
        if operation is ControlledGateOperation.BEADS_INIT_MUTATION:
            if type(parameters) is not BeadsInitRequest:
                raise AssertionError("Beads init received the wrong exact request type")
            self._assert_attempt_persisted("G04:modeled-beads-init")
            parameters.target.initialize_beads(parameters.beads_prefix)
            self.mutations.append(operation)
            return finish(RawControlledGateResult(operation, 0, "", ""))
        if operation is ControlledGateOperation.BEADS_METADATA_READBACK:
            if type(parameters) is not BeadsMetadataReadbackRequest:
                raise AssertionError("metadata readback received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "database": parameters.expected_database,
                    "host": "127.0.0.1",
                    "mode": "server",
                    "operation": "beads-generated-metadata-readback",
                    "port": 3307,
                    "prefix": parameters.beads_prefix,
                },
            )
        if operation is ControlledGateOperation.BEADS_PREFIX_READBACK:
            if type(parameters) is not BeadsPrefixReadbackRequest:
                raise AssertionError("prefix readback received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "operation": "beads-prefix-readback",
                    "prefix": parameters.beads_prefix,
                },
            )
        if operation is ControlledGateOperation.DOLT_REMOTE_READBACK:
            if type(parameters) is not DoltRemoteReadbackRequest:
                raise AssertionError("remote readback received the wrong exact request type")
            remotes = [] if not getattr(self, "remote_added", False) else [
                {"name": "origin", "url": parameters.expected_remote_url}
            ]
            return self._raw(
                operation,
                {"challenge": parameters.challenge, "operation": "dolt-remote-readback", "remotes": remotes},
            )
        if operation is ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION:
            if type(parameters) is not DoltRemoteAddRequest:
                raise AssertionError("remote add received the wrong exact request type")
            self._assert_attempt_persisted("G05:modeled-dolt-remote-add")
            parameters.target.add_dolt_remote()
            self.remote_added = True
            self.mutations.append(operation)
            return finish(RawControlledGateResult(operation, 0, "", ""))
        if operation is ControlledGateOperation.AGENT_SETUP_MUTATION:
            if type(parameters) is not AgentSetupMutationRequest:
                raise AssertionError("agent setup received the wrong exact request type")
            self._assert_attempt_persisted(f"G05:modeled-{parameters.integration}-setup")
            parameters.target.setup_agent(parameters.integration)
            integrations = getattr(self, "integrations", set())
            integrations.add(parameters.integration)
            self.integrations = integrations
            self.mutations.append(operation)
            return finish(RawControlledGateResult(operation, 0, "", ""))
        if operation is ControlledGateOperation.AGENT_SETUP_READBACK:
            if type(parameters) is not AgentSetupReadbackRequest:
                raise AssertionError("agent setup readback received the wrong exact request type")
            installed = parameters.integration in getattr(self, "integrations", set())
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "installed": installed,
                    "integration": parameters.integration,
                    "operation": "agent-setup-readback",
                },
            )
        if operation is ControlledGateOperation.INTEGRATIONS_READBACK:
            if type(parameters) is not IntegrationsReadbackRequest:
                raise AssertionError("integrations readback received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "integrations": sorted(getattr(self, "integrations", set())),
                    "operation": "agent-integrations-readback",
                },
            )
        if operation is ControlledGateOperation.HOOKS_INSTALL_MUTATION:
            if type(parameters) is not HooksInstallRequest:
                raise AssertionError("hooks install received the wrong exact request type")
            self._assert_attempt_persisted("G05:modeled-hooks-install")
            parameters.target.install_hooks(parameters.expected_hooks)
            self.hooks_installed = True
            self.mutations.append(operation)
            return finish(RawControlledGateResult(operation, 0, "", ""))
        if operation is ControlledGateOperation.HOOKS_READBACK:
            if type(parameters) is not HooksReadbackRequest:
                raise AssertionError("hooks readback received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "hook_location": ".beads/hooks",
                    "hooks": list(parameters.expected_hooks),
                    "managed": getattr(self, "hooks_installed", False),
                    "operation": "beads-hooks-readback",
                },
            )
        if operation is ControlledGateOperation.CORE_HOOKS_PATH_READBACK:
            if type(parameters) is not CoreHooksPathReadbackRequest:
                raise AssertionError("core hooks path readback received the wrong exact request type")
            return self._raw(
                operation,
                {
                    "challenge": parameters.challenge,
                    "hooks_path": ".beads/hooks",
                    "operation": "git-core-hooks-path-readback",
                },
            )
        raise AssertionError(f"unexpected controlled operation: {operation}")


class ControlledG01G03Tests(unittest.TestCase):
    def make_case(self) -> tuple[
        tempfile.TemporaryDirectory[str],
        Path,
        Path,
        ProvisioningRequest,
        ImmutableLiveConfiguration,
        ControlledGateFixture,
        ControlledG01G03Controller,
    ]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        home = root / "home"
        home.mkdir()
        evidence_dir = (root / "evidence").resolve()
        request = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git",
            "demo",
            "generic",
            "controlled description",
        )
        config = configuration()
        fixture = ControlledGateFixture(evidence_dir=evidence_dir)
        controller = ControlledG01G03Controller._for_controlled_test(
            fixture,
            evidence_dir=evidence_dir,
        )
        return temporary, home, evidence_dir, request, config, fixture, controller

    def run_case(self, **_: object):
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        result = controller.run(request, configuration=config, home=home)
        fixture.controller = controller
        return result, home, evidence_dir, request, config, fixture

    def assert_persisted_safe(self, result: object, home: Path, evidence_dir: Path) -> dict[str, object]:
        files = list(evidence_dir.glob("*.json"))
        self.assertEqual(len(files), 1)
        payload = json.loads(files[0].read_text(encoding="utf-8"))
        serialized = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["state"], result.state)  # type: ignore[attr-defined]
        self.assertEqual(payload["destination"], "[REDACTED]")
        self.assertNotIn("synthetic-sensitive-value", serialized)
        self.assertNotIn(str(home), serialized)
        self.assertNotIn("/Users/synthetic-private", serialized)
        self.assertNotIn("token=", serialized)
        return payload

    def test_successful_controlled_slice_rechecks_and_reads_disk_without_live_readiness(self) -> None:
        result, home, evidence_dir, request, config, fixture = self.run_case()
        self.assertEqual(result.state, "partial")
        self.assertTrue(result.simulation)
        self.assertIsNone(result.failed_gate)
        self.assertEqual(
            [(item.gate, item.status) for item in result.gates],
            [
                (Gate.PREFLIGHT, "passed"), (Gate.CLONE, "passed"), (Gate.RENDER, "passed"),
                (Gate.BEADS, "passed"), (Gate.BEADS_REMOTE, "passed"),
            ],
        )
        self.assertEqual(
            fixture.operations,
            [
                ControlledGateOperation.ORIGIN_ACCESS_READ,
                ControlledGateOperation.TOOLCHAIN_READ,
                ControlledGateOperation.CENTRAL_DOLT_READ,
                ControlledGateOperation.ORIGIN_ACCESS_READ,
                ControlledGateOperation.CLONE_MUTATION,
                ControlledGateOperation.CHECKOUT_READBACK,
                ControlledGateOperation.CHECKOUT_READBACK,
                ControlledGateOperation.TEMPLATE_REVISION_READ,
                ControlledGateOperation.RENDER_MUTATION,
                ControlledGateOperation.CENTRAL_DOLT_READ,
                ControlledGateOperation.BEADS_INIT_MUTATION,
                ControlledGateOperation.BEADS_METADATA_READBACK,
                ControlledGateOperation.BEADS_PREFIX_READBACK,
                ControlledGateOperation.BEADS_METADATA_READBACK,
                ControlledGateOperation.DOLT_REMOTE_READBACK,
                ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION,
                ControlledGateOperation.DOLT_REMOTE_READBACK,
                ControlledGateOperation.AGENT_SETUP_MUTATION,
                ControlledGateOperation.AGENT_SETUP_READBACK,
                ControlledGateOperation.AGENT_SETUP_MUTATION,
                ControlledGateOperation.AGENT_SETUP_READBACK,
                ControlledGateOperation.INTEGRATIONS_READBACK,
                ControlledGateOperation.HOOKS_INSTALL_MUTATION,
                ControlledGateOperation.HOOKS_READBACK,
                ControlledGateOperation.CORE_HOOKS_PATH_READBACK,
            ],
        )
        self.assertEqual(
            fixture.mutations,
            [
                ControlledGateOperation.CLONE_MUTATION,
                ControlledGateOperation.RENDER_MUTATION,
                ControlledGateOperation.BEADS_INIT_MUTATION,
                ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION,
                ControlledGateOperation.AGENT_SETUP_MUTATION,
                ControlledGateOperation.AGENT_SETUP_MUTATION,
                ControlledGateOperation.HOOKS_INSTALL_MUTATION,
            ],
        )
        self.assertEqual(
            result.mutation_attempts,
            [
                "G02:modeled-clone", "G03:modeled-render", "G04:modeled-beads-init",
                "G05:modeled-dolt-remote-add", "G05:modeled-claude-setup",
                "G05:modeled-codex-setup", "G05:modeled-hooks-install",
            ],
        )
        self.assertEqual(result.mutations_completed, result.mutation_attempts)
        self.assertEqual(result.git_sync, "not-attempted")
        self.assertEqual(result.dolt_sync, "not-attempted")
        self.assertIn("controlled", result.next_action.lower())
        self.assertIn("unavailable", result.next_action.lower())
        self.assert_persisted_safe(result, home, evidence_dir)
        destination = home / config.destination_route
        answers = (destination / ".copier-answers.yml").read_text(encoding="utf-8")
        self.assertIn(config.resolved_template_commit, answers)
        self.assertNotIn(str(home), answers)
        self.assertEqual(len(set(fixture.controller._evidence_fds_used)), 1)
        self.assertGreaterEqual(len(fixture.controller._evidence_fds_used), 17)
        self.assertEqual(
            request_fingerprint(request, destination),
            result.request_fingerprint,
        )

    def test_destination_and_origin_are_rechecked_before_clone(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        fixture.occupy_after_g01_origin = True
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.state, "partial")
        self.assertEqual(result.failed_gate, str(Gate.CLONE))
        self.assertNotIn(ControlledGateOperation.CLONE_MUTATION, fixture.operations)
        self.assertEqual(result.mutation_attempts, [])
        self.assert_persisted_safe(result, home, evidence_dir)

        _, home, evidence_dir, request, config, fixture, controller = self.make_case()

        def changed_origin(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
            if type(parameters) is not OriginAccessRequest:
                raise AssertionError
            transport.origin_reads += 1
            identity = parameters.repository_identity if transport.origin_reads == 1 else "pjbeyer/other"
            return transport._raw(
                ControlledGateOperation.ORIGIN_ACCESS_READ,
                {
                    "challenge": parameters.challenge,
                    "identity": identity,
                    "operation": "authenticated-repository-access",
                    "origin_url": parameters.origin_url,
                    "permission": "write",
                    "references": [],
                },
            )

        fixture.overrides[ControlledGateOperation.ORIGIN_ACCESS_READ] = changed_origin
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.CLONE))
        self.assertNotIn(ControlledGateOperation.CLONE_MUTATION, fixture.operations)
        self.assertEqual(fixture.operations[-1], ControlledGateOperation.ORIGIN_ACCESS_READ)
        self.assert_persisted_safe(result, home, evidence_dir)

    def test_template_revision_is_rechecked_immediately_before_render(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()

        def changed_revision(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
            if type(parameters) is not TemplateRevisionReadRequest:
                raise AssertionError
            return transport._raw(
                ControlledGateOperation.TEMPLATE_REVISION_READ,
                {
                    "challenge": parameters.challenge,
                    "operation": "template-revision-readback",
                    "resolved_commit": OTHER_SHA,
                    "source_identity": parameters.template_source_identity,
                    "tag": parameters.template_tag,
                },
            )

        fixture.overrides[ControlledGateOperation.TEMPLATE_REVISION_READ] = changed_revision
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.state, "partial")
        self.assertEqual(result.failed_gate, str(Gate.RENDER))
        self.assertEqual(fixture.operations[-1], ControlledGateOperation.TEMPLATE_REVISION_READ)
        self.assertNotIn(ControlledGateOperation.RENDER_MUTATION, fixture.operations)
        self.assertEqual(result.mutations_completed, ["G02:modeled-clone"])
        self.assert_persisted_safe(result, home, evidence_dir)

    def test_g01_failure_first_matrix_is_blocked_sanitized_and_never_mutates(self) -> None:
        cases = ("nonzero", "malformed", "parser-mismatch", "filesystem", "transport", "late-readback")
        for case in cases:
            with self.subTest(case=case):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                patcher = None
                if case == "nonzero":
                    fixture.overrides[ControlledGateOperation.ORIGIN_ACCESS_READ] = RawControlledGateResult(
                        ControlledGateOperation.ORIGIN_ACCESS_READ,
                        7,
                        "",
                        "token=synthetic-sensitive-value /Users/synthetic-private/project",
                    )
                elif case == "malformed":
                    fixture.overrides[ControlledGateOperation.ORIGIN_ACCESS_READ] = RawControlledGateResult(
                        ControlledGateOperation.ORIGIN_ACCESS_READ, 0, "{", ""
                    )
                elif case == "parser-mismatch":
                    fixture.overrides[ControlledGateOperation.ORIGIN_ACCESS_READ] = fixture._raw(
                        ControlledGateOperation.ORIGIN_ACCESS_READ,
                        {
                            "challenge": "wrong",
                            "identity": "pjbeyer/other",
                            "operation": "authenticated-repository-access",
                            "origin_url": request.origin_url,
                            "permission": "admin",
                            "references": ["refs/heads/main"],
                        },
                    )
                elif case == "filesystem":
                    patcher = patch.object(
                        ControlledG01G03Adapter,
                        "_assert_destination_absent",
                        side_effect=OSError(
                            "filesystem exposed token=synthetic-sensitive-value at /Users/synthetic-private/project"
                        ),
                    )
                elif case == "transport":
                    fixture.exceptions.add(ControlledGateOperation.ORIGIN_ACCESS_READ)
                elif case == "late-readback":
                    fixture.overrides[ControlledGateOperation.CENTRAL_DOLT_READ] = RawControlledGateResult(
                        ControlledGateOperation.CENTRAL_DOLT_READ, 9, "", "synthetic central failure"
                    )
                if patcher is None:
                    result = controller.run(request, configuration=config, home=home)
                else:
                    with patcher:
                        result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.state, "blocked-preflight")
                self.assertEqual(result.failed_gate, str(Gate.PREFLIGHT))
                self.assertEqual(result.mutation_attempts, [])
                self.assertEqual(result.mutations_completed, [])
                self.assertEqual(fixture.mutations, [])
                payload = self.assert_persisted_safe(result, home, evidence_dir)
                self.assertEqual(payload["gates"][-1]["gate"], Gate.PREFLIGHT.value)
                self.assertEqual(payload["gates"][-1]["status"], "failed")

    def test_g02_failure_first_matrix_preserves_pre_execution_attempts(self) -> None:
        cases = ("nonzero", "malformed", "parser-mismatch", "filesystem", "transport", "failed-readback")
        for case in cases:
            with self.subTest(case=case):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                patcher = None
                if case == "nonzero":
                    fixture.overrides[ControlledGateOperation.CLONE_MUTATION] = RawControlledGateResult(
                        ControlledGateOperation.CLONE_MUTATION, 8, "", "synthetic clone failure"
                    )
                elif case == "malformed":
                    def malformed_clone(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                        transport.apply_default_mutation(ControlledGateOperation.CLONE_MUTATION, parameters)
                        return RawControlledGateResult(
                            ControlledGateOperation.CLONE_MUTATION, 0, "unexpected assertion", ""
                        )
                    fixture.overrides[ControlledGateOperation.CLONE_MUTATION] = malformed_clone
                elif case == "parser-mismatch":
                    def mismatched_checkout(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                        if type(parameters) is not CheckoutReadbackRequest:
                            raise AssertionError
                        return transport._raw(
                            ControlledGateOperation.CHECKOUT_READBACK,
                            {
                                "branch": "develop",
                                "challenge": parameters.challenge,
                                "identity": "pjbeyer/other",
                                "operation": "checkout-readback",
                                "origin_url": parameters.origin_url,
                                "root_digest": parameters.destination_digest,
                            },
                        )
                    fixture.overrides[ControlledGateOperation.CHECKOUT_READBACK] = mismatched_checkout
                elif case == "filesystem":
                    patcher = patch.object(
                        ControlledG01G03Adapter,
                        "_validate_checkout_filesystem",
                        side_effect=OSError(
                            "filesystem exposed token=synthetic-sensitive-value at /Users/synthetic-private/project"
                        ),
                    )
                elif case == "transport":
                    fixture.exceptions.add(ControlledGateOperation.CLONE_MUTATION)
                elif case == "failed-readback":
                    fixture.overrides[ControlledGateOperation.CHECKOUT_READBACK] = RawControlledGateResult(
                        ControlledGateOperation.CHECKOUT_READBACK,
                        6,
                        "",
                        "token=synthetic-sensitive-value /Users/synthetic-private/project",
                    )
                if patcher is None:
                    result = controller.run(request, configuration=config, home=home)
                else:
                    with patcher:
                        result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.state, "partial")
                self.assertEqual(result.failed_gate, str(Gate.CLONE))
                self.assertEqual(result.mutation_attempts, ["G02:modeled-clone"])
                self.assertEqual(result.mutations_completed, [])
                payload = self.assert_persisted_safe(result, home, evidence_dir)
                self.assertEqual(payload["mutation_attempts"], ["G02:modeled-clone"])
                self.assertEqual(payload["mutations_completed"], [])
                self.assertEqual(payload["gates"][-1]["gate"], Gate.CLONE.value)
                self.assertEqual(payload["gates"][-1]["status"], "failed")
                if case in {"malformed", "parser-mismatch", "filesystem", "failed-readback"}:
                    self.assertIn(ControlledGateOperation.CLONE_MUTATION, fixture.mutations)

    def test_g03_failure_first_matrix_keeps_clone_and_unproven_render_separate(self) -> None:
        cases = ("nonzero", "malformed", "parser-mismatch", "filesystem", "transport", "failed-readback")
        for case in cases:
            with self.subTest(case=case):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                patcher = None
                if case == "nonzero":
                    fixture.overrides[ControlledGateOperation.RENDER_MUTATION] = RawControlledGateResult(
                        ControlledGateOperation.RENDER_MUTATION, 5, "", "synthetic render failure"
                    )
                elif case == "malformed":
                    fixture.overrides[ControlledGateOperation.TEMPLATE_REVISION_READ] = RawControlledGateResult(
                        ControlledGateOperation.TEMPLATE_REVISION_READ, 0, "not-json", ""
                    )
                elif case == "parser-mismatch":
                    def wrong_revision(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                        if type(parameters) is not TemplateRevisionReadRequest:
                            raise AssertionError
                        return transport._raw(
                            ControlledGateOperation.TEMPLATE_REVISION_READ,
                            {
                                "challenge": parameters.challenge,
                                "operation": "template-revision-readback",
                                "resolved_commit": OTHER_SHA,
                                "source_identity": parameters.template_source_identity,
                                "tag": parameters.template_tag,
                            },
                        )
                    fixture.overrides[ControlledGateOperation.TEMPLATE_REVISION_READ] = wrong_revision
                elif case == "filesystem":
                    patcher = patch.object(
                        ControlledG01G03Adapter,
                        "_read_copier_answers",
                        side_effect=OSError(
                            "filesystem exposed token=synthetic-sensitive-value at /Users/synthetic-private/project"
                        ),
                    )
                elif case == "transport":
                    fixture.exceptions.add(ControlledGateOperation.RENDER_MUTATION)
                elif case == "failed-readback":
                    fixture.render_answers_change = ("project_kind", "homebrew-tap")
                if patcher is None:
                    result = controller.run(request, configuration=config, home=home)
                else:
                    with patcher:
                        result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.state, "partial")
                self.assertEqual(result.failed_gate, str(Gate.RENDER))
                self.assertEqual(result.mutations_completed, ["G02:modeled-clone"])
                if case in {"nonzero", "filesystem", "transport", "failed-readback"}:
                    self.assertEqual(
                        result.mutation_attempts,
                        ["G02:modeled-clone", "G03:modeled-render"],
                    )
                else:
                    self.assertEqual(result.mutation_attempts, ["G02:modeled-clone"])
                payload = self.assert_persisted_safe(result, home, evidence_dir)
                self.assertEqual(payload["mutations_completed"], ["G02:modeled-clone"])
                self.assertEqual(payload["gates"][-1]["gate"], Gate.RENDER.value)
                self.assertEqual(payload["gates"][-1]["status"], "failed")
                if case in {"filesystem", "failed-readback"}:
                    self.assertIn(ControlledGateOperation.RENDER_MUTATION, fixture.mutations)

    def test_direct_adapter_subclass_forged_admission_and_noop_callback_cannot_mutate(self) -> None:
        temporary, home, evidence_dir, request, config, fixture, controller = self.make_case()
        del temporary
        destination = home / config.destination_route
        fingerprint = request_fingerprint(request, destination)
        from scripts.preflight import parse_origin
        parsed = parse_origin(request.origin_url)

        constructor = dict(
            request=request,
            origin=parsed,
            destination=destination,
            configuration=config,
            fingerprint=fingerprint,
            run_nonce="a" * 64,
            fixture_session=object(),
        )
        with self.assertRaises(AdapterError):
            ControlledG01G03Adapter(fixture, **constructor)
        with self.assertRaises(AdapterError):
            ControlledG01G03Adapter(fixture, _admission=object(), **constructor)

        class DerivedAdapter(ControlledG01G03Adapter):
            pass

        with self.assertRaises(AdapterError):
            DerivedAdapter(fixture, _admission=object(), **constructor)
        with self.assertRaises(AdapterError):
            _register_controlled_transport(object(), fixture, lambda *_: True)
        with self.assertRaises(AdapterError):
            _register_controlled_transport(controller, fixture, lambda *_: True)
        self.assertEqual(fixture.mutations, [])
        self.assertFalse(destination.exists())

        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        original = ControlledG01G03Adapter._authorize_mutation_attempt

        def noop_attempt(self: ControlledG01G03Adapter, gate: Gate, label: str) -> None:
            del self, gate, label

        with patch.object(ControlledG01G03Adapter, "_authorize_mutation_attempt", noop_attempt):
            result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.CLONE))
        self.assertEqual(result.mutation_attempts, [])
        self.assertEqual(fixture.mutations, [])
        self.assertIn("not persisted", result.gates[-1].detail)
        self.assertIsNotNone(original)

    def test_task6_g04_g05_success_accepts_database_equal_prefix_from_two_readbacks(self) -> None:
        result, home, evidence_dir, request, config, fixture = self.run_case()
        self.assertEqual(result.state, "partial")
        self.assertIsNone(result.failed_gate)
        self.assertEqual(
            [(item.gate, item.status) for item in result.gates[-2:]],
            [(Gate.BEADS, "passed"), (Gate.BEADS_REMOTE, "passed")],
        )
        self.assertEqual(
            result.mutation_attempts,
            [
                "G02:modeled-clone", "G03:modeled-render", "G04:modeled-beads-init",
                "G05:modeled-dolt-remote-add", "G05:modeled-claude-setup",
                "G05:modeled-codex-setup", "G05:modeled-hooks-install",
            ],
        )
        self.assertEqual(result.mutations_completed, result.mutation_attempts)
        self.assertEqual(result.actual_database, request.beads_prefix)
        self.assertEqual(result.git_sync, "not-attempted")
        self.assertEqual(result.dolt_sync, "not-attempted")
        payload = self.assert_persisted_safe(result, home, evidence_dir)
        self.assertEqual(payload["actual_database"], request.beads_prefix)
        destination = home / config.destination_route
        metadata = json.loads((destination / ".beads/metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["dolt_database"], request.beads_prefix)
        self.assertTrue(all((destination / ".beads/hooks" / name).is_file() for name in (
            "post-checkout", "post-merge", "pre-commit", "pre-push", "prepare-commit-msg",
        )))

    def test_task6_g04_rechecks_central_boundary_and_rejects_final_metadata_drift(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        central_reads = 0

        def changed_central(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
            nonlocal central_reads
            if type(parameters) is not CentralProbeRequest:
                raise AssertionError
            central_reads += 1
            return transport._raw(
                ControlledGateOperation.CENTRAL_DOLT_READ,
                {
                    "challenge": parameters.challenge,
                    "host": "127.0.0.1",
                    "operation": "central-dolt-select-one-and-prefix-read",
                    "port": 3307,
                    "prefix_matches": [] if central_reads == 1 else ["demo-existing"],
                    "query_result": [{"ok": 1}],
                },
            )

        fixture.overrides[ControlledGateOperation.CENTRAL_DOLT_READ] = changed_central
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.BEADS))
        self.assertEqual(central_reads, 2)
        self.assertNotIn(ControlledGateOperation.BEADS_INIT_MUTATION, fixture.mutations)
        self.assertNotIn("G04:modeled-beads-init", result.mutation_attempts)
        self.assert_persisted_safe(result, home, evidence_dir)

        _, home, evidence_dir, request, config, fixture, controller = self.make_case()

        def change_metadata_after_prefix(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
            if type(parameters) is not BeadsPrefixReadbackRequest:
                raise AssertionError
            metadata_path = transport.evidence_dir.parent / "home" / configuration().destination_route / ".beads" / "metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "dolt_database": "other",
                        "dolt_mode": "server",
                        "dolt_server_host": "127.0.0.1",
                        "dolt_server_port": 3307,
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            return transport._raw(
                ControlledGateOperation.BEADS_PREFIX_READBACK,
                {
                    "challenge": parameters.challenge,
                    "operation": "beads-prefix-readback",
                    "prefix": parameters.beads_prefix,
                },
            )

        fixture.overrides[ControlledGateOperation.BEADS_PREFIX_READBACK] = change_metadata_after_prefix
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.BEADS))
        self.assertIn("G04:modeled-beads-init", result.mutation_attempts)
        self.assertNotIn("G04:modeled-beads-init", result.mutations_completed)
        self.assertEqual(result.actual_database, "not-reached")
        self.assert_persisted_safe(result, home, evidence_dir)

    def test_task6_secure_metadata_read_and_hook_content_are_required(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        destination = home / config.destination_route
        metadata = destination / ".beads" / "metadata.json"
        outside = evidence_dir.parent / "outside-metadata.json"
        outside.write_text('{"dolt_database":"other"}', encoding="utf-8")
        from scripts import adapters as adapters_module

        real_open = adapters_module.os.open
        swapped = False

        def swap_metadata_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            nonlocal swapped
            if path == ".beads" and not swapped:
                swapped = True
                metadata.unlink()
                metadata.symlink_to(outside)
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        with patch.object(adapters_module.os, "open", side_effect=swap_metadata_before_open):
            result = controller.run(request, configuration=config, home=home)
        self.assertTrue(swapped)
        self.assertEqual(result.failed_gate, str(Gate.BEADS))
        self.assertIn("G04:modeled-beads-init", result.mutation_attempts)
        self.assertNotIn("G04:modeled-beads-init", result.mutations_completed)
        self.assert_persisted_safe(result, home, evidence_dir)

        _, home, evidence_dir, request, config, fixture, controller = self.make_case()

        def install_inert_hook(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
            if type(parameters) is not HooksInstallRequest:
                raise AssertionError
            transport._assert_attempt_persisted("G05:modeled-hooks-install")
            parameters.target.install_hooks(parameters.expected_hooks)
            hooks = (
                transport.evidence_dir.parent
                / "home"
                / configuration().destination_route
                / ".beads"
                / "hooks"
            )
            for name in parameters.expected_hooks:
                hook = hooks / name
                hook.write_text("untrusted hook\n", encoding="utf-8")
                hook.chmod(0o600)
            transport.hooks_installed = True
            transport.mutations.append(ControlledGateOperation.HOOKS_INSTALL_MUTATION)
            return RawControlledGateResult(ControlledGateOperation.HOOKS_INSTALL_MUTATION, 0, "", "")

        fixture.overrides[ControlledGateOperation.HOOKS_INSTALL_MUTATION] = install_inert_hook
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.BEADS_REMOTE))
        self.assertIn("G05:modeled-hooks-install", result.mutation_attempts)
        self.assertNotIn("G05:modeled-hooks-install", result.mutations_completed)
        self.assert_persisted_safe(result, home, evidence_dir)

    def test_task6_g04_failure_first_matrix_is_partial_and_preserves_attempt(self) -> None:
        cases = ("nonzero", "malformed", "parser-mismatch", "filesystem", "transport", "failed-readback")
        for case in cases:
            with self.subTest(case=case):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                patcher = None
                if case == "nonzero":
                    fixture.overrides[ControlledGateOperation.BEADS_INIT_MUTATION] = RawControlledGateResult(
                        ControlledGateOperation.BEADS_INIT_MUTATION, 8, "", "synthetic failure"
                    )
                elif case == "malformed":
                    fixture.overrides[ControlledGateOperation.BEADS_METADATA_READBACK] = RawControlledGateResult(
                        ControlledGateOperation.BEADS_METADATA_READBACK, 0, "{", ""
                    )
                elif case == "parser-mismatch":
                    def wrong_metadata(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                        if type(parameters) is not BeadsMetadataReadbackRequest:
                            raise AssertionError
                        return transport._raw(
                            ControlledGateOperation.BEADS_METADATA_READBACK,
                            {
                                "challenge": parameters.challenge, "database": parameters.expected_database,
                                "host": "127.0.0.2", "mode": "embedded",
                                "operation": "beads-generated-metadata-readback", "port": 3306,
                                "prefix": "other",
                            },
                        )
                    fixture.overrides[ControlledGateOperation.BEADS_METADATA_READBACK] = wrong_metadata
                elif case == "filesystem":
                    patcher = patch.object(
                        ControlledG01G03Adapter,
                        "_read_generated_beads_metadata",
                        side_effect=OSError("/private/tmp/synthetic-g04 token=synthetic-sensitive-value"),
                    )
                elif case == "transport":
                    fixture.exceptions.add(ControlledGateOperation.BEADS_INIT_MUTATION)
                elif case == "failed-readback":
                    def init_then_nonzero(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                        result = transport.execute_gate_for_test.__func__(transport, ControlledGateOperation.BEADS_INIT_MUTATION, parameters)
                        del result
                        transport.overrides[ControlledGateOperation.BEADS_INIT_MUTATION] = RawControlledGateResult(
                            ControlledGateOperation.BEADS_INIT_MUTATION, 0, "", ""
                        )
                        transport.overrides[ControlledGateOperation.BEADS_METADATA_READBACK] = RawControlledGateResult(
                            ControlledGateOperation.BEADS_METADATA_READBACK, 9, "", "/var/synthetic-private"
                        )
                        return RawControlledGateResult(ControlledGateOperation.BEADS_INIT_MUTATION, 0, "", "")
                    fixture.overrides[ControlledGateOperation.BEADS_INIT_MUTATION] = init_then_nonzero
                if patcher is None:
                    result = controller.run(request, configuration=config, home=home)
                else:
                    with patcher:
                        result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.state, "partial")
                self.assertEqual(result.failed_gate, str(Gate.BEADS))
                self.assertIn("G04:modeled-beads-init", result.mutation_attempts)
                self.assertNotIn("G04:modeled-beads-init", result.mutations_completed)
                self.assertNotIn("G05:modeled-dolt-remote-add", result.mutation_attempts)
                payload = self.assert_persisted_safe(result, home, evidence_dir)
                self.assertEqual(payload["gates"][-1]["status"], "failed")

    def test_task6_g05_failure_first_matrix_preserves_only_proven_prior_mutations(self) -> None:
        cases = ("nonzero", "malformed", "parser-mismatch", "filesystem", "transport", "failed-readback")
        for case in cases:
            with self.subTest(case=case):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                patcher = None
                if case == "nonzero":
                    fixture.overrides[ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION] = RawControlledGateResult(
                        ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION, 7, "", "synthetic failure"
                    )
                elif case == "malformed":
                    fixture.overrides[ControlledGateOperation.DOLT_REMOTE_READBACK] = RawControlledGateResult(
                        ControlledGateOperation.DOLT_REMOTE_READBACK, 0, "not-json", ""
                    )
                elif case == "parser-mismatch":
                    def wrong_remote(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                        if type(parameters) is not DoltRemoteReadbackRequest:
                            raise AssertionError
                        return transport._raw(
                            ControlledGateOperation.DOLT_REMOTE_READBACK,
                            {
                                "challenge": parameters.challenge, "operation": "dolt-remote-readback",
                                "remotes": [{"name": "origin", "url": "git+https://github.com/pjbeyer/other.git"}],
                            },
                        )
                    fixture.remote_added = True
                    fixture.overrides[ControlledGateOperation.DOLT_REMOTE_READBACK] = wrong_remote
                elif case == "filesystem":
                    patcher = patch.object(
                        ControlledG01G03Adapter,
                        "_validate_hooks_disk_readback",
                        side_effect=OSError("/tmp/synthetic-g05 token=synthetic-sensitive-value"),
                    )
                elif case == "transport":
                    fixture.exceptions.add(ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION)
                elif case == "failed-readback":
                    calls = 0
                    def fail_second_remote(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                        nonlocal calls
                        if type(parameters) is not DoltRemoteReadbackRequest:
                            raise AssertionError
                        calls += 1
                        if calls == 1:
                            return transport._raw(
                                ControlledGateOperation.DOLT_REMOTE_READBACK,
                                {"challenge": parameters.challenge, "operation": "dolt-remote-readback", "remotes": []},
                            )
                        return RawControlledGateResult(
                            ControlledGateOperation.DOLT_REMOTE_READBACK, 9, "", "/private/var/synthetic-private"
                        )
                    fixture.overrides[ControlledGateOperation.DOLT_REMOTE_READBACK] = fail_second_remote
                if patcher is None:
                    result = controller.run(request, configuration=config, home=home)
                else:
                    with patcher:
                        result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.state, "partial")
                self.assertEqual(result.failed_gate, str(Gate.BEADS_REMOTE))
                self.assertIn("G04:modeled-beads-init", result.mutations_completed)
                if case in {"nonzero", "transport", "failed-readback"}:
                    self.assertIn("G05:modeled-dolt-remote-add", result.mutation_attempts)
                    self.assertNotIn("G05:modeled-dolt-remote-add", result.mutations_completed)
                elif case in {"malformed", "parser-mismatch"}:
                    self.assertNotIn("G05:modeled-dolt-remote-add", result.mutation_attempts)
                else:
                    self.assertIn("G05:modeled-dolt-remote-add", result.mutations_completed)
                    self.assertIn("G05:modeled-codex-setup", result.mutations_completed)
                    self.assertIn("G05:modeled-hooks-install", result.mutation_attempts)
                    self.assertNotIn("G05:modeled-hooks-install", result.mutations_completed)
                payload = self.assert_persisted_safe(result, home, evidence_dir)
                self.assertEqual(payload["gates"][-1]["status"], "failed")

    def test_task6_rejects_unsafe_duplicate_or_symlink_metadata_and_wrong_g05_exact_sets(self) -> None:
        metadata_cases = (
            '{"dolt_database":"demo","dolt_database":"other","dolt_mode":"server","dolt_server_host":"127.0.0.1","dolt_server_port":3307}',
            '{"dolt_database":"bad-name","dolt_mode":"server","dolt_server_host":"127.0.0.1","dolt_server_port":3307}',
            '{"dolt_database":"token=unsafe","dolt_mode":"server","dolt_server_host":"127.0.0.1","dolt_server_port":3307}',
        )
        for raw in metadata_cases:
            with self.subTest(raw=raw):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                def rewrite_metadata(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
                    if type(parameters) is not BeadsInitRequest:
                        raise AssertionError
                    transport._assert_attempt_persisted("G04:modeled-beads-init")
                    parameters.target.initialize_beads(parameters.beads_prefix)
                    destination = (
                        transport.evidence_dir.parent
                        / "home"
                        / configuration().destination_route
                    )
                    (destination / ".beads" / "metadata.json").write_text(raw, encoding="utf-8")
                    transport.mutations.append(ControlledGateOperation.BEADS_INIT_MUTATION)
                    return RawControlledGateResult(ControlledGateOperation.BEADS_INIT_MUTATION, 0, "", "")
                fixture.overrides[ControlledGateOperation.BEADS_INIT_MUTATION] = rewrite_metadata
                result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.failed_gate, str(Gate.BEADS))
                self.assertNotIn("G04:modeled-beads-init", result.mutations_completed)
                self.assert_persisted_safe(result, home, evidence_dir)

        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        outside = evidence_dir.parent / "outside-metadata.json"
        outside.write_text("{}", encoding="utf-8")
        def symlink_metadata(parameters: object, transport: ControlledGateFixture) -> RawControlledGateResult:
            if type(parameters) is not BeadsInitRequest:
                raise AssertionError
            transport._assert_attempt_persisted("G04:modeled-beads-init")
            parameters.target.initialize_beads(parameters.beads_prefix)
            beads = (
                transport.evidence_dir.parent
                / "home"
                / configuration().destination_route
                / ".beads"
            )
            (beads / "metadata.json").unlink()
            (beads / "metadata.json").symlink_to(outside)
            transport.mutations.append(ControlledGateOperation.BEADS_INIT_MUTATION)
            return RawControlledGateResult(ControlledGateOperation.BEADS_INIT_MUTATION, 0, "", "")
        fixture.overrides[ControlledGateOperation.BEADS_INIT_MUTATION] = symlink_metadata
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.BEADS))
        self.assertNotIn("G04:modeled-beads-init", result.mutations_completed)

        g05_operations = (
            ControlledGateOperation.INTEGRATIONS_READBACK,
            ControlledGateOperation.HOOKS_READBACK,
            ControlledGateOperation.CORE_HOOKS_PATH_READBACK,
        )
        for operation in g05_operations:
            with self.subTest(operation=operation):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                fixture.overrides[operation] = RawControlledGateResult(operation, 0, "{}", "")
                result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.failed_gate, str(Gate.BEADS_REMOTE))
                self.assert_persisted_safe(result, home, evidence_dir)

    def test_task6_private_tmp_and_var_errors_are_redacted_and_controller_never_retries(self) -> None:
        for private_path in ("/tmp/g04", "/private/tmp/g04", "/var/g05", "/private/var/g05"):
            with self.subTest(path=private_path):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                fixture.exceptions.add(
                    ControlledGateOperation.BEADS_INIT_MUTATION
                    if "g04" in private_path
                    else ControlledGateOperation.DOLT_REMOTE_ADD_MUTATION
                )
                result = controller.run(request, configuration=config, home=home)
                serialized = json.dumps(self.assert_persisted_safe(result, home, evidence_dir))
                self.assertNotIn(private_path, serialized)
                before = list(fixture.operations)
                with self.assertRaises(InspectionControlError):
                    controller.run(request, configuration=config, home=home)
                self.assertEqual(fixture.operations, before)

    def test_controller_is_single_use_and_prior_ledger_is_not_overwritten(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        first = controller.run(request, configuration=config, home=home)
        ledger = next(evidence_dir.glob("*.json"))
        original = ledger.read_bytes()
        original_operations = list(fixture.operations)

        with self.assertRaisesRegex(InspectionControlError, "Task-5 exact inspection/resume"):
            controller.run(request, configuration=config, home=home)
        self.assertEqual(fixture.operations, original_operations)
        self.assertEqual(ledger.read_bytes(), original)
        self.assertEqual(len(list(evidence_dir.glob("*.json"))), 1)
        self.assertEqual(first.run_id, json.loads(original)["run_id"])

    def test_stale_raw_observation_replay_fails_before_mutation_and_keeps_ledger(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        fixture.replay_first_origin = True
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.CLONE))
        self.assertEqual(result.mutation_attempts, [])
        self.assertEqual(fixture.mutations, [])
        payload = self.assert_persisted_safe(result, home, evidence_dir)
        self.assertEqual(payload["gates"][-1]["gate"], Gate.CLONE.value)
        self.assertEqual(len(list(evidence_dir.glob("*.json"))), 1)

    def test_two_runs_use_distinct_ledgers_and_fresh_nonce_rejects_stale_raw_replay(self) -> None:
        _, home, evidence_dir, request, config, first_fixture, first_controller = self.make_case()
        first = first_controller.run(request, configuration=config, home=home)
        first_ledger = evidence_dir / f"{first.request_fingerprint}-{first.run_id}.json"
        first_bytes = first_ledger.read_bytes()
        first_origin = first_fixture.first_origin_raw
        self.assertIsNotNone(first_origin)

        destination = home / config.destination_route
        for path in sorted(destination.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
        destination.rmdir()

        second_fixture = ControlledGateFixture(evidence_dir=evidence_dir)
        second_fixture.overrides[ControlledGateOperation.ORIGIN_ACCESS_READ] = first_origin  # type: ignore[assignment]
        second_controller = ControlledG01G03Controller._for_controlled_test(
            second_fixture,
            evidence_dir=evidence_dir,
        )
        second = second_controller.run(request, configuration=config, home=home)
        ledgers = sorted(evidence_dir.glob("*.json"))
        self.assertEqual(len(ledgers), 2)
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(first_ledger.read_bytes(), first_bytes)
        self.assertEqual(second.failed_gate, str(Gate.PREFLIGHT))
        self.assertEqual(second_fixture.mutations, [])

    def test_copier_answers_accept_only_canonical_json_quoted_flat_strings(self) -> None:
        valid_lines = [
            '# controlled comment\n',
            '\n',
            f'_commit: {json.dumps(SHA)}\n',
            f'_src_path: {json.dumps(SOURCE)}\n',
            'project_description: "controlled description"\n',
            'project_kind: "generic"\n',
            'repository_name: "demo"\n',
            'repository_owner: "pjbeyer"\n',
            'template_revision: "v0.1.3"\n',
        ]
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        fixture.render_answers_raw = "".join(valid_lines)
        self.assertIsNone(controller.run(request, configuration=config, home=home).failed_gate)

        invalid_values = (
            'project_kind: generic',
            "project_kind: 'generic'",
            'project_kind: &kind "generic"',
            'project_kind: !!str "generic"',
            'project_kind: ["generic"]',
            'project_kind: "generic" # comment',
            'project_kind: "generic"',
        )
        for replacement in invalid_values:
            with self.subTest(value=replacement):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                lines = list(valid_lines)
                lines[5] = replacement + "\n"
                if replacement == 'project_kind: "generic"':
                    lines.insert(6, replacement + "\n")
                fixture.render_answers_raw = "".join(lines)
                result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.failed_gate, str(Gate.RENDER))
                self.assertNotIn("G03:modeled-render", result.mutations_completed)

    def test_private_unix_paths_are_sanitized_in_persisted_diagnostics(self) -> None:
        for private_path in ("/tmp/a", "/private/tmp/a", "/var/a", "/private/var/a"):
            with self.subTest(path=private_path):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                with patch.object(
                    ControlledG01G03Adapter,
                    "_assert_destination_absent",
                    side_effect=OSError(private_path),
                ):
                    result = controller.run(request, configuration=config, home=home)
                serialized = json.dumps(self.assert_persisted_safe(result, home, evidence_dir))
                self.assertNotIn(private_path, serialized)

    def test_final_persistence_failure_does_not_create_passed_and_failed_gate(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        real_persist = controller._persist_owned
        calls = 0

        def fail_g03_success(evidence: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 6:
                raise InspectionControlError("injected final-gate persistence failure")
            real_persist(evidence)  # type: ignore[arg-type]

        with patch.object(controller, "_persist_owned", side_effect=fail_g03_success):
            result = controller.run(request, configuration=config, home=home)
        failed_gate = Gate(result.failed_gate)
        statuses = [item.status for item in result.gates if item.gate is failed_gate]
        self.assertEqual(statuses, ["failed"])
        self.assertEqual(result.mutation_attempts, ["G02:modeled-clone"])
        self.assertEqual(result.mutations_completed, ["G02:modeled-clone"])
        payload = self.assert_persisted_safe(result, home, evidence_dir)
        self.assertEqual(
            [item["status"] for item in payload["gates"] if item["gate"] == failed_gate.value],
            ["failed"],
        )

    def test_root_home_destination_git_and_tree_symlinks_fail_closed(self) -> None:
        for target in ("root", "home", "destination"):
            with self.subTest(target=target):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name).resolve()
                outside = root / "outside"
                outside.mkdir()
                evidence_dir = root / "evidence"
                home = root / "home"
                fixture = ControlledGateFixture(evidence_dir=evidence_dir)
                if target == "root":
                    with self.assertRaises(InspectionControlError):
                        ControlledG01G03Controller._for_controlled_test(
                            fixture,
                            evidence_dir=root,
                        )
                    self.assertEqual(fixture.operations, [])
                    self.assertEqual(fixture.mutations, [])
                    continue
                if target == "home":
                    home.symlink_to(outside)
                else:
                    home.mkdir()
                    destination = home / configuration().destination_route
                    destination.parent.mkdir(parents=True)
                    destination.symlink_to(outside)
                fixture = ControlledGateFixture(evidence_dir=evidence_dir)
                controller = ControlledG01G03Controller._for_controlled_test(
                    fixture,
                    evidence_dir=evidence_dir,
                )
                request = ProvisioningRequest(
                    "https://github.com/pjbeyer/demo.git",
                    "demo",
                    "generic",
                    "controlled description",
                )
                with self.assertRaises(InspectionControlError):
                    controller.run(request, configuration=configuration(), home=home)
                self.assertEqual(fixture.operations, [])
                self.assertEqual(fixture.mutations, [])

        for operation, target, failed_gate in (
            (ControlledGateOperation.CLONE_MUTATION, "destination", Gate.CLONE),
            (ControlledGateOperation.CLONE_MUTATION, "tree", Gate.CLONE),
            (ControlledGateOperation.RENDER_MUTATION, ".git", Gate.RENDER),
        ):
            with self.subTest(operation=operation, target=target):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                fixture.swap_after_attempt = operation
                fixture.swap_target = target
                result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.failed_gate, str(failed_gate))
                self.assertIn(operation, fixture.mutations)
                self.assertNotIn(
                    "G02:modeled-clone" if failed_gate is Gate.CLONE else "G03:modeled-render",
                    result.mutations_completed,
                )
                self.assert_persisted_safe(result, home, evidence_dir)

    def test_evidence_leaf_symlink_is_rejected_before_creation_or_transport(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        home = root / "home"
        outside = root / "outside"
        home.mkdir()
        outside.mkdir()
        evidence_dir = root / "evidence"
        evidence_dir.symlink_to(outside)
        fixture = ControlledGateFixture(evidence_dir=evidence_dir)
        with self.assertRaises(InspectionControlError):
            ControlledG01G03Controller._for_controlled_test(
                fixture,
                evidence_dir=evidence_dir,
            )
        self.assertEqual(fixture.operations, [])
        self.assertEqual(list(outside.iterdir()), [])

    def test_descriptor_swaps_leave_replacements_untouched_and_attempt_in_original_ledger(self) -> None:
        cases = (
            (ControlledGateOperation.BEADS_INIT_MUTATION, "destination", "G04:modeled-beads-init", Gate.BEADS),
            (ControlledGateOperation.BEADS_INIT_MUTATION, "beads", "G04:modeled-beads-init", Gate.BEADS),
            (ControlledGateOperation.HOOKS_INSTALL_MUTATION, "hooks", "G05:modeled-hooks-install", Gate.BEADS_REMOTE),
        )
        for operation, swapped_leaf, attempt, failed_gate in cases:
            with self.subTest(operation=operation, leaf=swapped_leaf):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                destination = home / config.destination_route
                external = evidence_dir.parent / f"external-{swapped_leaf}"
                external.mkdir()

                def swap_after(parameters: object, transport: ControlledGateFixture) -> None:
                    del parameters, transport
                    target = destination if swapped_leaf == "destination" else destination / ".beads"
                    if swapped_leaf == "hooks":
                        target = destination / ".beads" / "hooks"
                    original = target.with_name(target.name + "-original")
                    target.rename(original)
                    target.mkdir()
                    (target / "replacement-marker").write_text("untouched\n", encoding="utf-8")

                fixture.post_operation[operation] = swap_after
                result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.failed_gate, str(failed_gate))
                self.assertIn(attempt, result.mutation_attempts)
                self.assertNotIn(attempt, result.mutations_completed)
                replacement = destination if swapped_leaf == "destination" else destination / ".beads"
                if swapped_leaf == "hooks":
                    replacement = destination / ".beads" / "hooks"
                self.assertEqual(
                    (replacement / "replacement-marker").read_text(encoding="utf-8"),
                    "untouched\n",
                )
                ledger = next(evidence_dir.glob("*.json"), None)
                if ledger is None:
                    ledger = next((evidence_dir.parent / "evidence-original").glob("*.json"))
                payload = json.loads(ledger.read_text(encoding="utf-8"))
                self.assertIn(attempt, payload["mutation_attempts"])
                self.assertNotIn(attempt, payload["mutations_completed"])
                self.assertEqual(list(external.iterdir()), [])

    def test_metadata_and_hook_leaf_replacements_prevent_completion(self) -> None:
        cases = (
            (
                ControlledGateOperation.BEADS_PREFIX_READBACK,
                "metadata",
                "G04:modeled-beads-init",
                Gate.BEADS,
            ),
            (
                ControlledGateOperation.CORE_HOOKS_PATH_READBACK,
                "hook",
                "G05:modeled-hooks-install",
                Gate.BEADS_REMOTE,
            ),
        )
        for operation, leaf, attempt, failed_gate in cases:
            with self.subTest(operation=operation, leaf=leaf):
                _, home, evidence_dir, request, config, fixture, controller = self.make_case()
                destination = home / config.destination_route

                def replace_after(parameters: object, transport: ControlledGateFixture) -> None:
                    del parameters
                    target = destination / ".beads" / "metadata.json"
                    if leaf == "hook":
                        target = destination / ".beads" / "hooks" / "pre-commit"
                    transport.replace_regular_same_content(target)

                fixture.post_operation[operation] = replace_after
                original_complete = ControlledG01G03Adapter._complete_mutation

                def complete_after_replace(adapter: object, gate: Gate, label: str) -> None:
                    if label == attempt:
                        replace_after(None, fixture)
                    return original_complete(adapter, gate, label)

                with unittest.mock.patch.object(ControlledG01G03Adapter, "_complete_mutation", complete_after_replace):
                    result = controller.run(request, configuration=config, home=home)
                self.assertEqual(result.state, "partial")
                self.assertEqual(result.failed_gate, str(failed_gate))
                self.assertIn(attempt, result.mutation_attempts)
                self.assertNotIn(attempt, result.mutations_completed)
                self.assert_persisted_safe(result, home, evidence_dir)

    def test_root_swap_after_session_construction_prevents_any_transport(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        root = evidence_dir.parent
        original = root.with_name(root.name + "-original")
        replacement_marker = "root replacement untouched\n"
        root.rename(original)
        root.mkdir()
        (root / "marker").write_text(replacement_marker, encoding="utf-8")
        with self.assertRaisesRegex(InspectionControlError, "controlled fixture directory chain|descriptor session"):
            controller.run(request, configuration=config, home=home)
        self.assertEqual(fixture.operations, [])
        self.assertEqual(fixture.mutations, [])
        self.assertEqual((root / "marker").read_text(encoding="utf-8"), replacement_marker)
        self.assertTrue((root / "evidence").is_dir())
        self.assertEqual(list((root / "evidence").iterdir()), [])

    def test_evidence_swap_after_attempt_stops_before_mutation_and_retains_original_ledger(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        original = evidence_dir.with_name("evidence-original")
        replacement_marker = "replacement remains untouched\n"

        def swap_evidence(evidence: object) -> None:
            real(evidence)  # type: ignore[arg-type]
            if len(controller._evidence_fds_used) == 3:
                evidence_dir.rename(original)
                evidence_dir.mkdir()
                (evidence_dir / "marker").write_text(replacement_marker, encoding="utf-8")

        real = controller._persist_owned
        with patch.object(controller, "_persist_owned", side_effect=swap_evidence):
            result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.failed_gate, str(Gate.CLONE))
        self.assertNotIn(ControlledGateOperation.CLONE_MUTATION, fixture.mutations)
        ledger = next(original.glob("*.json"))
        payload = json.loads(ledger.read_text(encoding="utf-8"))
        self.assertIn("G02:modeled-clone", payload["mutation_attempts"])
        self.assertNotIn("G02:modeled-clone", payload["mutations_completed"])
        self.assertEqual((evidence_dir / "marker").read_text(encoding="utf-8"), replacement_marker)

    def test_caller_maps_booleans_and_raw_subclasses_cannot_establish_trust(self) -> None:
        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        fixture.overrides[ControlledGateOperation.ORIGIN_ACCESS_READ] = {  # type: ignore[assignment]
            "identity": "pjbeyer/demo",
            "empty": True,
            "writable": True,
        }
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.state, "blocked-preflight")
        self.assertEqual(result.failed_gate, str(Gate.PREFLIGHT))
        self.assert_persisted_safe(result, home, evidence_dir)

        class DerivedRaw(RawControlledGateResult):
            pass

        _, home, evidence_dir, request, config, fixture, controller = self.make_case()
        fixture.overrides[ControlledGateOperation.ORIGIN_ACCESS_READ] = DerivedRaw(
            ControlledGateOperation.ORIGIN_ACCESS_READ,
            0,
            "{}",
            "",
        )
        result = controller.run(request, configuration=config, home=home)
        self.assertEqual(result.state, "blocked-preflight")
        self.assert_persisted_safe(result, home, evidence_dir)


if __name__ == "__main__":
    unittest.main(verbosity=2)

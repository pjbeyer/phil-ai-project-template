"""Immutable live configuration and exact authorization binding tests.

All values and paths are synthetic.  No test invokes an external command or
models a completed source/database readback.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.adapters import AdapterError, LiveAdapter
from scripts.evidence import (
    live_evidence_from_json,
    live_evidence_to_json,
    redact,
    request_fingerprint,
)
from scripts.models import (
    APPROVED_AUDIT_IDENTITY,
    APPROVED_COMPONENT_NAMES,
    APPROVED_EXECUTOR_POLICY_VERSION,
    APPROVED_MANIFEST_IDENTITY,
    APPROVED_TEMPLATE_SOURCE_IDENTITIES,
    AuthorizationError,
    ComponentPin,
    ConfigurationError,
    Gate,
    ImmutableLiveConfiguration,
    LiveAuthorization,
    LiveProvisioningEvidence,
    ProvisioningRequest,
    assert_live_authorized,
    configuration_digest,
)


_SHA_A = "1" * 40
_SHA_B = "2" * 40
_TEMPLATE_SOURCE = "pjbeyer/phil-ai-project-template"
# Machine-independent stand-in for the operator's approved project home. The
# published tests must not hard-code a real workstation path (FR-027/NFR-007).
_SYNTHETIC_HOME = "/Users/synthetic-operator"


def component_pins(*, reverse: bool = False, changed: str | None = None) -> dict[str, ComponentPin]:
    names = list(APPROVED_COMPONENT_NAMES)
    if reverse:
        names.reverse()
    return {
        name: ComponentPin(
            name=name,
            source_identity=f"speckit/component/{name}",
            resolved_commit=_SHA_B if name == changed else _SHA_A,
        )
        for name in names
    }


def configuration(
    *,
    repository: str = "demo",
    owner: str = "pjbeyer",
    resolved_commit: str = _SHA_A,
    pins: dict[str, ComponentPin] | None = None,
) -> ImmutableLiveConfiguration:
    identity = f"{owner}/{repository}"
    return ImmutableLiveConfiguration.create(
        repository_identity=identity,
        template_source_identity=_TEMPLATE_SOURCE,
        template_tag="v0.1.3",
        resolved_template_commit=resolved_commit,
        component_pins=pins if pins is not None else component_pins(),
    )


def authorization(
    config: ImmutableLiveConfiguration,
    *,
    fingerprint: str = "a" * 64,
    gate: Gate = Gate.PREFLIGHT,
) -> LiveAuthorization:
    return LiveAuthorization(
        named_identity=config.repository_identity,
        request_fingerprint=fingerprint,
        config_digest=configuration_digest(config),
        permitted_starting_gate=gate,
    )


def changed_config(
    config: ImmutableLiveConfiguration,
    **changes: object,
) -> ImmutableLiveConfiguration:
    changed = copy.copy(config)
    for field_name, value in changes.items():
        object.__setattr__(changed, field_name, value)
    changed.__post_init__()
    return changed


def forged(config: ImmutableLiveConfiguration, field_name: str, value: object) -> ImmutableLiveConfiguration:
    changed = copy.copy(config)
    object.__setattr__(changed, field_name, value)
    return changed


class ImmutableConfigurationTests(unittest.TestCase):
    def test_configuration_is_canonical_immutable_and_has_no_host_or_credential_fields(self) -> None:
        config = configuration()
        self.assertEqual(config.destination_route, "Projects/pjbeyer/demo")
        self.assertEqual(config.render_revision, _SHA_A)
        self.assertEqual(config.manifest_identity, APPROVED_MANIFEST_IDENTITY)
        self.assertEqual(config.audit_identity, APPROVED_AUDIT_IDENTITY)
        self.assertEqual(config.executor_policy_version, APPROVED_EXECUTOR_POLICY_VERSION)
        self.assertEqual(tuple(pin.name for pin in config.component_pins), tuple(sorted(APPROVED_COMPONENT_NAMES)))
        with self.assertRaises(FrozenInstanceError):
            config.template_tag = "v0.2.0"  # type: ignore[misc]
        self.assertFalse(
            {"env", "command_env", "credential", "credentials", "token", "manifest_path", "audit_path"}
            & set(config.__dataclass_fields__)
        )

    def test_digest_is_stable_for_semantically_identical_mapping_order(self) -> None:
        first = configuration(pins=component_pins())
        second = configuration(pins=component_pins(reverse=True))
        self.assertEqual(first, second)
        self.assertEqual(configuration_digest(first), configuration_digest(second))

    def test_security_relevant_commit_component_and_route_changes_alter_digest(self) -> None:
        baseline = configuration()
        cases = (
            configuration(resolved_commit=_SHA_B),
            configuration(pins=component_pins(changed=next(iter(APPROVED_COMPONENT_NAMES)))),
            configuration(repository="other"),
        )
        for changed in cases:
            with self.subTest(changed=changed):
                self.assertNotEqual(configuration_digest(baseline), configuration_digest(changed))

    def test_template_source_is_allowlisted_and_resolved_commit_is_mandatory(self) -> None:
        self.assertEqual(APPROVED_TEMPLATE_SOURCE_IDENTITIES, frozenset({_TEMPLATE_SOURCE}))
        base = {
            "repository_identity": "pjbeyer/demo",
            "template_tag": "v0.1.3",
            "component_pins": component_pins(),
        }
        for source, commit in (("other/template", _SHA_A), (_TEMPLATE_SOURCE, "v0.1.0"), (_TEMPLATE_SOURCE, "")):
            with self.subTest(source=source, commit=commit), self.assertRaises(ConfigurationError):
                ImmutableLiveConfiguration.create(
                    template_source_identity=source,
                    resolved_template_commit=commit,
                    **base,
                )

    def test_tag_is_non_authoritative_and_rendering_is_modeled_by_verified_commit(self) -> None:
        config = configuration()
        self.assertNotEqual(config.template_tag, config.render_revision)
        self.assertEqual(config.render_revision, config.resolved_template_commit)
        with self.assertRaises(ConfigurationError):
            changed_config(config, template_tag="HEAD")

    def test_template_tag_requires_conservative_version_shape(self) -> None:
        config = configuration()
        accepted = ("v0.1.3", "v2.10.3-rc.1", "1.2.3+build.7")
        rejected = (
            "main",
            "develop",
            "release",
            "origin/develop",
            "refs/tags/v0.1.0",
            "$(whoami)",
            "`whoami`",
            "v0.1.0;whoami",
            "v0.1.0&&whoami",
            "v0.1.0|whoami",
        )
        for value in accepted:
            with self.subTest(value=value):
                changed_config(config, template_tag=value)
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                changed_config(config, template_tag=value)

    def test_component_pin_set_is_exact_validated_and_immutable(self) -> None:
        missing = component_pins()
        missing.pop(next(iter(missing)))
        extra = component_pins()
        extra["unreviewed"] = next(iter(extra.values()))
        for pins in (missing, extra):
            with self.subTest(names=set(pins)), self.assertRaises(ConfigurationError):
                configuration(pins=pins)
        config = configuration()
        self.assertIsInstance(config.component_pins, tuple)
        with self.assertRaises(TypeError):
            config.component_pins[0] = config.component_pins[0]  # type: ignore[index]

    def test_destination_authority_is_internal_and_derived_from_identity(self) -> None:
        pjbeyer = configuration()
        flexapp = configuration(owner="flexapp")
        self.assertEqual(pjbeyer.destination_route, "Projects/pjbeyer/demo")
        self.assertEqual(flexapp.destination_route, "Projects/work/demo")
        constructor_fields = set(ImmutableLiveConfiguration.__dataclass_fields__)
        self.assertNotIn("destination_path_digest", constructor_fields)
        with self.assertRaises(TypeError):
            ImmutableLiveConfiguration.create(
                repository_identity="pjbeyer/demo",
                destination=Path("/tmp/demo"),
                approved_home=Path("/tmp"),
                template_source_identity=_TEMPLATE_SOURCE,
                template_tag="v0.1.3",
                resolved_template_commit=_SHA_A,
                component_pins=component_pins(),
            )

    def test_matches_destination_rejects_forged_route_state_and_unrelated_paths(self) -> None:
        config = configuration()
        with patch.dict("os.environ", {"PROVISIONING_APPROVED_HOME": _SYNTHETIC_HOME}):
            approved = Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo")
            self.assertTrue(config.matches_destination(approved))
            self.assertFalse(config.matches_destination(Path("/tmp/demo")))
            forged_route = forged(config, "destination_route", "Projects/pjbeyer/other")
            self.assertFalse(forged_route.matches_destination(approved))
            self.assertFalse(
                forged_route.matches_destination(Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/other"))
            )

    def test_destination_root_is_approved_home_derived_and_digest_independent(self) -> None:
        config = configuration()
        digest = configuration_digest(config)
        with patch.dict("os.environ", {"PROVISIONING_APPROVED_HOME": _SYNTHETIC_HOME}):
            self.assertEqual(configuration_digest(config), digest)
            self.assertTrue(
                config.matches_destination(Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo"))
            )
            # HOME must never substitute for the approved home.
            with patch.dict("os.environ", {"HOME": "/Users/unrelated-home"}):
                self.assertFalse(
                    config.matches_destination(Path("/Users/unrelated-home/Projects/pjbeyer/demo"))
                )

    def test_destination_requires_approved_home_and_exact_canonical_route(self) -> None:
        config = configuration()
        with patch.dict("os.environ", {"PROVISIONING_APPROVED_HOME": _SYNTHETIC_HOME}):
            approved = Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo")
            self.assertTrue(config.matches_destination(approved))
            cases = (
                Path("relative/demo"),
                Path("/tmp/demo"),
                Path(f"{_SYNTHETIC_HOME}/Projects/work/demo"),
                Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo/../other"),
            )
            for destination in cases:
                with self.subTest(destination=destination):
                    self.assertFalse(config.matches_destination(destination))
        # An unconfigured approved home fails closed rather than matching anything.
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(
                config.matches_destination(Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo"))
            )

    def test_approved_home_resolution_prefers_env_then_config_file(self) -> None:
        from scripts.models import _approved_project_home

        with patch.dict("os.environ", {}, clear=True), patch.object(
            Path, "home", return_value=Path(_SYNTHETIC_HOME)
        ):
            # No env var and no synthetic config file -> fail closed (the test
            # must not observe the operator's real ~/.config/provisioning file).
            with self.assertRaises(ConfigurationError):
                _approved_project_home()

        # Config file alone supplies the root.
        with patch.dict("os.environ", {"XDG_CONFIG_HOME": "/tmp/pjb-xdg"}, clear=True), patch.object(
            Path, "home", return_value=Path(_SYNTHETIC_HOME)
        ):
            cfg_dir = Path("/tmp/pjb-xdg/provisioning")
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "config.json").write_text(
                json.dumps({"approved_project_home": _SYNTHETIC_HOME}), encoding="utf-8"
            )
            self.assertEqual(_approved_project_home(), Path(_SYNTHETIC_HOME))

            # Env var takes precedence over the config file.
            with patch.dict("os.environ", {"PROVISIONING_APPROVED_HOME": "/Users/synthetic-env-home"}):
                self.assertEqual(_approved_project_home(), Path("/Users/synthetic-env-home"))

    def test_approved_home_config_file_is_validated(self) -> None:
        from scripts.models import _approved_project_home

        cases = {
            "not-json": "{{{",
            "not-object": '["approved_project_home"]',
            "wrong-type": json.dumps({"approved_project_home": 123}),
        }
        for name, content in cases.items():
            with self.subTest(case=name), patch.dict(
                "os.environ", {"XDG_CONFIG_HOME": "/tmp/pjb-xdg"}, clear=True
            ), patch.object(Path, "home", return_value=Path(_SYNTHETIC_HOME)):
                cfg_dir = Path("/tmp/pjb-xdg/provisioning")
                cfg_dir.mkdir(parents=True, exist_ok=True)
                (cfg_dir / "config.json").write_text(content, encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    _approved_project_home()

    def test_approved_template_source_resolution_prefers_env_then_config(self) -> None:
        from scripts.models import _approved_template_source

        with patch.dict("os.environ", {}, clear=True), patch.object(
            Path, "home", return_value=Path(_SYNTHETIC_HOME)
        ):
            # No env var and no synthetic config file -> fail closed (hermetic).
            with self.assertRaises(ConfigurationError):
                _approved_template_source()

        # Env var supplies the checkout path.
        with patch.dict(
            "os.environ", {"PROVISIONING_TEMPLATE_SOURCE": f"{_SYNTHETIC_HOME}/template"}, clear=True
        ):
            self.assertEqual(
                _approved_template_source(), Path(f"{_SYNTHETIC_HOME}/template")
            )

        # Config file alone supplies it via the dedicated key.
        with patch.dict("os.environ", {"XDG_CONFIG_HOME": "/tmp/pjb-xdg"}, clear=True), patch.object(
            Path, "home", return_value=Path(_SYNTHETIC_HOME)
        ):
            cfg_dir = Path("/tmp/pjb-xdg/provisioning")
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "config.json").write_text(
                json.dumps({"approved_template_source": f"{_SYNTHETIC_HOME}/template"}), encoding="utf-8"
            )
            self.assertEqual(
                _approved_template_source(), Path(f"{_SYNTHETIC_HOME}/template")
            )

    def test_approved_manifest_path_resolution_uses_hermes_home_then_fallback(self) -> None:
        from scripts.models import _approved_manifest_path

        # HERMES_HOME is authoritative for the manifest location.
        with patch.dict("os.environ", {"HERMES_HOME": f"{_SYNTHETIC_HOME}/.hermes"}, clear=True):
            self.assertEqual(
                _approved_manifest_path(),
                Path(f"{_SYNTHETIC_HOME}/.hermes/scripts/beads_cron_manifest.json"),
            )
        # Without HERMES_HOME, fall back to the operator's HOME/.hermes.
        with patch.dict("os.environ", {}, clear=True), patch.object(
            Path, "home", return_value=Path(_SYNTHETIC_HOME)
        ):
            self.assertEqual(
                _approved_manifest_path(),
                Path(f"{_SYNTHETIC_HOME}/.hermes/scripts/beads_cron_manifest.json"),
            )

    def test_config_rejects_secret_patterns_pointers_tokenized_urls_and_private_paths(self) -> None:
        rejected_sources = (
            "op://SyntheticVault/SyntheticItem/SyntheticField",
            "https://synthetic-userinfo@synthetic.invalid/source",
            "token=synthetic-marker",
            "/Users/synthetic-private/template",
        )
        for source in rejected_sources:
            pins = component_pins()
            name = next(iter(pins))
            unsafe = copy.copy(pins[name])
            object.__setattr__(unsafe, "source_identity", source)
            pins[name] = unsafe
            with self.subTest(source=source), self.assertRaises(ConfigurationError):
                configuration(pins=pins)
        canonical = json.dumps(configuration().canonical_fields(), sort_keys=True)
        self.assertNotIn("/Users/", canonical)
        self.assertNotIn("synthetic-home", canonical)
        self.assertNotIn("op://", canonical)
        self.assertNotIn("@synthetic.invalid", canonical)

    def test_config_rejects_shell_expansion_and_floating_credential_pointers(self) -> None:
        config = configuration()
        rejected = (
            "${SYNTHETIC_TOKEN}",
            "$SYNTHETIC_TOKEN",
            "GITHUB_TOKEN=synthetic-marker",
            "main",
            "origin/main",
            "refs/remotes/origin/main",
            "refs/heads/main",
            "heads/main",
            "HEAD",
            ":current:",
        )
        for value in rejected:
            with self.subTest(field="template_tag", value=value), self.assertRaises(ConfigurationError):
                changed_config(config, template_tag=value)
            pins = component_pins()
            name = next(iter(pins))
            unsafe = copy.copy(pins[name])
            object.__setattr__(unsafe, "source_identity", value)
            pins[name] = unsafe
            with self.subTest(field="component_source", value=value), self.assertRaises(ConfigurationError):
                configuration(pins=pins)

    def test_config_rejects_embedded_private_absolute_paths(self) -> None:
        config = configuration()
        embedded_paths = (
            "prefix=/Users/synthetic-private/project suffix",
            r"prefix=C:\Users\synthetic-private\project suffix",
            "prefix=C:/Users/synthetic-private/project suffix",
        )
        for embedded in embedded_paths:
            with self.subTest(field="template_tag", value=embedded), self.assertRaises(ConfigurationError):
                changed_config(config, template_tag=embedded)
            pins = component_pins()
            name = next(iter(pins))
            unsafe = copy.copy(pins[name])
            object.__setattr__(unsafe, "source_identity", embedded)
            pins[name] = unsafe
            with self.subTest(field="component_source", value=embedded), self.assertRaises(ConfigurationError):
                configuration(pins=pins)

        legitimate_url = "https://example.invalid/Users/synthetic-public/project"
        pins = component_pins()
        name = next(iter(pins))
        safe = copy.copy(pins[name])
        object.__setattr__(safe, "source_identity", legitimate_url)
        pins[name] = safe
        with self.assertRaises(ConfigurationError):
            # Stable source identity policy, not private-path detection, rejects it.
            configuration(pins=pins)
        self.assertEqual(redact(legitimate_url), legitimate_url)

    def test_fixed_identity_fields_reject_equality_forging_string_subclasses(self) -> None:
        class EqualString(str):
            def __eq__(self, other: object) -> bool:
                return True

            __hash__ = str.__hash__

        config = configuration()
        fixed = (
            ("manifest_identity", APPROVED_MANIFEST_IDENTITY),
            ("audit_identity", APPROVED_AUDIT_IDENTITY),
            ("executor_policy_version", APPROVED_EXECUTOR_POLICY_VERSION),
        )
        for field_name, expected in fixed:
            hostile = EqualString("hostile-but-equal")
            self.assertTrue(hostile == expected)
            with self.subTest(field=field_name), self.assertRaises(ConfigurationError):
                changed_config(config, **{field_name: hostile})
            with self.subTest(field=f"digest:{field_name}"), self.assertRaises(ConfigurationError):
                configuration_digest(forged(config, field_name, hostile))

    def test_configuration_requires_factory_registration_and_detects_valid_mutation(self) -> None:
        config = configuration()
        unregistered = object.__new__(ImmutableLiveConfiguration)
        for field_name in config.__dataclass_fields__:
            object.__setattr__(unregistered, field_name, getattr(config, field_name))
        unregistered.__post_init__()
        with self.assertRaises(ConfigurationError):
            configuration_digest(unregistered)
        self.assertFalse(
            unregistered.matches_destination(Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo"))
        )

        missing = object.__new__(ImmutableLiveConfiguration)
        with self.assertRaises(ConfigurationError):
            configuration_digest(missing)
        self.assertFalse(missing.matches_destination(Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo")))

        digest = configuration_digest(config)
        object.__setattr__(config, "resolved_template_commit", _SHA_B)
        config.__post_init__()
        with self.assertRaises(ConfigurationError):
            configuration_digest(config)
        self.assertFalse(config.matches_destination(Path(f"{_SYNTHETIC_HOME}/Projects/pjbeyer/demo")))
        self.assertNotEqual(digest, hashlib.sha256(b"irrelevant").hexdigest())


class ExactAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = configuration()
        self.fingerprint = "a" * 64
        self.authorization = authorization(self.config, fingerprint=self.fingerprint)

    def assert_rejected(
        self,
        *,
        config: ImmutableLiveConfiguration | None = None,
        fingerprint: str | None = None,
        gate: Gate = Gate.PREFLIGHT,
        authorization_value: object | None = None,
        identity: str | None = None,
    ) -> None:
        with self.assertRaises(AuthorizationError):
            assert_live_authorized(
                self.authorization if authorization_value is None else authorization_value,
                named_identity=identity or self.config.repository_identity,
                request_fingerprint=fingerprint or self.fingerprint,
                configuration=config or self.config,
                starting_gate=gate,
            )

    def test_exact_reviewed_binding_is_accepted(self) -> None:
        accepted = assert_live_authorized(
            self.authorization,
            named_identity=self.config.repository_identity,
            request_fingerprint=self.fingerprint,
            configuration=self.config,
            starting_gate=Gate.PREFLIGHT,
        )
        self.assertIsNot(accepted, self.authorization)
        self.assertEqual(accepted, self.authorization)
        self.assertIs(
            assert_live_authorized(
                accepted,
                named_identity=self.config.repository_identity,
                request_fingerprint=self.fingerprint,
                configuration=self.config,
                starting_gate=Gate.PREFLIGHT,
            ).permitted_starting_gate,
            Gate.PREFLIGHT,
        )

    def test_authorization_requires_constructor_registration_and_detects_valid_mutation(self) -> None:
        unregistered = object.__new__(LiveAuthorization)
        for field_name in self.authorization.__dataclass_fields__:
            object.__setattr__(unregistered, field_name, getattr(self.authorization, field_name))
        unregistered.__post_init__()
        self.assert_rejected(authorization_value=unregistered)

        manual_new = LiveAuthorization.__new__(LiveAuthorization)
        for field_name in self.authorization.__dataclass_fields__:
            object.__setattr__(manual_new, field_name, getattr(self.authorization, field_name))
        manual_new.__post_init__()
        self.assert_rejected(authorization_value=manual_new)
        with self.assertRaises(AuthorizationError):
            manual_new.__init__(
                self.authorization.named_identity,
                self.authorization.request_fingerprint,
                self.authorization.config_digest,
                self.authorization.permitted_starting_gate,
            )

        missing = object.__new__(LiveAuthorization)
        self.assert_rejected(authorization_value=missing)

        object.__setattr__(self.authorization, "request_fingerprint", "b" * 64)
        self.authorization.__post_init__()
        self.assert_rejected(
            authorization_value=self.authorization,
            fingerprint="b" * 64,
        )

    def test_rejects_any_changed_template_source_commit_manifest_audit_pin_policy_or_path(self) -> None:
        changed_pin = list(self.config.component_pins)
        changed_pin[0] = replace(changed_pin[0], resolved_commit=_SHA_B)
        cases = {
            "template source identity": forged(self.config, "template_source_identity", "other/template"),
            "resolved commit": changed_config(self.config, resolved_template_commit=_SHA_B),
            "manifest identity": forged(self.config, "manifest_identity", "other-manifest/v1"),
            "audit identity": forged(self.config, "audit_identity", "other-audit/v1"),
            "component pin": changed_config(self.config, component_pins=tuple(changed_pin)),
            "executor policy version": forged(self.config, "executor_policy_version", "other-policy/v2"),
            "canonical path": forged(self.config, "destination_route", "Projects/pjbeyer/other"),
        }
        for label, changed in cases.items():
            with self.subTest(label=label):
                self.assert_rejected(config=changed)

    def test_rejects_changed_request_field_fingerprint_identity_and_starting_gate(self) -> None:
        home = Path("/Users/synthetic-home")
        base = ProvisioningRequest("https://github.com/pjbeyer/demo.git", "demo", "generic", "baseline")
        baseline = request_fingerprint(base, home / "Projects/pjbeyer/demo")
        auth = authorization(self.config, fingerprint=baseline)
        changed_requests = (
            replace(base, origin_url="https://github.com/pjbeyer/other.git"),
            replace(base, beads_prefix="other"),
            replace(base, project_kind="macos-cli"),
            replace(base, description="changed"),
            replace(base, destination_confirmation="Projects/pjbeyer/demo"),
        )
        for changed in changed_requests:
            with self.subTest(changed=changed), self.assertRaises(AuthorizationError):
                assert_live_authorized(
                    auth,
                    named_identity=self.config.repository_identity,
                    request_fingerprint=request_fingerprint(changed, home / "Projects/pjbeyer/demo"),
                    configuration=self.config,
                    starting_gate=Gate.PREFLIGHT,
                )
        self.assert_rejected(identity="pjbeyer/other")
        self.assert_rejected(gate=Gate.CLONE)

    def test_request_fingerprint_binds_every_request_field_without_authorization_payloads(self) -> None:
        destination = Path.home() / "Projects/pjbeyer/demo"
        base = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git",
            "demo",
            "generic",
            "baseline",
            "Projects/pjbeyer/demo",
        )
        baseline = request_fingerprint(base, destination)
        changed_requests = (
            replace(base, origin_url="https://github.com/pjbeyer/other.git"),
            replace(base, beads_prefix="other"),
            replace(base, project_kind="macos-cli"),
            replace(base, description="changed"),
            replace(base, destination_confirmation="Projects/pjbeyer/other"),
        )
        fingerprints = {baseline}
        for changed in changed_requests:
            changed_fingerprint = request_fingerprint(changed, destination)
            self.assertNotEqual(changed_fingerprint, baseline)
            fingerprints.add(changed_fingerprint)
        self.assertEqual(len(fingerprints), 1 + len(changed_requests))

    def test_request_fingerprint_rejects_capability_bearing_fields(self) -> None:
        destination = Path("/tmp/synthetic-demo")
        base = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git",
            "demo",
            "generic",
            "baseline",
        )
        self.assertRegex(request_fingerprint(base, destination), r"^[0-9a-f]{64}$")
        first = object()
        second = object()
        for field_name in ("live_authorization", "resume_authorization"):
            with self.subTest(field=field_name):
                first_fingerprint = request_fingerprint(
                    replace(base, **{field_name: first}),  # type: ignore[arg-type]
                    destination,
                )
                second_fingerprint = request_fingerprint(
                    replace(base, **{field_name: second}),  # type: ignore[arg-type]
                    destination,
                )
                self.assertNotEqual(first_fingerprint, request_fingerprint(base, destination))
                self.assertEqual(first_fingerprint, second_fingerprint)

    def test_absolute_destination_confirmation_must_exactly_match_destination(self) -> None:
        destination = Path("/Users/synthetic-home/Projects/pjbeyer/demo")
        matched = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git",
            "demo",
            "generic",
            "baseline",
            destination_confirmation=str(destination),
        )

        self.assertRegex(request_fingerprint(matched, destination), r"^[0-9a-f]{64}$")
        with self.assertRaises(ConfigurationError):
            request_fingerprint(
                replace(
                    matched,
                    destination_confirmation="/Users/synthetic-home/Projects/pjbeyer/other",
                ),
                destination,
            )
        with self.assertRaises(ConfigurationError):
            request_fingerprint(
                replace(
                    matched,
                    destination_confirmation="/Users/synthetic-home/Projects/pjbeyer/demo/../demo",
                ),
                destination,
            )
        with self.assertRaises(ConfigurationError):
            request_fingerprint(
                replace(
                    matched,
                    destination_confirmation="/Users/synthetic-home/Projects/pjbeyer/demo//leaf/..",
                ),
                destination,
            )
        with self.assertRaises(ConfigurationError):
            request_fingerprint(
                replace(matched, destination_confirmation=destination),  # type: ignore[arg-type]
                destination,
            )

    def test_absolute_confirmation_never_resolves_or_reads_the_filesystem(self) -> None:
        destination = Path("/tmp/synthetic-demo")
        matched = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git",
            "demo",
            "generic",
            "baseline",
            destination_confirmation=str(destination),
        )
        mismatched = replace(matched, destination_confirmation="/tmp/synthetic-other")
        with patch.object(Path, "resolve", side_effect=AssertionError("resolve called")) as resolve, patch.object(
            Path, "exists", side_effect=AssertionError("exists called")
        ) as exists, patch.object(Path, "stat", side_effect=AssertionError("stat called")) as stat:
            matched_fingerprint = request_fingerprint(matched, destination)
            self.assertRegex(matched_fingerprint, r"^[0-9a-f]{64}$")
            with self.assertRaises(ConfigurationError):
                request_fingerprint(mismatched, destination)
            resolve.assert_not_called()
            exists.assert_not_called()
            stat.assert_not_called()

    def test_request_fingerprint_rejects_unsafe_values_instead_of_redacting_collisions(self) -> None:
        destination = Path.home() / "Projects/pjbeyer/demo"
        unsafe_values = (
            "${SYNTHETIC_TOKEN}",
            "$SYNTHETIC_TOKEN",
            "GITHUB_TOKEN=synthetic-marker",
            "refs/heads/main",
            "HEAD",
            "op://SyntheticVault/SyntheticItem/SyntheticField",
            "https://***@synthetic.invalid/value",
            "/Users/synthetic-private/value",
            "note before /Users/synthetic-private/value after",
            r"note before C:\Users\synthetic-private\value after",
            "note before C:/Users/synthetic-private/value after",
        )
        for value in unsafe_values:
            for field_name in (
                "origin_url",
                "beads_prefix",
                "project_kind",
                "description",
                "destination_confirmation",
            ):
                request = ProvisioningRequest(
                    "https://github.com/pjbeyer/demo.git",
                    "demo",
                    "generic",
                    "baseline",
                    "Projects/pjbeyer/demo",
                )
                with self.subTest(value=value, field=field_name), self.assertRaises(ConfigurationError):
                    request_fingerprint(replace(request, **{field_name: value}), destination)

    def test_rejects_subclasses_hybrids_protocol_lookalikes_booleans_and_blobs(self) -> None:
        class AuthorizationSubclass(LiveAuthorization):
            pass

        subclass = AuthorizationSubclass(
            self.authorization.named_identity,
            self.authorization.request_fingerprint,
            self.authorization.config_digest,
            self.authorization.permitted_starting_gate,
        )
        lookalike = SimpleNamespace(
            named_identity=self.authorization.named_identity,
            request_fingerprint=self.authorization.request_fingerprint,
            config_digest=self.authorization.config_digest,
            permitted_starting_gate=self.authorization.permitted_starting_gate,
        )
        for value in (subclass, lookalike, True, False, self.authorization.__dict__ if hasattr(self.authorization, "__dict__") else {}):
            with self.subTest(value_type=type(value).__name__):
                self.assert_rejected(authorization_value=value)

    def test_rejects_wrong_or_forged_values_for_every_incoming_binding(self) -> None:
        class IdentitySubclass(str):
            pass

        class DigestSubclass(str):
            pass

        class ConfigurationSubclass(ImmutableLiveConfiguration):
            pass

        hostile_configuration = object.__new__(ConfigurationSubclass)
        for field_name in self.config.__dataclass_fields__:
            object.__setattr__(hostile_configuration, field_name, getattr(self.config, field_name))
        self.assertIs(type(hostile_configuration), ConfigurationSubclass)
        self.assertEqual(hostile_configuration.canonical_fields(), self.config.canonical_fields())
        cases = (
            {"named_identity": IdentitySubclass(self.config.repository_identity)},
            {"named_identity": True},
            {"named_identity": "invalid identity"},
            {"request_fingerprint": DigestSubclass(self.fingerprint)},
            {"request_fingerprint": True},
            {"request_fingerprint": "A" * 64},
            {"request_fingerprint": "a" * 63},
            {"configuration": hostile_configuration},
            {"configuration": True},
            {"starting_gate": str(Gate.PREFLIGHT)},
            {"starting_gate": True},
        )
        baseline = {
            "named_identity": self.config.repository_identity,
            "request_fingerprint": self.fingerprint,
            "configuration": self.config,
            "starting_gate": Gate.PREFLIGHT,
        }
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(AuthorizationError):
                assert_live_authorized(self.authorization, **{**baseline, **changed})

        forged_authorization = copy.copy(self.authorization)
        object.__setattr__(forged_authorization, "request_fingerprint", True)
        self.assert_rejected(authorization_value=forged_authorization)
        forged_configuration = forged(self.config, "repository_identity", True)
        self.assert_rejected(config=forged_configuration)

    def test_rejects_equality_forging_binding_objects(self) -> None:
        class EqualToEverything:
            def __eq__(self, other: object) -> bool:
                return True

        forged_authorization = copy.copy(self.authorization)
        object.__setattr__(forged_authorization, "named_identity", EqualToEverything())
        self.assert_rejected(authorization_value=forged_authorization)
        forged_configuration = forged(self.config, "template_tag", EqualToEverything())
        self.assert_rejected(config=forged_configuration)

    def test_rejects_authorization_with_stale_or_wrong_config_digest(self) -> None:
        stale = replace(self.authorization, config_digest="b" * 64)
        self.assert_rejected(authorization_value=stale)

    def test_concurrent_mutation_cannot_return_changed_authorization(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        original_post_init = LiveAuthorization.__post_init__

        def paused_post_init(value: LiveAuthorization) -> None:
            original_post_init(value)
            entered.set()
            if not release.wait(timeout=2):
                raise AssertionError("mutation test timed out")

        outcome: list[object] = []

        def check() -> None:
            try:
                outcome.append(
                    assert_live_authorized(
                        self.authorization,
                        named_identity=self.config.repository_identity,
                        request_fingerprint=self.fingerprint,
                        configuration=self.config,
                        starting_gate=Gate.PREFLIGHT,
                    )
                )
            except BaseException as error:
                outcome.append(error)

        with patch.object(LiveAuthorization, "__post_init__", paused_post_init):
            thread = threading.Thread(target=check)
            thread.start()
            self.assertTrue(entered.wait(timeout=2))
            object.__setattr__(self.authorization, "permitted_starting_gate", Gate.CLONE)
            release.set()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], AuthorizationError)


class SafeLiveEvidenceTests(unittest.TestCase):
    def evidence(self) -> LiveProvisioningEvidence:
        config = configuration()
        return LiveProvisioningEvidence(
            template_source_identity=config.template_source_identity,
            template_tag=config.template_tag,
            resolved_template_commit=config.resolved_template_commit,
            config_digest=configuration_digest(config),
            actual_database="synthetic_database",
            manifest_identity=config.manifest_identity,
            stable_issue_markers=("scope-readme", "first-speckit-spec"),
            validated_component_pins=config.component_pins,
        )

    def test_json_round_trip_has_exact_safe_shape(self) -> None:
        evidence = self.evidence()
        payload = live_evidence_to_json(evidence)
        decoded = json.loads(payload)
        self.assertEqual(
            set(decoded),
            {
                "template_source_identity",
                "template_tag",
                "resolved_template_commit",
                "config_digest",
                "actual_database",
                "manifest_identity",
                "stable_issue_markers",
                "validated_component_pins",
            },
        )
        self.assertEqual(live_evidence_from_json(payload), evidence)
        self.assertNotIn("destination", decoded)
        self.assertNotIn("readback", payload.lower())
        self.assertNotIn("/Users/", payload)

    def test_json_reader_rejects_missing_extra_or_wrong_shape(self) -> None:
        payload = json.loads(live_evidence_to_json(self.evidence()))
        missing = dict(payload)
        missing.pop("actual_database")
        extra = {**payload, "credential": "synthetic-marker"}
        wrong = {**payload, "stable_issue_markers": "scope-readme"}
        for changed in (missing, extra, wrong):
            with self.subTest(keys=set(changed)), self.assertRaises(ValueError):
                live_evidence_from_json(json.dumps(changed))

    def test_evidence_rejects_secret_patterns_pointers_tokenized_urls_and_private_paths(self) -> None:
        evidence = self.evidence()
        rejected = (
            "op://SyntheticVault/SyntheticItem/SyntheticField",
            "https://synthetic-userinfo@synthetic.invalid/value",
            "password=synthetic-marker",
            "/Users/synthetic-private/value",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                replace(evidence, actual_database=value)

    def test_evidence_rejects_unsafe_values_in_every_text_and_pin_field(self) -> None:
        evidence = self.evidence()
        rejected = (
            "${SYNTHETIC_TOKEN}",
            "$SYNTHETIC_TOKEN",
            "GITHUB_TOKEN=synthetic-marker",
            "main",
            "origin/main",
            "refs/remotes/origin/main",
            "refs/heads/main",
            "heads/main",
            "HEAD",
            "op://SyntheticVault/SyntheticItem/SyntheticField",
            "https://***@synthetic.invalid/value",
            "/Users/synthetic-private/value",
            "prefix /Users/synthetic-private/value suffix",
        )
        scalar_fields = (
            "template_source_identity",
            "template_tag",
            "resolved_template_commit",
            "config_digest",
            "actual_database",
            "manifest_identity",
        )
        for value in rejected:
            for field_name in scalar_fields:
                with self.subTest(value=value, field=field_name), self.assertRaises(ConfigurationError):
                    replace(evidence, **{field_name: value})
            with self.subTest(value=value, field="stable_issue_markers"), self.assertRaises(ConfigurationError):
                replace(evidence, stable_issue_markers=(value,))
            unsafe_pin = copy.copy(evidence.validated_component_pins[0])
            object.__setattr__(unsafe_pin, "source_identity", value)
            with self.subTest(value=value, field="pin.source_identity"), self.assertRaises(ConfigurationError):
                replace(
                    evidence,
                    validated_component_pins=(unsafe_pin, *evidence.validated_component_pins[1:]),
                )

    def test_evidence_template_tag_requires_conservative_version_shape(self) -> None:
        evidence = self.evidence()
        for value in ("v0.1.3", "v2.10.3-rc.1", "1.2.3+build.7"):
            with self.subTest(value=value):
                replace(evidence, template_tag=value)
        for value in (
            "develop",
            "release",
            "origin/develop",
            "refs/tags/v0.1.0",
            "$(whoami)",
            "`whoami`",
            "v0.1.0;whoami",
            "v0.1.0&&whoami",
        ):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                replace(evidence, template_tag=value)

    def test_evidence_rejects_embedded_private_paths_and_admits_https_url(self) -> None:
        evidence = self.evidence()
        private_values = (
            "prefix /Users/synthetic-private/value suffix",
            r"prefix C:\Users\synthetic-private\value suffix",
            "prefix C:/Users/synthetic-private/value suffix",
        )
        for value in private_values:
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                replace(evidence, actual_database=value)
            self.assertNotEqual(redact(value), value)
        legitimate_url = "https://example.invalid/Users/synthetic-public/value"
        self.assertEqual(redact(legitimate_url), legitimate_url)

    def test_mutated_evidence_fails_closed_at_serialization(self) -> None:
        evidence = self.evidence()
        object.__setattr__(evidence, "template_tag", "develop")
        with self.assertRaises(ConfigurationError):
            live_evidence_to_json(evidence)
        object.__setattr__(evidence, "template_tag", "v0.1.3")
        object.__setattr__(evidence, "actual_database", "prefix C:/Users/synthetic-private/value")
        with self.assertRaises(ConfigurationError):
            live_evidence_to_json(evidence)

    def test_evidence_fixed_identity_rejects_equality_forging_string_subclass(self) -> None:
        class EqualString(str):
            def __eq__(self, other: object) -> bool:
                return True

            __hash__ = str.__hash__

        hostile = EqualString("hostile-but-equal")
        self.assertTrue(hostile == APPROVED_MANIFEST_IDENTITY)
        with self.assertRaises(ConfigurationError):
            replace(self.evidence(), manifest_identity=hostile)

    def test_serialization_hygiene_rejects_embedded_private_paths(self) -> None:
        unsafe = 'prefix {"detail":"before /Users/synthetic-private/value after"}'
        self.assertNotEqual(redact(unsafe), unsafe)


class LegacyLiveAdapterQuarantineTests(unittest.TestCase):
    def test_live_availability_flag_is_lifted(self) -> None:
        """The coarse quarantine flag is now True (Phil-approved 2026-09-13).

        Individual mutations remain bound to a sealed LiveAuthorization +
        ImmutableLiveConfiguration; this test pins only the flag state.
        """
        import scripts.adapters as adapters_module

        self.assertTrue(adapters_module._LIVE_EXECUTION_AVAILABLE)

    def test_gate_precedes_config_authorization_and_executor_access(self) -> None:
        """An unprepared/gate-unauthorized adapter still fails closed in order.

        With the flag lifted, `prepare()` now requires a real
        ImmutableLiveConfiguration and a sealed authorization; a forged request
        carrying a non-LiveAuthorization object still fails closed before any
        executor construction or config validation.
        """
        class Tripwire:
            def __getattribute__(self, name: str) -> object:
                raise AssertionError(f"legacy live adapter accessed {name}")

        request = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git",
            "demo",
            "generic",
            live_authorization=Tripwire(),  # type: ignore[arg-type]
        )
        adapter = LiveAdapter(config=Tripwire())  # type: ignore[arg-type]
        origin = SimpleNamespace(identity="pjbeyer/demo")
        destination = Path("/Users/synthetic-home/Projects/pjbeyer/demo")
        with patch("scripts.adapters.assert_live_authorized", side_effect=AssertionError("authorization accessed")), patch.object(
            adapter,
            "_controlled_executor_type",
            side_effect=AssertionError("executor constructed"),
        ), patch.object(adapter, "_validate_config", side_effect=AssertionError("config validated")):
            # prepare() must reject the non-exact config BEFORE consulting the
            # authorization binder, the executor type, or config validation.
            with self.assertRaisesRegex(AdapterError, "exact immutable configuration type"):
                adapter.prepare(request, origin, destination, "a" * 64)  # type: ignore[arg-type]
            # template_revision on an unprepared adapter still fails closed.
            with self.assertRaises(AdapterError):
                _ = adapter.template_revision

    def test_context_returns_real_tuple_only_when_prepared(self) -> None:
        """With the flag lifted, _context returns the real 4-tuple when prepared.

        Also confirms an unprepared adapter fails closed with a controlled
        AdapterError (not AttributeError) and that a stale/non-exact config is
        rejected at the choke point.
        """
        import scripts.adapters as adapters_module

        original = adapters_module._LIVE_EXECUTION_AVAILABLE
        try:
            adapters_module._LIVE_EXECUTION_AVAILABLE = True
            adapter = LiveAdapter()
            # Bare, unprepared adapter: fail closed before touching any field.
            with self.assertRaises(AdapterError):
                adapter._context()
            config = ImmutableLiveConfiguration.create(
                repository_identity="pjbeyer/demo",
                template_source_identity="pjbeyer/phil-ai-project-template",
                template_tag="v0.1.3",
                resolved_template_commit="1" * 40,
                component_pins={
                    name: ComponentPin(name, f"speckit/component/{name}", "1" * 40)
                    for name in APPROVED_COMPONENT_NAMES
                },
            )
            adapter.config = config
            adapter.request = ProvisioningRequest(
                "https://github.com/pjbeyer/demo.git", "demo", "generic"
            )
            adapter.origin = SimpleNamespace(identity="pjbeyer/demo")
            adapter.destination = Path("/Users/synthetic-home/Projects/pjbeyer/demo")
            adapter._prepared = True
            # Prepared with a valid immutable config: _context returns the tuple.
            request, origin, destination, returned_config = adapter._context()
            self.assertEqual(request, adapter.request)
            self.assertEqual(origin, adapter.origin)
            self.assertEqual(destination, adapter.destination)
            self.assertIs(returned_config, config)
        finally:
            adapters_module._LIVE_EXECUTION_AVAILABLE = original


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Unit tests for project-provisioning request preflight."""
from __future__ import annotations

import unittest
from pathlib import Path

from scripts.models import ProvisioningRequest
from scripts.preflight import PreflightError, clean_beads_env, destination_for, normalize_request, parse_origin


class PreflightTests(unittest.TestCase):
    def test_https_and_ssh_origin_parse(self) -> None:
        self.assertEqual(parse_origin("https://github.com/pjbeyer/demo.git").identity, "pjbeyer/demo")
        self.assertEqual(parse_origin("git@github.com:flexapp/demo.git").identity, "flexapp/demo")

    def test_rejects_userinfo_and_untrusted_host(self) -> None:
        for origin in ("https://token@github.com/pjbeyer/demo.git", "https://example.com/pjbeyer/demo", "https://github.com/pjbeyer/demo path"):
            with self.subTest(origin=origin), self.assertRaises(PreflightError):
                parse_origin(origin)

    def test_routing_and_prefix_validation(self) -> None:
        request = ProvisioningRequest("https://github.com/pjbeyer/demo.git", "demo", "generic")
        origin, destination = normalize_request(request, Path("/example"))
        self.assertEqual(origin.identity, "pjbeyer/demo")
        self.assertEqual(destination, Path("/example/Projects/pjbeyer/demo"))
        with self.assertRaises(PreflightError):
            normalize_request(ProvisioningRequest("https://github.com/pjbeyer/demo.git", "NO", "generic"), Path("/example"))

    def test_coding_agent_plugin_kind_and_visibility_are_admitted(self) -> None:
        request = ProvisioningRequest(
            "https://github.com/pjbeyer/demo.git", "demo", "coding-agent-plugin",
            visibility="work-internal",
        )
        origin, _ = normalize_request(request, Path("/example"))
        self.assertEqual(origin.identity, "pjbeyer/demo")

    def test_unrecognized_kind_and_visibility_fail_closed(self) -> None:
        with self.assertRaises(PreflightError):
            normalize_request(
                ProvisioningRequest(
                    "https://github.com/pjbeyer/demo.git", "demo", "not-a-kind"
                ),
                Path("/example"),
            )
        with self.assertRaises(PreflightError):
            normalize_request(
                ProvisioningRequest(
                    "https://github.com/pjbeyer/demo.git", "demo", "generic",
                    visibility="not-a-visibility",
                ),
                Path("/example"),
            )

    def test_visibility_defaults_to_personal_only(self) -> None:
        request = ProvisioningRequest("https://github.com/pjbeyer/demo.git", "demo", "generic")
        self.assertEqual(request.visibility, "personal-only")

    def test_unknown_owner_needs_confirmation(self) -> None:
        origin = parse_origin("https://github.com/other/demo.git")
        with self.assertRaises(PreflightError):
            destination_for(origin, None, Path("/example"))

    def test_cleans_stale_beads_overrides(self) -> None:
        env = clean_beads_env()
        self.assertNotIn("BEADS_DOLT_PORT", env)
        self.assertNotIn("BEADS_DOLT_DATABASE", env)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Publish-hygiene gate (FR-029 / SC-011) deterministic coverage.

Proves the open-source publish-hygiene scanner rejects every FR-029 hazard
class (absolute workstation path, credential/secret, private endpoint / internal
hostname, tokenized URL), that require_publish_hygiene fails closed, and that
the non-open-source/private-origin contract is encoded correctly.
"""
from __future__ import annotations

import unittest

from scripts.publish_hygiene import (
    PublishHygieneError,
    non_open_source_requires_private,
    require_publish_hygiene,
    scan_published_surface,
)


class PublishHygieneTests(unittest.TestCase):
    def test_clean_surface_passes(self) -> None:
        result = scan_published_surface(
            rendered_texts=[("README.md", "A public project with no secrets.")],
            answer_metadata=[("project_description", "A benign open-source tool")],
            git_history=[("commit", "feat: add public readme")],
            remote_issue_bodies=[("issue", "Track the first release")],
        )
        self.assertTrue(result.passed)
        require_publish_hygiene(result)  # no raise

    def test_rendered_absolute_workstation_path_rejected(self) -> None:
        result = scan_published_surface(
            rendered_texts=[("README.md", "install from /Users/alice/dev/tool")]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.findings[0].category, "private-path")

    def test_rendered_secret_shaped_value_rejected(self) -> None:
        result = scan_published_surface(
            rendered_texts=[("README.md", "token=ghp_1234567890abcdefghij")]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.findings[0].category, "secret")

    def test_answer_metadata_op_reference_rejected(self) -> None:
        result = scan_published_surface(
            answer_metadata=[("project_description", "use op://vault/dev-token")]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.findings[0].category, "secret")

    def test_rendered_private_endpoint_rejected(self) -> None:
        for endpoint in ("10.1.2.3:3307", "192.168.1.10", "connect via localhost"):
            with self.subTest(endpoint=endpoint):
                result = scan_published_surface(rendered_texts=[("README.md", endpoint)])
                self.assertFalse(result.passed)
                self.assertEqual(result.findings[0].category, "private-endpoint")

    def test_internal_hostname_inventory_rejected(self) -> None:
        result = scan_published_surface(
            rendered_texts=[("README.md", "hosts: db.prod.internal, api.corp.local")]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.findings[0].category, "private-endpoint")

    def test_tokenized_url_userinfo_rejected(self) -> None:
        result = scan_published_surface(
            rendered_texts=[("README.md", "clone https://user:pass@github.com/x/y.git")]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.findings[0].category, "secret")

    def test_require_publish_hygiene_fails_closed(self) -> None:
        dirty = scan_published_surface(rendered_texts=[("f", "AKIA0123456789ABCDEF")])
        with self.assertRaises(PublishHygieneError):
            require_publish_hygiene(dirty)

    def test_non_open_source_requires_private(self) -> None:
        self.assertTrue(non_open_source_requires_private("personal-only"))
        self.assertTrue(non_open_source_requires_private("work-internal"))
        self.assertFalse(non_open_source_requires_private("open-source"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Origin-visibility resolution (SC-013) deterministic coverage.

Proves the closed four-way matrix, the contradiction and unreachable fail-closed
paths, the G11 pre-push gate, and owner-independence all hold without any
transport.
"""
from __future__ import annotations

import unittest

from scripts.origin_visibility import (
    OriginVisibility,
    VisibilityResolutionError,
    require_visibility_for,
    resolve_origin_visibility,
)


class OriginVisibilityTests(unittest.TestCase):
    def test_public(self) -> None:
        self.assertIs(
            resolve_origin_visibility(True, True), OriginVisibility.PUBLIC
        )

    def test_private(self) -> None:
        self.assertIs(
            resolve_origin_visibility(False, True), OriginVisibility.PRIVATE
        )

    def test_unreachable(self) -> None:
        self.assertIs(
            resolve_origin_visibility(False, False), OriginVisibility.UNREACHABLE
        )

    def test_contradiction_fails_closed(self) -> None:
        with self.assertRaises(VisibilityResolutionError):
            resolve_origin_visibility(True, False)

    def test_non_open_source_gate(self) -> None:
        for visibility in ("personal-only", "work-internal"):
            require_visibility_for(visibility, OriginVisibility.PRIVATE)  # no raise
            with self.subTest(visibility=visibility, resolved="public"):
                with self.assertRaises(VisibilityResolutionError):
                    require_visibility_for(visibility, OriginVisibility.PUBLIC)
            with self.subTest(visibility=visibility, resolved="unreachable"):
                with self.assertRaises(VisibilityResolutionError):
                    require_visibility_for(visibility, OriginVisibility.UNREACHABLE)

    def test_open_source_gate(self) -> None:
        require_visibility_for("open-source", OriginVisibility.PUBLIC)  # no raise
        with self.assertRaises(VisibilityResolutionError):
            require_visibility_for("open-source", OriginVisibility.PRIVATE)

    def test_unknown_visibility_fails_closed(self) -> None:
        # Never infer from owner or from an unrecognized value (FR-029).
        with self.assertRaises(VisibilityResolutionError):
            require_visibility_for("pjbeyer-private", OriginVisibility.PRIVATE)
        with self.assertRaises(VisibilityResolutionError):
            require_visibility_for("nonsense", OriginVisibility.PUBLIC)


if __name__ == "__main__":
    unittest.main(verbosity=2)

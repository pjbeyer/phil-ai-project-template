#!/usr/bin/env python3
"""Render-contract tests for the project-provisioning Copier template."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COPIER = shutil.which("copier")
SHA = re.compile(r"@[0-9a-f]{40}(?:\s+#\s*[^\n]+)?$")
SECRET = re.compile(r"(?:ghp_|github_pat_|AKIA|-----BEGIN|https://[^/@\s]+@)", re.I)
COMMON = {
    "README.md", "CONTRIBUTING.md", "AGENTS.md", ".gitignore", "VERSION", "CHANGELOG.md",
    "release-please-config.json", ".release-please-manifest.json", ".github/workflows/release-please.yml",
}


@unittest.skipUnless(COPIER, "copier is required")
class RenderContractTests(unittest.TestCase):
    maxDiff = None

    def render(self, kind: str) -> Path:
        target = Path(tempfile.mkdtemp()) / kind
        command = [
            COPIER, "copy", "--trust", "--defaults", "--data", "repository_owner=example",
            "--data", "repository_name=demo", "--data", "project_kind=" + kind,
            "--data", "template_revision=v0.1.0", str(ROOT), str(target),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        self.addCleanup(shutil.rmtree, target.parent)
        return target

    def files(self, target: Path) -> set[str]:
        return {path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()}

    def assert_common(self, target: Path, files: set[str]) -> None:
        self.assertTrue(COMMON <= files)
        self.assertIn("v0.1.0", (target / "README.md").read_text())
        rendered_paths = "\n".join(
            path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()
        )
        self.assertNotIn("/Users/", rendered_paths)
        self.assertEqual(json.loads((target / "release-please-config.json").read_text())["release-type"], "simple")
        for workflow in (target / ".github/workflows").glob("*.yml"):
            yaml.safe_load(workflow.read_text())
            for line in workflow.read_text().splitlines():
                if "uses:" in line:
                    self.assertRegex(line.strip(), SHA)
        rendered = "\n".join(
            path.read_text(errors="ignore") for path in target.rglob("*")
            if path.is_file()
        )
        self.assertNotRegex(rendered, SECRET)
        self.assertFalse((target / ".beads").exists())
        self.assertFalse((target / ".specify").exists())

    def test_generic_render_contract(self) -> None:
        target = self.render("generic")
        files = self.files(target)
        self.assert_common(target, files)
        self.assertEqual(files, COMMON)

    def test_macos_cli_render_contract(self) -> None:
        target = self.render("macos-cli")
        files = self.files(target)
        self.assert_common(target, files)
        self.assertEqual(files, COMMON | {".github/workflows/macos-ci.yml", "scripts/ci-macos.sh"})
        self.assertFalse((target / "src").exists())
        subprocess.run(["bash", "scripts/ci-macos.sh"], check=True, cwd=target)

    def test_homebrew_tap_render_contract(self) -> None:
        target = self.render("homebrew-tap")
        files = self.files(target)
        self.assert_common(target, files)
        self.assertEqual(files, COMMON | {".github/workflows/homebrew-ci.yml", "Formula/.gitkeep", "Casks/.gitkeep"})
        workflow = (target / ".github/workflows/homebrew-ci.yml").read_text()
        self.assertNotIn("flexapp/flex-gha-actions", workflow)
        for job in ("tap-syntax", "read-only-without-token", "test-formulae", "test-casks"):
            self.assertIn(job + ":", workflow)
        self.assertIn('HOMEBREW_GITHUB_API_TOKEN: ""', workflow)
        self.assertIn("test -z \"$HOMEBREW_GITHUB_API_TOKEN\"", workflow)
        self.assertIn("secrets.HOMEBREW_GITHUB_API_TOKEN", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)

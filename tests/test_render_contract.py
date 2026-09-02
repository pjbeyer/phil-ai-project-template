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
    ".copier-answers.yml", "README.md", "CONTRIBUTING.md", "AGENTS.md", ".gitignore",
    "VERSION", "CHANGELOG.md", "release-please-config.json", ".release-please-manifest.json",
    ".github/workflows/release-please.yml",
}


@unittest.skipUnless(COPIER, "copier is required")
class RenderContractTests(unittest.TestCase):
    maxDiff = None

    def source(self) -> Path:
        """Create an immutable, isolated Git source for Copier copy/update tests."""
        root = Path(tempfile.mkdtemp())
        source = root / "template"
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        subprocess.run(["git", "init", "-q"], cwd=source, check=True)
        subprocess.run(["git", "config", "user.email", "copier-test@example.invalid"], cwd=source, check=True)
        subprocess.run(["git", "config", "user.name", "Copier test"], cwd=source, check=True)
        subprocess.run(["git", "add", "."], cwd=source, check=True)
        subprocess.run(["git", "commit", "-qm", "template fixture"], cwd=source, check=True)
        subprocess.run(["git", "tag", "fixture-v0.1.2"], cwd=source, check=True)
        self.addCleanup(shutil.rmtree, root)
        return source

    def render(self, kind: str) -> Path:
        source = self.source()
        target = source.parent / kind
        assert COPIER is not None
        command = [
            COPIER, "copy", "--trust", "--defaults", "--vcs-ref=fixture-v0.1.2",
            "--data", "repository_owner=example", "--data", "repository_name=demo",
            "--data", "project_kind=" + kind, "--data", "template_revision=v0.1.2",
            str(source), str(target),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        return target

    def files(self, target: Path) -> set[str]:
        return {path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()}

    def assert_answers(self, target: Path, kind: str) -> None:
        answers = yaml.safe_load((target / ".copier-answers.yml").read_text())
        self.assertEqual(answers["repository_owner"], "example")
        self.assertEqual(answers["repository_name"], "demo")
        self.assertEqual(answers["project_kind"], kind)
        self.assertEqual(answers["template_revision"], "v0.1.2")
        self.assertTrue(answers["_src_path"])
        self.assertNotIn("@", answers["_src_path"])
        self.assertEqual(answers["_commit"], "fixture-v0.1.2")
        self.assertNotRegex(json.dumps(answers), SECRET)

    def assert_update_works(self, target: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.email", "copier-test@example.invalid"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.name", "Copier test"], cwd=target, check=True)
        subprocess.run(["git", "add", "."], cwd=target, check=True)
        subprocess.run(["git", "commit", "-qm", "initial render"], cwd=target, check=True)
        assert COPIER is not None
        subprocess.run(
            [COPIER, "update", "--trust", "--defaults", "--vcs-ref=fixture-v0.1.2"],
            cwd=target, check=True, capture_output=True, text=True,
        )
        self.assertTrue((target / ".copier-answers.yml").is_file())

    def assert_common(self, target: Path, files: set[str], kind: str) -> None:
        self.assertTrue(COMMON <= files)
        self.assert_answers(target, kind)
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
        rendered = "\n".join(path.read_text(errors="ignore") for path in target.rglob("*") if path.is_file())
        self.assertNotRegex(rendered, SECRET)
        self.assertFalse((target / ".beads").exists())
        self.assertFalse((target / ".specify").exists())

    def test_generic_render_contract(self) -> None:
        target = self.render("generic")
        files = self.files(target)
        self.assert_common(target, files, "generic")
        self.assertEqual(files, COMMON)
        self.assert_update_works(target)

    def test_macos_cli_render_contract(self) -> None:
        target = self.render("macos-cli")
        files = self.files(target)
        self.assert_common(target, files, "macos-cli")
        self.assertEqual(files, COMMON | {".github/workflows/macos-ci.yml", "scripts/ci-macos.sh"})
        self.assertFalse((target / "src").exists())
        subprocess.run(["bash", "scripts/ci-macos.sh"], check=True, cwd=target)
        self.assert_update_works(target)

    def test_homebrew_tap_render_contract(self) -> None:
        target = self.render("homebrew-tap")
        files = self.files(target)
        self.assert_common(target, files, "homebrew-tap")
        self.assertEqual(files, COMMON | {".github/workflows/homebrew-ci.yml", "Formula/.gitkeep", "Casks/.gitkeep"})
        workflow = (target / ".github/workflows/homebrew-ci.yml").read_text()
        self.assertNotIn("flexapp/flex-gha-actions", workflow)
        for job in ("tap-syntax", "read-only-without-token", "test-formulae", "test-casks"):
            self.assertIn(job + ":", workflow)
        self.assertIn('HOMEBREW_GITHUB_API_TOKEN: ""', workflow)
        self.assertIn("test -z \"$HOMEBREW_GITHUB_API_TOKEN\"", workflow)
        self.assertIn("secrets.HOMEBREW_GITHUB_API_TOKEN", workflow)
        self.assert_update_works(target)


if __name__ == "__main__":
    unittest.main(verbosity=2)

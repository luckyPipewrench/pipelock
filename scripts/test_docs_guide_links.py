#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise the documentation gate with real guide and example fixtures."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DocsGuideLinksTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for command in ("bash", "dirname", "awk", "rg"):
            executable = shutil.which(command)
            if executable is None:
                self.skipTest(f"{command} is required to exercise the documentation gate")
            (self.bin / command).symlink_to(executable)
        (self.bin / "python3").symlink_to(sys.executable)
        for directory in ("scripts", "examples/sample", "docs/guides", "docs/specs"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        for source in ("scripts/docs-check.sh", "examples/check_guide_links.py"):
            shutil.copyfile(ROOT / source, self.root / source)
        for name in ("README.md", "CLAUDE.md", "CONTRIBUTING.md", "GOVERNANCE.md", "SECURITY.md"):
            (self.root / name).write_text("", encoding="utf-8")
        for name in (
            "guides/deployment-recipes.md", "guides/conductor.md", "guides/conductor-operator-runbook.md",
            "guides/conductor-production-runbook.md", "guides/enterprise-license-issuance-runbook.md",
            "specs/pipelock-conductor-audit-sink.md",
        ):
            (self.root / "docs" / name).write_text("", encoding="utf-8")
        for name in ("ci-workflow.yaml", "ci-workflow-advanced.yaml"):
            shutil.copyfile(ROOT / "examples" / name, self.root / "examples" / name)
        # The gate's unrelated brand, stats and Go checks remain in the script.
        # Stub their executables so this test exercises only the documentation path.
        (self.root / "scripts/render_brand.py").write_text("print('brand-check fixture')\n", encoding="utf-8")
        for command in ("make", "go"):
            path = self.bin / command
            path.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' '{command} fixture'\n", encoding="utf-8")
            path.chmod(0o700)
        self.guide = self.root / "docs/guides/sample.md"
        self.readme = self.root / "examples/sample/README.md"
        self.guide.write_text("Try [the example](../../examples/sample/).\n", encoding="utf-8")
        self.readme.write_text("Read [the guide](../../docs/guides/sample.md).\n", encoding="utf-8")

    def run_gate(self):
        return subprocess.run(
            [str(self.bin / "bash"), str(self.root / "scripts/docs-check.sh")],
            cwd=self.root,
            env=os.environ | {"PATH": str(self.bin)},
            capture_output=True, text=True, check=False, timeout=15,
        )

    def assert_failure(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("docs-check: ok", result.stdout)
        self.assertNotIn("make fixture", result.stdout)
        self.assertNotIn("go fixture", result.stdout)

    def test_reciprocal_links_pass_and_preserve_later_checks(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("example-guide-links: OK (1 guide/example relationships)", result.stdout)
        for output in ("brand-check fixture", "make fixture", "go fixture", "docs-check: ok"):
            self.assertIn(output, result.stdout)

    def test_missing_backlink_fails(self):
        self.readme.write_text("Example usage only.\n", encoding="utf-8")
        result = self.run_gate()
        self.assert_failure(result)
        self.assertIn("missing Markdown link to docs/guides/sample.md", result.stderr)

    def test_missing_checker_fails(self):
        (self.root / "examples/check_guide_links.py").unlink()
        result = self.run_gate()
        self.assert_failure(result)
        self.assertIn("check_guide_links.py", result.stderr)

    def test_existing_python_requirement_still_fails(self):
        # The brand check requires Python before guide-link validation runs.
        (self.bin / "python3").unlink()
        result = self.run_gate()
        self.assert_failure(result)
        self.assertIn("python3: command not found", result.stderr)

    def test_existing_stale_claim_check_still_fails(self):
        (self.root / "README.md").write_text("143 attack cases\n", encoding="utf-8")
        result = self.run_gate()
        self.assert_failure(result)
        self.assertIn("docs-check: failed: found stale gauntlet corpus count", result.stdout)


if __name__ == "__main__":
    unittest.main()

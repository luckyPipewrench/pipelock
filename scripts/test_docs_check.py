#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for fail-closed documentation checks."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS_CHECK = ROOT / "scripts" / "docs-check.sh"


def write_command(directory: Path, name: str, body: str) -> None:
    """Create one executable test command in an isolated PATH."""
    path = directory / name
    path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class DocsCheckTest(unittest.TestCase):
    def run_with_path(self, commands: dict[str, str]) -> subprocess.CompletedProcess[str]:
        """Run the real docs check with only the named commands available."""
        bash = shutil.which("bash")
        dirname = shutil.which("dirname")
        if bash is None or dirname is None:
            self.skipTest("bash and dirname are required to run docs-check.sh")

        with tempfile.TemporaryDirectory() as temp_dir:
            command_dir = Path(temp_dir)
            os.symlink(bash, command_dir / "bash")
            os.symlink(dirname, command_dir / "dirname")
            for name, body in commands.items():
                write_command(command_dir, name, body)
            return subprocess.run(
                [bash, str(DOCS_CHECK)],
                cwd=ROOT,
                env=os.environ | {"PATH": str(command_dir)},
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

    def test_missing_rg_fails_before_reporting_success(self):
        result = self.run_with_path({})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docs-check: failed: rg is required", result.stderr)
        self.assertNotIn("docs-check: ok", result.stdout)

    def test_rg_operational_error_fails_instead_of_meaning_no_match(self):
        result = self.run_with_path({"python3": "exit 0", "rg": "exit 2"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("docs-check: failed: rg could not check gauntlet corpus count (exit 2)", result.stderr)
        self.assertNotIn("docs-check: ok", result.stdout)


if __name__ == "__main__":
    unittest.main()

# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Subprocess checks for the Makefile's read-only validation contracts."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/check_lint_version.py"


class LintVersionContract(unittest.TestCase):
    def test_conflicting_workflow_pins_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, version in enumerate(("v2.13.2", "v2.13.1")):
                path = Path(directory) / f"{index}.yaml"
                path.write_text("jobs: {lint: {steps: [{uses: golangci/golangci-lint-action@sha, with: {version: " + version + "}}]}}")
                paths.append(str(path))
            result = subprocess.run(["python3", str(CHECK), *paths], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pins disagree across workflows", result.stderr)

    def test_make_targets_invoke_pin_check(self):
        for target in ("lint", "fmt", "debt-check"):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", "-n", target], cwd=ROOT,
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("python3 scripts/check_lint_version.py .github/workflows/ci.yaml", result.stdout)

    def run_check(self, workflow, installed="1.64.8"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "ci.yaml"
            path.write_text(workflow, encoding="utf-8")
            binary = root / "golangci-lint"
            binary.write_text(f"#!/bin/sh\necho 'golangci-lint has version {installed} built with go1.26.0 from fixture on 2026-01-01T00:00:00Z'\n")
            binary.chmod(0o755)
            return subprocess.run(
                ["python3", str(CHECK), str(path)],
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}"},
                capture_output=True,
                text=True,
                timeout=10,
            )

    def test_structural_pin_and_mismatch(self):
        workflow = """jobs:
  lint:
    steps:
      - uses: other/action@v1
        with: {version: v0.0.1}
      - uses: golangci/golangci-lint-action@sha
        with: {version: v1.64.8}
"""
        self.assertEqual(self.run_check(workflow).returncode, 0)
        self.assertNotEqual(self.run_check(workflow, "1.64.7").returncode, 0)
        self.assertNotEqual(self.run_check(workflow, "1.64.8-dev").returncode, 0)
        self.assertNotEqual(self.run_check(workflow, "unknown").returncode, 0)

    def test_missing_malformed_and_ambiguous_pins_fail(self):
        base = "jobs: {lint: {steps: [{uses: golangci/golangci-lint-action@sha, with: {version: %s}}]}}"
        for workflow in (
            "jobs: {}",
            base % "null",
            base % "latest",
            base % "v1.64.8" + "\ninvalid: [",
            "jobs: {lint: {steps: [{uses: golangci/golangci-lint-action@sha, with: {version: v1.64.8, version: v1.64.7}}]}}",
            "jobs: {lint: {steps: malformed}}",
            "jobs: {a: {steps: [{uses: golangci/golangci-lint-action@sha, with: {version: v1.64.8}}]}, b: {steps: [{uses: golangci/golangci-lint-action@sha, with: {version: v1.64.7}}]}}",
        ):
            with self.subTest(workflow=workflow):
                self.assertNotEqual(self.run_check(workflow).returncode, 0)


class TidyContract(unittest.TestCase):
    def test_tidy_check_preserves_files_and_detects_drift(self):
        if not shutil.which("go"):
            self.skipTest("Go unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.com/contract\n\ngo 1.26\n")
            (root / "main.go").write_text("package contract\n")
            source = (ROOT / "Makefile").read_text()
            target = re.search(r"(?m)^tidy-check:\n(?:\t.*\n)+", source)
            self.assertIsNotNone(target)
            (root / "Makefile").write_text(target.group())
            env = {**os.environ, "GOWORK": "off", "GOPROXY": "off"}

            def run():
                before = (root / "go.mod").read_bytes()
                result = subprocess.run(
                    ["make", "tidy-check"], cwd=root, env=env,
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual((root / "go.mod").read_bytes(), before)
                self.assertFalse((root / "go.sum").exists())
                return result

            self.assertEqual(run().returncode, 0)
            (root / "go.mod").write_text(
                "module example.com/contract\n\ngo 1.26\n\nrequire example.com/unused v1.0.0\n"
            )
            drift = run()
            self.assertNotEqual(drift.returncode, 0)
            self.assertIn("diff current/go.mod tidy/go.mod", drift.stdout + drift.stderr)
            (root / "go.mod").write_text("module example.com/contract\n\ngo 1.26\n")
            (root / "go.sum").write_text("example.com/unused v1.0.0 h1:unused\n")
            before_sum = (root / "go.sum").read_bytes()
            result = subprocess.run(
                ["make", "tidy-check"], cwd=root, env=env,
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "go.sum").read_bytes(), before_sum)


if __name__ == "__main__":
    unittest.main()

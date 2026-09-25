#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Keep core-only execution in CI coverage and wait for every upload."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class CodecovUploadCountTest(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/ci.yaml").read_text()
        self.codecov = (ROOT / "codecov.yml").read_text()
        self.jobs = yaml.safe_load(self.workflow)["jobs"]

    def run_count_check(self, workflow: str, codecov: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory(prefix="pipelock-codecov-contract-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / ".github/workflows").mkdir(parents=True)
            check = root / "scripts/check-codecov-upload-count.sh"
            check.write_bytes((ROOT / "scripts/check-codecov-upload-count.sh").read_bytes())
            (root / ".github/workflows/ci.yaml").write_text(workflow)
            (root / "codecov.yml").write_text(codecov)
            return subprocess.run(
                ["bash", str(check)], capture_output=True, text=True, check=False, timeout=10
            )

    def test_both_go126_build_variants_publish_their_profiles(self):
        for variant, profile in (
            ("oss", "coverage-oss-"),
            ("enterprise", "coverage-"),
        ):
            with self.subTest(variant=variant):
                steps = self.jobs[f"test-{variant}-go126"]["steps"]
                uploads = [
                    step for step in steps
                    if str(step.get("uses", "")).startswith("codecov/codecov-action@")
                ]
                self.assertEqual(len(uploads), 1)
                self.assertEqual(
                    uploads[0]["with"]["files"], f"./{profile}${{{{ matrix.shard }}}}.out"
                )
                test_commands = [
                    line.strip()
                    for step in steps
                    for line in step.get("run", "").splitlines()
                    if line.strip().startswith("go test ")
                ]
                self.assertEqual(len(test_commands), 1)
                self.assertIn(f'-coverprofile="{profile}${{TEST_SHARD}}.out"', test_commands[0])

    def test_real_upload_count_matches(self):
        result = self.run_count_check(self.workflow, self.codecov)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(yaml.safe_load(self.codecov)["codecov"]["notify"]["after_n_builds"], 13)

    def test_old_enterprise_only_count_is_rejected(self):
        document = yaml.safe_load(self.codecov)
        document["codecov"]["notify"]["after_n_builds"] = 7
        result = self.run_count_check(self.workflow, yaml.safe_dump(document))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MISMATCH", result.stderr)

    def test_missing_core_upload_is_rejected(self):
        # Preserve the actual workflow formatting consumed by the shell check.
        steps = self.jobs["test-oss-go126"]["steps"]
        uploads = [
            step for step in steps
            if str(step.get("uses", "")).startswith("codecov/codecov-action@")
        ]
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        start = self.workflow.index(
            "      - name: " + upload["name"], self.workflow.index("  test-oss-go126:")
        )
        end = self.workflow.index("\n  test-oss-go127:", start)
        broken = self.workflow[:start] + self.workflow[end:]
        broken_steps = yaml.safe_load(broken)["jobs"]["test-oss-go126"]["steps"]
        self.assertFalse(
            any("codecov/codecov-action@" in step.get("uses", "") for step in broken_steps)
        )
        result = self.run_count_check(broken, self.codecov)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MISMATCH", result.stderr)

    def test_no_uploading_matrix_is_rejected(self):
        workflow = "jobs:\n  tests:\n    strategy:\n      matrix:\n        shard: ['proxy']\n    steps: []\n"
        result = self.run_count_check(workflow, self.codecov)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("no uploading test matrix", result.stderr)


if __name__ == "__main__":
    unittest.main()

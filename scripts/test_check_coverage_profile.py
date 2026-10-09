# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the coverage profile check that runs before every upload."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-coverage-profile.sh"
BLOCK = "github.com/luckyPipewrench/pipelock/internal/a/a.go:3.14,5.2 1 1\n"


def run(profile: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(SCRIPT), str(profile)], check=False, text=True, capture_output=True)


class CoverageProfileCheckTest(unittest.TestCase):
    def test_accepts_every_go_mode_with_a_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "c.out"
            for mode in ("set", "count", "atomic"):
                with self.subTest(mode=mode):
                    profile.write_text(f"mode: {mode}\n{BLOCK}", encoding="utf-8")
                    result = run(profile)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_missing_empty_headerless_and_blockless_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "c.out"
            self.assertNotEqual(run(profile).returncode, 0, "missing profile accepted")
            for body in ("", "mode: set\n", BLOCK, "mode: bogus\n" + BLOCK, "mode: set\nnot a block line\n"):
                with self.subTest(body=body):
                    profile.write_text(body, encoding="utf-8")
                    self.assertNotEqual(run(profile).returncode, 0)

    def test_every_codecov_upload_is_verified_first(self) -> None:
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8"))["jobs"]
        uploads = 0
        for name, job in jobs.items():
            steps = job.get("steps", [])
            for index, step in enumerate(steps):
                if not str(step.get("uses", "")).startswith("codecov/codecov-action@"):
                    continue
                uploads += 1
                with self.subTest(job=name):
                    files = step["with"]["files"].removeprefix("./")
                    verify = [
                        earlier for earlier in steps[:index]
                        if earlier.get("run") == f"bash scripts/check-coverage-profile.sh {files}"
                    ]
                    self.assertEqual(len(verify), 1, f"{name} uploads {files} without verifying it")
                    self.assertNotIn("continue-on-error", verify[0])
                    self.assertNotIn("if", verify[0])
        self.assertGreater(uploads, 0, "found no Codecov uploads, so this guard is inert")


if __name__ == "__main__":
    unittest.main()

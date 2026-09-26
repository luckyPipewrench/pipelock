#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise the composite action's audit output with controlled audit JSON."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ActionAuditOutputTest(unittest.TestCase):
    def run_audit_step(self, finding):
        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        step = next(item for item in action["runs"]["steps"] if item["name"] == "Run audit")
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            fixture = base / "fixture.json"
            fixture.write_text(json.dumps({"score": 80, "findings": [finding]}), encoding="utf-8")
            binary = base / "pipelock"
            binary.write_text('#!/bin/sh\ncat "$AUDIT_FIXTURE"\n', encoding="utf-8")
            binary.chmod(0o700)
            output = base / "output"
            summary = base / "summary"
            env = os.environ | {
                "PATH": f"{base}:{os.environ['PATH']}",
                "AUDIT_FIXTURE": str(fixture),
                "RUNNER_TEMP": temp,
                "PIPELOCK_DIR": ".",
                "PIPELOCK_CONFIG": "",
                "PIPELOCK_EXCLUDE": "",
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
            }
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", step["run"]],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout, summary.read_text(encoding="utf-8"), output.read_text(encoding="utf-8")

    def test_filename_cannot_inject_workflow_annotation(self):
        forged = "config\n::warning file=other.yml::forged.yml"
        stdout, _, output = self.run_audit_step({
            "severity": "critical", "message": "Detected configuration issue",
            "file": forged, "line": 7,
        })
        annotations = [line for line in stdout.splitlines() if line.startswith("::")]
        self.assertEqual(len(annotations), 1, stdout)
        self.assertNotIn("\n::warning", stdout)
        self.assertIn("critical_count=1", output)
        self.assertIn("file=config%0A%3A%3Awarning", annotations[0])

    def test_normal_annotation_keeps_location_and_message(self):
        stdout, _, _ = self.run_audit_step({
            "severity": "warning", "message": "Detected configuration issue",
            "file": "config.yml", "line": 7,
        })
        self.assertIn("::warning file=config.yml,line=7::Detected configuration issue", stdout)


if __name__ == "__main__":
    unittest.main()

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
            # The real binary prints JSON for --json and a human-readable report
            # for -o, and that report quotes repository file names verbatim.
            # Replaying the JSON for both calls hid that second output stream.
            binary.write_text(
                '#!/bin/sh\n'
                'for arg in "$@"; do\n'
                '  if [ "$arg" = "-o" ]; then\n'
                '    printf \'Findings:\\n  (forged.yml\\n::warning file=forged.yml::FORGED from filename:1)\\n\'\n'
                '    exit 0\n'
                '  fi\n'
                'done\n'
                'cat "$AUDIT_FIXTURE"\n',
                encoding="utf-8",
            )
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

    def test_server_name_cannot_inject_summary_markdown(self):
        server = "mcp\n[Review details](https://api.vendor.example) | extra\rrow"
        _, summary, _ = self.run_audit_step({
            "severity": "warning", "message": f"MCP server {server} has no policy",
            "file": ".mcp.json", "line": 4,
        })
        self.assertNotIn("\n[Review details]", summary)
        self.assertNotIn("[Review details](https://api.vendor.example)", summary)
        self.assertIn("MCP server mcp", summary)
        self.assertIn("&#46;mcp&#46;json", summary)

    def test_normal_annotation_keeps_location_and_message(self):
        stdout, _, _ = self.run_audit_step({
            "severity": "warning", "message": "Detected configuration issue",
            "file": "config.yml", "line": 7,
        })
        self.assertIn("::warning file=config.yml,line=7::Detected configuration issue", stdout)


class ActionValidateOutputTest(unittest.TestCase):
    def run_validate_step(self, message, code):
        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        step = next(item for item in action["runs"]["steps"] if item["name"] == "Validate config")
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            binary = base / "pipelock"
            binary.write_text(f"#!/bin/sh\nprintf '%s\\n' {json.dumps(message)}\nexit {code}\n", encoding="utf-8")
            binary.chmod(0o700)
            env = os.environ | {"PATH": f"{base}:{os.environ['PATH']}", "PIPELOCK_CONFIG": "pipelock.yaml"}
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c", step["run"]],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )

    def test_config_value_cannot_inject_workflow_command(self):
        result = self.run_validate_step('invalid host "a\n::warning file=x.yml::FORGED"', 1)
        self.assertEqual(result.returncode, 1, result.stderr)
        lines = result.stdout.splitlines()
        self.assertTrue(lines[0].startswith("::stop-commands::"), result.stdout)
        token = lines[0].removeprefix("::stop-commands::")
        self.assertRegex(token, r"^[0-9a-f]{32}$")
        self.assertEqual(lines[-1], f"::{token}::")
        forged = [i for i, line in enumerate(lines) if "FORGED" in line]
        self.assertTrue(forged, result.stdout)
        self.assertTrue(all(0 < i < len(lines) - 1 for i in forged), result.stdout)

    def test_valid_config_keeps_success_and_output(self):
        result = self.run_validate_step("Config validation: OK", 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Config validation: OK", result.stdout)


if __name__ == "__main__":
    unittest.main()

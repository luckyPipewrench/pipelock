# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Require complete producer evidence for the scheduled timing refresh."""

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.ci_test_durations import ci_artifact_inputs
from scripts.ci_test_packages import ROOT, SHARDS


class ShardDriftTest(unittest.TestCase):
    def test_requires_every_nonempty_measured_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "missing or empty"):
                ci_artifact_inputs(root)
            paths = []
            for lane in ("oss", "enterprise"):
                for shard in SHARDS:
                    path = root / f"go-test-json-{lane}-go126-{shard}" / f"go-test-{lane}.json"
                    path.parent.mkdir()
                    path.write_text(json.dumps({"Action": "pass", "Package": "example.test/rest",
                                                "Elapsed": 1.0}) + "\n", encoding="utf-8")
                    paths.append(path)
            self.assertEqual(ci_artifact_inputs(root), paths)
            for path in paths:
                body = path.read_text(encoding="utf-8")
                for invalid in ("", "not JSON\n", '{"Action":"start"}\n'):
                    with self.subTest(path=path.name, invalid=invalid):
                        path.write_text(invalid, encoding="utf-8")
                        with self.assertRaises(ValueError):
                            ci_artifact_inputs(root)
                path.write_text(body, encoding="utf-8")
                path.unlink()
                with self.assertRaisesRegex(ValueError, "missing or empty"):
                    ci_artifact_inputs(root)
                path.write_text(body, encoding="utf-8")

    def test_workflow_requires_complete_evidence_before_writing(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci-shard-drift.yaml").read_text(encoding="utf-8"))
        step = next(step for step in workflow["jobs"]["drift"]["steps"]
                    if step.get("name") == "Refresh weights and check the budget")
        self.assertIn('--write --ci-artifacts "$RUNNER_TEMP/timing" || exit $?', step["run"])


if __name__ == "__main__":
    unittest.main()

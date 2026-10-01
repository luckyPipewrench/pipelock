# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Terminal report contracts using inert observations and real private files."""
import ast
import copy
import json
from pathlib import Path
import tempfile
import unittest

import managed
import run


class TerminalReportTests(unittest.TestCase):
    def test_late_failures_remove_aggregate_claim_and_preserve_raw_observations(self):
        for mode, claim in (
            ("sandbox", "strict_launch_and_own_endpoint_boundary_observed"),
            ("managed-contain", "managed_launch_and_own_endpoint_boundary_observed"),
        ):
            for failure in ("fixture accounting failed", "workspace cleanup failed", "late interruption"):
                with self.subTest(mode=mode, failure=failure), tempfile.TemporaryDirectory() as temporary:
                    report = {"mode": mode, "status": "fail", "containment": claim,
                              "failure": failure, "lifecycle": {"cleanup_complete": True},
                              "observations": {"namespace_distinct": True, "health_arrivals": 3}}
                    if failure == "late interruption":
                        report["interrupted_signal"] = 15
                    original = copy.deepcopy(report)
                    path = Path(temporary) / "summary.json"
                    run.write_final_report(path, report)
                    expected = {**original, "containment": "not_established"}
                    # The same normalized object drives the console summary.
                    self.assertEqual(report, expected)
                    self.assertEqual(json.loads(path.read_text()), expected)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_success_incomplete_refusal_and_proxy_only_states_are_unambiguous(self):
        cases = [
            ("complete", "strict_launch_and_own_endpoint_boundary_observed", "strict_launch_and_own_endpoint_boundary_observed"),
            ("complete", "managed_launch_and_own_endpoint_boundary_observed", "managed_launch_and_own_endpoint_boundary_observed"),
            ("incomplete", "managed_launch_and_own_endpoint_boundary_observed", "not_established"),
            ("refused", "strict_launch_and_own_endpoint_boundary_observed", "not_established"),
            ("fail", "not_established", "not_established"),
            ("fail", "not_tested_proxy_only", "not_tested_proxy_only"),
            ("complete", "not_tested_proxy_only", "not_tested_proxy_only"),
        ]
        for status, before, after in cases:
            with self.subTest(status=status, before=before), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "summary.json"
                report = {"status": status, "containment": before}
                run.write_final_report(path, report)
                self.assertEqual(json.loads(path.read_text()), {"status": status, "containment": after})
                self.assertEqual(report["containment"], after)

    def test_both_entrypoints_finalize_their_summary_through_the_shared_writer(self):
        # Structural wiring witness only; this does not claim a managed host or
        # Chromium ran. Behavioral assertions above inspect actual saved JSON.
        self.assertIs(managed.write_final_report, run.write_final_report)
        for module in (run, managed):
            tree = ast.parse(Path(module.__file__).read_text())
            summary_calls = []
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                if any(isinstance(part, ast.Constant) and part.value == "summary.json"
                       for part in ast.walk(node.args[0])):
                    summary_calls.append(node)
            self.assertEqual(len(summary_calls), 1, module.__name__)
            self.assertIsInstance(summary_calls[0].func, ast.Name)
            self.assertEqual(summary_calls[0].func.id, "write_final_report")


if __name__ == "__main__":
    unittest.main()

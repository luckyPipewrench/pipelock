#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0


import io
import json
import sys
import unittest
from unittest import mock

import summarize_go_test_json


class SummarizeGoTestJSONTest(unittest.TestCase):
    def test_summarizes_slowest_packages_and_failure_tail(self):
        lines = [
            json.dumps(
                {
                    "Time": "2026-07-05T00:00:00Z",
                    "Action": "pass",
                    "Package": "example.com/fast",
                    "Elapsed": 0.25,
                }
            ),
            json.dumps(
                {
                    "Time": "2026-07-05T00:00:01Z",
                    "Action": "output",
                    "Package": "example.com/slow",
                    "Output": "useful failure line\n",
                }
            ),
            json.dumps(
                {
                    "Time": "2026-07-05T00:00:02Z",
                    "Action": "fail",
                    "Package": "example.com/slow",
                    "Elapsed": 61.2,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(results, label="unit", top=2, out=out)

        summary = out.getvalue()
        self.assertIn("Go test package timing (unit)", summary)
        self.assertIn("1m01.2s  fail  example.com/slow", summary)
        self.assertIn("0.2s  pass  example.com/fast", summary)
        self.assertIn("failed package output tails:", summary)
        self.assertIn("useful failure line", summary)

    def test_preserves_failed_test_output_when_package_tail_evicted(self):
        lines = [
            json.dumps(
                {
                    "Action": "run",
                    "Package": "example.com/proxy",
                    "Test": "TestFlaky",
                }
            ),
            json.dumps(
                {
                    "Action": "output",
                    "Package": "example.com/proxy",
                    "Test": "TestFlaky",
                    "Output": "    proxy_test.go:42: lost early failure\n",
                }
            ),
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/proxy",
                    "Test": "TestFlaky",
                    "Elapsed": 0.75,
                }
            ),
        ]
        for i in range(summarize_go_test_json.FAILED_OUTPUT_LIMIT + 5):
            lines.append(
                json.dumps(
                    {
                        "Action": "output",
                        "Package": "example.com/proxy",
                        "Output": f"later parallel output {i}\n",
                    }
                )
            )
        lines.append(
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/proxy",
                    "Elapsed": 10.0,
                }
            )
        )

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(results, label="unit", top=1, out=out)

        summary = out.getvalue()
        self.assertIn("failed tests:", summary)
        self.assertIn("--- example.com/proxy TestFlaky (0.8s) ---", summary)
        self.assertIn("lost early failure", summary)

    def test_omits_failed_tests_header_for_package_only_failure(self):
        lines = [
            json.dumps(
                {
                    "Action": "output",
                    "Package": "example.com/broken",
                    "Output": "compile failed\n",
                }
            ),
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/broken",
                    "Elapsed": 0.1,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(results, label="unit", top=1, out=out)

        summary = out.getvalue()
        self.assertNotIn("failed tests:", summary)
        self.assertIn("failed package output tails:", summary)
        self.assertIn("compile failed", summary)

    def test_does_not_duplicate_test_output_as_package_tail(self):
        lines = [
            json.dumps(
                {
                    "Action": "output",
                    "Package": "example.com/proxy",
                    "Test": "TestProxy",
                    "Output": "    proxy_test.go:42: failed once\n",
                }
            ),
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/proxy",
                    "Test": "TestProxy",
                    "Elapsed": 0.5,
                }
            ),
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/proxy",
                    "Elapsed": 0.5,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(results, label="unit", top=1, out=out)

        summary = out.getvalue()
        self.assertIn("failed tests:", summary)
        self.assertIn("--- example.com/proxy TestProxy (0.5s) ---", summary)
        self.assertEqual(summary.count("failed once"), 1)
        self.assertNotIn("failed package output tails:", summary)

    def test_ignores_non_json_lines(self):
        results = summarize_go_test_json.parse_events(
            [
                "not json",
                json.dumps(
                    {
                        "Action": "pass",
                        "Package": "example.com/pkg",
                        "Elapsed": 1,
                    }
                ),
            ]
        )

        self.assertEqual(results["example.com/pkg"].action, "pass")

    def test_main_returns_nonzero_when_final_package_action_fails(self):
        lines = "\n".join(
            [
                json.dumps(
                    {
                        "Action": "fail",
                        "Package": "example.com/pkg",
                        "Elapsed": 1,
                    }
                ),
                "",
            ]
        )

        with (
            mock.patch.object(sys, "argv", ["summarize_go_test_json.py"]),
            mock.patch.object(sys, "stdin", io.StringIO(lines)),
            mock.patch.object(sys, "stdout", io.StringIO()),
        ):
            status = summarize_go_test_json.main()

        self.assertEqual(status, 1)

    def test_main_allows_retry_stream_when_final_package_action_passes(self):
        lines = "\n".join(
            [
                json.dumps(
                    {
                        "Action": "fail",
                        "Package": "example.com/pkg",
                        "Elapsed": 1,
                    }
                ),
                json.dumps(
                    {
                        "Action": "pass",
                        "Package": "example.com/pkg",
                        "Elapsed": 1,
                    }
                ),
                "",
            ]
        )

        with (
            mock.patch.object(sys, "argv", ["summarize_go_test_json.py"]),
            mock.patch.object(sys, "stdin", io.StringIO(lines)),
            mock.patch.object(sys, "stdout", io.StringIO()),
        ):
            status = summarize_go_test_json.main()

        self.assertEqual(status, 0)

    def test_format_duration_handles_subsecond_and_minute_rollover(self):
        self.assertEqual(summarize_go_test_json.format_duration(0.25), "0.2s")
        self.assertEqual(summarize_go_test_json.format_duration(61.2), "1m01.2s")
        self.assertEqual(summarize_go_test_json.format_duration(600.0), "10m00.0s")

    def test_main_rejects_non_positive_top(self):
        with (
            mock.patch.object(sys, "argv", ["summarize_go_test_json.py", "--top", "0"]),
            mock.patch.object(sys, "stderr", io.StringIO()) as stderr,
            self.assertRaises(SystemExit) as raised,
        ):
            summarize_go_test_json.main()

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--top must be at least 1", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

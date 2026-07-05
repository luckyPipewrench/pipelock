#!/usr/bin/env python3

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

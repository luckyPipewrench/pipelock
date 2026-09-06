#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0


import io
import json
import sys
import tempfile
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

    def test_default_output_uses_current_stdout(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out):
            summarize_go_test_json.print_summary({}, label="unit", top=1)

        self.assertIn("Go test package timing (unit)", out.getvalue())

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

    def test_preserves_running_test_output_when_package_times_out(self):
        lines = [
            json.dumps(
                {
                    "Action": "run",
                    "Package": "example.com/conductor",
                    "Test": "TestServe",
                }
            ),
            json.dumps(
                {
                    "Action": "output",
                    "Package": "example.com/conductor",
                    "Test": "TestServe",
                    "Output": "goroutine 42 [chan receive]:\\n",
                }
            ),
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/conductor",
                    "Elapsed": 900,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(results, label="unit", top=1, out=out)

        summary = out.getvalue()
        self.assertIn("interrupted test output:", summary)
        self.assertIn("--- example.com/conductor TestServe ---", summary)
        self.assertIn("goroutine 42 [chan receive]:", summary)

    def test_full_failed_output_preserves_complete_timeout_stack(self):
        lines = [
            json.dumps(
                {
                    "Action": "run",
                    "Package": "example.com/conductor",
                    "Test": "TestServe",
                }
            )
        ]
        for index in range(summarize_go_test_json.FAILED_OUTPUT_LIMIT + 21):
            lines.append(
                json.dumps(
                    {
                        "Action": "output",
                        "Package": "example.com/conductor",
                        "Test": "TestServe",
                        "Output": f"stack line {index}\\n",
                    }
                )
            )
        lines.append(
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/conductor",
                    "Elapsed": 900,
                }
            )
        )

        out = io.StringIO()
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as captured:
            captured.write("\n".join(lines) + "\n")
            captured.seek(0)
            with (
                mock.patch.object(sys, "stdout", out),
                mock.patch.object(
                    summarize_go_test_json.tempfile,
                    "TemporaryFile",
                    side_effect=AssertionError("regular input must be replayed directly"),
                ),
            ):
                summarize_go_test_json.summarize_full_output(
                    captured, label="unit", top=1, top_tests=25
                )

        summary = out.getvalue()
        self.assertIn("stack line 0", summary)
        self.assertIn("stack line 50", summary)
        self.assertIn("stack line 100", summary)

    def test_full_output_streams_large_passed_output_without_retaining_it(self):
        import tracemalloc

        class DiscardOutput:
            def write(self, value):
                return len(value)
            def flush(self):
                pass

        def events():
            payload = json.dumps({"Action": "output", "Package": "example.com/pass", "Output": "x" * 8192})
            for _ in range(2048):
                yield payload
            yield json.dumps({"Action": "pass", "Package": "example.com/pass"})
            yield json.dumps({"Action": "fail", "Package": "example.com/fail"})

        tracemalloc.start()
        try:
            with (
                mock.patch.object(sys, "stdout", DiscardOutput()),
                mock.patch.object(
                    summarize_go_test_json.tempfile,
                    "TemporaryFile",
                    wraps=tempfile.TemporaryFile,
                ) as captured,
            ):
                results = summarize_go_test_json.summarize_full_output(
                    events(), label="unit", top=1, top_tests=1
                )
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 4 * 1024 * 1024)
        self.assertFalse(results["example.com/pass"].output)
        captured.assert_called_once_with(mode="w+t", encoding="utf-8")

    def test_full_output_preserves_malformed_text_and_escapes_controls(self):
        lines = [
            "toolchain prelude\x1b[2J\n",
            json.dumps({"Action": "output", "Package": "example.com/fail", "Output": "stack\x1b[2J\n"}),
            json.dumps({"Action": "fail", "Package": "example.com/fail"}),
            json.dumps({"Action": "output", "Package": "example.com/pass", "Output": "unrelated passed output"}),
            json.dumps({"Action": "pass", "Package": "example.com/pass"}),
        ]
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out):
            summarize_go_test_json.summarize_full_output(lines, label="unit", top=1, top_tests=1)
        self.assertIn("unparsed diagnostic: toolchain prelude", out.getvalue())
        self.assertIn("stack\\u001b[2J", out.getvalue())
        self.assertNotIn("\x1b", out.getvalue())
        self.assertNotIn("unrelated passed output", out.getvalue())

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
                "null",
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

    def test_summarizes_slowest_tests_with_parallelism_caveat(self):
        lines = [
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/proxy",
                    "Test": "TestFast",
                    "Elapsed": 1.0,
                }
            ),
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/proxy",
                    "Test": "TestSlow",
                    "Elapsed": 12.5,
                }
            ),
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/proxy",
                    "Elapsed": 13.0,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(
            results, label="unit", top=1, top_tests=1, out=out
        )

        summary = out.getvalue()
        self.assertIn("slowest 1 tests:", summary)
        self.assertIn("12.5s  pass  example.com/proxy TestSlow", summary)
        self.assertNotIn("example.com/proxy TestFast", summary)
        self.assertIn("wall-clock attribution, not exclusive CPU time", summary)

    def test_escapes_terminal_controls_in_report_names(self):
        lines = [
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/\x1b[2Jproxy",
                    "Test": "TestSlow\nspoof",
                    "Elapsed": 1.0,
                }
            ),
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/\x1b[2Jproxy",
                    "Elapsed": 1.0,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(
            results, label="unit\x1b[0m", top=1, top_tests=1, out=out
        )

        summary = out.getvalue()
        self.assertNotIn("\x1b", summary)
        self.assertIn("unit\\u001b[0m", summary)
        self.assertIn("example.com/\\u001b[2Jproxy TestSlow\\u000aspoof", summary)

    def test_escapes_terminal_controls_in_failure_output(self):
        lines = [
            json.dumps(
                {
                    "Action": "output",
                    "Package": "example.com/proxy",
                    "Test": "TestFailure",
                    "Output": "test output\x1b[2J\rspoof\n",
                }
            ),
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/proxy",
                    "Test": "TestFailure",
                    "Elapsed": 1.0,
                }
            ),
            json.dumps(
                {
                    "Action": "output",
                    "Package": "example.com/proxy",
                    "Output": "package output\x1b[0m\n",
                }
            ),
            json.dumps(
                {
                    "Action": "fail",
                    "Package": "example.com/proxy",
                    "Elapsed": 1.0,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(results, label="unit", top=1, out=out)

        summary = out.getvalue()
        self.assertNotIn("\x1b", summary)
        self.assertNotIn("\r", summary)
        self.assertIn("test output\\u001b[2J\\u000dspoof", summary)
        self.assertIn("package output\\u001b[0m", summary)

    def test_invalid_elapsed_values_fall_back_without_stopping_summary(self):
        lines = [
            json.dumps(
                {"Action": "pass", "Package": "example.com/bool", "Elapsed": True}
            ),
            '{"Action":"pass","Package":"example.com/infinite","Elapsed":1e400}',
            json.dumps(
                {"Action": "pass", "Package": "example.com/negative", "Elapsed": -1}
            ),
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/valid",
                    "Elapsed": 1.5,
                }
            ),
        ]

        results = summarize_go_test_json.parse_events(lines)
        out = io.StringIO()
        summarize_go_test_json.print_summary(results, label="unit", top=4, out=out)

        summary = out.getvalue()
        self.assertIn("0.0s  pass  example.com/bool", summary)
        self.assertIn("0.0s  pass  example.com/infinite", summary)
        self.assertIn("0.0s  pass  example.com/negative", summary)
        self.assertIn("1.5s  pass  example.com/valid", summary)

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

    def test_main_allows_failed_packages_when_requested(self):
        lines = json.dumps(
            {"Action": "fail", "Package": "example.com/pkg", "Elapsed": 1}
        )

        with (
            mock.patch.object(
                sys,
                "argv",
                ["summarize_go_test_json.py", "--allow-failed-packages"],
            ),
            mock.patch.object(sys, "stdin", io.StringIO(lines)),
            mock.patch.object(sys, "stdout", io.StringIO()),
        ):
            status = summarize_go_test_json.main()

        self.assertEqual(status, 0)

    def test_main_sanitizes_raw_controls_without_parsing(self):
        out = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["summarize_go_test_json.py", "--sanitize-raw"]),
            mock.patch.object(sys, "stdin", io.StringIO("bad\x1b[2J\rline\n")),
            mock.patch.object(sys, "stdout", out),
        ):
            status = summarize_go_test_json.main()

        self.assertEqual(status, 0)
        self.assertNotIn("\x1b", out.getvalue())
        self.assertNotIn("\r", out.getvalue())
        self.assertIn("bad\\u001b[2J\\u000dline", out.getvalue())

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

    def test_main_rejects_non_positive_top_tests(self):
        with (
            mock.patch.object(
                sys, "argv", ["summarize_go_test_json.py", "--top-tests", "0"]
            ),
            mock.patch.object(sys, "stderr", io.StringIO()) as stderr,
            self.assertRaises(SystemExit) as raised,
        ):
            summarize_go_test_json.main()

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--top-tests must be at least 1", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

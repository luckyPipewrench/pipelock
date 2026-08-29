#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0


import io
import json
import unittest

import stream_go_test_json


class StreamGoTestJSONTest(unittest.TestCase):
    def test_reports_first_event_lead_stream_span_and_tail(self):
        readings = iter([10.0, 12.5, 15.0, 16.0])
        lines = [
            "not json\n",
            "null\n",
            json.dumps({"Action": "start", "Package": "example.com/proxy"}) + "\n",
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/proxy",
                    "Elapsed": 2.0,
                }
            )
            + "\n",
        ]
        raw = io.StringIO()
        out = io.StringIO()

        stream_go_test_json.stream_events(
            lines,
            raw=raw,
            label="proxy",
            out=out,
            clock=lambda: next(readings),
        )

        self.assertEqual(raw.getvalue(), "".join(lines))
        output = out.getvalue()
        self.assertIn("[proxy] pass     2.0s example.com/proxy", output)
        self.assertIn("first JSON lead: 2.5s", output)
        self.assertIn("JSON stream span: 2.5s", output)
        self.assertIn("post-stream tail: 1.0s", output)

    def test_empty_stream_reports_zero_timings(self):
        readings = iter([3.0, 8.0])
        out = io.StringIO()

        stream_go_test_json.stream_events(
            [],
            raw=io.StringIO(),
            label="empty",
            out=out,
            clock=lambda: next(readings),
        )

        self.assertIn(
            "first JSON lead: 0.0s; JSON stream span: 0.0s; post-stream tail: 0.0s",
            out.getvalue(),
        )

    def test_ignores_non_string_action_and_escapes_terminal_controls(self):
        readings = iter([1.0, 2.0, 3.0, 4.0])
        lines = [
            json.dumps({"Action": [], "Package": "example.com/ignored"}) + "\n",
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/\x1b[2Jproxy",
                    "Elapsed": 1.0,
                }
            )
            + "\n",
        ]
        out = io.StringIO()

        stream_go_test_json.stream_events(
            lines,
            raw=io.StringIO(),
            label="proxy\x1b[0m",
            out=out,
            clock=lambda: next(readings),
        )

        output = out.getvalue()
        self.assertNotIn("\x1b", output)
        self.assertIn("[proxy\\u001b[0m] pass", output)
        self.assertIn("example.com/\\u001b[2Jproxy", output)

    def test_invalid_elapsed_values_fall_back_without_stopping_summary(self):
        readings = iter([1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
        lines = [
            json.dumps(
                {"Action": "pass", "Package": "example.com/bool", "Elapsed": True}
            )
            + "\n",
            '{"Action":"pass","Package":"example.com/infinite","Elapsed":1e400}\n',
            json.dumps(
                {"Action": "pass", "Package": "example.com/negative", "Elapsed": -1}
            )
            + "\n",
            json.dumps(
                {
                    "Action": "pass",
                    "Package": "example.com/valid",
                    "Elapsed": 1.5,
                }
            )
            + "\n",
        ]
        out = io.StringIO()

        stream_go_test_json.stream_events(
            lines,
            raw=io.StringIO(),
            label="proxy",
            out=out,
            clock=lambda: next(readings),
        )

        output = out.getvalue()
        self.assertIn("0.0s example.com/bool", output)
        self.assertIn("0.0s example.com/infinite", output)
        self.assertIn("0.0s example.com/negative", output)
        self.assertIn("1.5s example.com/valid", output)
        self.assertIn("first JSON lead:", output)


if __name__ == "__main__":
    unittest.main()

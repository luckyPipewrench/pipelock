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


if __name__ == "__main__":
    unittest.main()

# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""YAML merge precedence and explicit duplicate-key contracts."""

import unittest

from yaml_contracts import UniqueKeyLoader, WorkflowLoader, yaml


class YAMLContractsTest(unittest.TestCase):
    def load(self, text):
        return yaml.load(text, Loader=UniqueKeyLoader)

    def test_merge_and_explicit_override(self):
        value = self.load("base: &base {a: 1, b: 2}\nresult: {<<: *base, a: 3}")
        self.assertEqual(value["result"], {"a": 3, "b": 2})

    def test_merge_sequence_precedence_and_reuse(self):
        value = self.load("a: &a {x: 1}\nb: &b {x: 2, y: 3}\nr: {<<: [*a, *b]}\ns: {<<: *b}")
        self.assertEqual(value["r"], {"x": 1, "y": 3})
        self.assertEqual(value["s"], {"x": 2, "y": 3})

    def test_explicit_duplicates_rejected(self):
        for text in (
            "a: 1\na: 2", "base: &b {a: 1, a: 2}\nr: {<<: *b}",
            "base: &b {a: 1}\nr: {<<: *b, a: 2, a: 3}",
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "duplicate YAML key"):
                self.load(text)

    def test_quoted_merge_key_is_literal(self):
        self.assertEqual(self.load("'<<': literal"), {"<<": "literal"})

    def test_invalid_merge_rejected(self):
        with self.assertRaises(yaml.YAMLError):
            self.load("result: {<<: scalar}")


class WorkflowContractsTest(YAMLContractsTest):
    def load(self, text):
        return yaml.load(text, Loader=WorkflowLoader)

    def test_plain_core_scalars(self):
        for text in ("on", "off", "yes", "no", "2026-01-01", "1:20", "1_000"):
            with self.subTest(text=text):
                self.assertEqual(self.load(text), text)
        for text, value in (("true", True), ("FALSE", False), ("012", 12),
                            ("0o12", 10), ("0x12", 18), ("1e2", 100.0),
                            ("null", None)):
            with self.subTest(text=text):
                self.assertEqual(self.load(text), value)
                self.assertIs(type(self.load(text)), type(value))
        self.assertEqual(self.load("on: push"), {"on": "push"})
        self.assertEqual(self.load("'false'"), "false")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the kill-switch source-count docs check."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_kill_switch_source_count as check

SOURCES_GO = """package killswitch

func (c *Controller) Sources() map[string]bool {
	sources := map[string]bool{
		"config": true,
		"api":    false,
		"signal": false,
	}
	if rt.sentinelFile != "" {
		sources["sentinel"] = true
	} else {
		sources["sentinel"] = false
	}
	return sources
}
"""


def make_root(readme: str) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "internal" / "killswitch").mkdir(parents=True)
    (root / "internal" / "killswitch" / "killswitch.go").write_text(SOURCES_GO, encoding="utf-8")
    (root / "README.md").write_text(readme, encoding="utf-8")
    return root


class KillSwitchSourceCountTest(unittest.TestCase):
    def test_count_comes_from_sources_function(self):
        self.assertEqual(check.expected_source_count(make_root("")), 4)

    def test_matching_word_and_digit_counts_pass(self):
        root = make_root("The kill switch has four independent activation sources.\nKill switch (4 sources)\n")
        self.assertEqual(check.stale_claims(root, 4), [])

    def test_any_wrong_phrasing_fails(self):
        for line in (
            "The kill switch has seven independent sources.",
            "Emergency deny-all (3 sources)",
            "kill switch: all five activation sources",
        ):
            with self.subTest(line=line):
                self.assertEqual(len(check.stale_claims(make_root(line), 4)), 1)

    def test_subset_and_unrelated_phrases_are_ignored(self):
        root = make_root(
            "The kill switch stays off when its three sources are false.\n"
            "The license check reads three sources in priority order.\n"
        )
        self.assertEqual(check.stale_claims(root, 4), [])

    def test_repository_docs_match_the_code(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(check.stale_claims(root, check.expected_source_count(root)), [])


if __name__ == "__main__":
    unittest.main()

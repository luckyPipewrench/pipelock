# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/bench-compare.awk, the check-bench-regression.sh comparator."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

AWK = Path(__file__).resolve().parent / "bench-compare.awk"


def _line(name: str, nsop: int) -> str:
    return f"{name}-8\t1000\t{nsop} ns/op\t0 B/op\t0 allocs/op\n"


class BenchCompareTest(unittest.TestCase):
    def run_compare(self, base: str, cur: str) -> tuple[int, str, list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "base").write_text(base)
            (d / "cur").write_text(cur)
            missing = d / "missing"
            missing.write_text("")
            proc = subprocess.run(
                ["awk", "-v", "threshold=50", "-v", f"missing={missing}", "-f", str(AWK),
                 str(d / "base"), str(d / "cur")],
                capture_output=True, text=True, check=False,
            )
            return proc.returncode, proc.stdout, sorted(missing.read_text().split())

    def test_missing_baseline_name_is_reported_even_when_survivor_improves(self) -> None:
        base = _line("BenchmarkAlpha", 100) + _line("BenchmarkBeta", 100)
        rc, out, missing = self.run_compare(base, _line("BenchmarkAlpha", 90))
        self.assertEqual((rc, out), (0, ""))
        self.assertEqual(missing, ["BenchmarkBeta"])

    def test_complete_matching_set_reports_nothing(self) -> None:
        base = _line("BenchmarkAlpha", 100) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 90) + _line("BenchmarkBeta", 90)
        self.assertEqual(self.run_compare(base, cur), (0, "", []))

    def test_regression_above_threshold_is_reported(self) -> None:
        base = _line("BenchmarkAlpha", 100) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 160) + _line("BenchmarkBeta", 90)
        self.assertEqual(self.run_compare(base, cur), (0, "BenchmarkAlpha +60.00%\n", []))

    def test_repeated_samples_do_not_create_missing_names(self) -> None:
        base = _line("BenchmarkAlpha", 100) * 3
        cur = _line("BenchmarkAlpha", 120) + _line("BenchmarkAlpha", 95)
        self.assertEqual(self.run_compare(base, cur), (0, "", []))

    def test_rise_from_zero_baseline_is_reported(self) -> None:
        base = _line("BenchmarkAlpha", 0) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 5) + _line("BenchmarkBeta", 100)
        self.assertEqual(
            self.run_compare(base, cur),
            (0, "BenchmarkAlpha rose from a 0 ns/op baseline to 5 ns/op\n", []),
        )

    def test_zero_baseline_that_stays_zero_is_not_reported(self) -> None:
        base = _line("BenchmarkAlpha", 0) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 0) + _line("BenchmarkBeta", 100)
        self.assertEqual(self.run_compare(base, cur), (0, "", []))

    def test_zero_baseline_overlap_alone_is_still_overlap(self) -> None:
        base = _line("BenchmarkAlpha", 0)
        self.assertEqual(self.run_compare(base, _line("BenchmarkAlpha", 0)), (0, "", []))

    def test_no_overlap_exits_3(self) -> None:
        rc, _, missing = self.run_compare(_line("BenchmarkAlpha", 100), _line("BenchmarkGamma", 100))
        self.assertEqual(rc, 3)
        self.assertEqual(missing, ["BenchmarkAlpha"])


if __name__ == "__main__":
    unittest.main()

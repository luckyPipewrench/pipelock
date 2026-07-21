# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Adversarial tests for the CI go-test retry wrapper."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "ci-test-with-retry.sh"


def run_wrapper(
    script: str, *, packages: str = "example.com/p/pkg", args: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env["CI_RETRY_STATE"] = str(Path(tmp) / "state")
        cmd = [
            "bash",
            str(WRAPPER),
            "--packages",
            packages,
            "--",
            "bash",
            "-c",
            script,
            "fake-go",
            *(args or []),
        ]
        return subprocess.run(
            cmd,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )


class TestCiTestWithRetry(unittest.TestCase):
    def test_retry_pass_race_output_fails_closed_even_with_zero_exit(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Output":"panic: test timed out after 15m0s\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":900}'
  exit 1
fi
printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Output":"WARNING: DATA RACE\n"}'
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("retry pass reported WARNING: DATA RACE", result.stderr)

    def test_panic_that_only_mentions_timed_out_is_not_starvation(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Output":"panic: test timed out after cleanup corruption\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
  exit 1
fi
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("first pass contained a non-timeout panic", result.stderr)

    def test_go_timeout_panic_can_retry_once(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Output":"panic: test timed out after 15m0s\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":900}'
  exit 1
fi
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("failed then passed on rerun", result.stderr)

    def test_coverage_retry_requires_recreated_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            coverage = str(Path(tmp) / "coverage.out")
            result = run_wrapper(
                rf'''
state=${{CI_RETRY_STATE:?}}
if [ ! -e "$state" ]; then
  : >"$state"
  printf 'mode: set\n' >{coverage!r}
  printf '%s\n' '{{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}}'
  exit 1
fi
printf '%s\n' '{{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}}'
exit 0
''',
                args=[f"-coverprofile={coverage}"],
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("coverage retry", result.stderr)


if __name__ == "__main__":
    unittest.main()

# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Adversarial tests for the CI go-test retry wrapper."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "ci-test-with-retry.sh"


def run_wrapper(
    script: str,
    *,
    packages: str = "example.com/p/pkg",
    args: list[str] | None = None,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env["CI_RETRY_STATE"] = str(Path(tmp) / "state")
        env.update(env_overrides or {})
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
    def test_waits_for_capture_before_inspecting_race_output(self) -> None:
        real_tee = shutil.which("tee")
        self.assertIsNotNone(real_tee)

        with tempfile.TemporaryDirectory() as tmp:
            fake_tee = Path(tmp) / "tee"
            fake_tee.write_text(
                f'#!/bin/sh\nsleep 0.2\nexec "{real_tee}" "$@"\n', encoding="utf-8"
            )
            fake_tee.chmod(0o700)
            result = run_wrapper(
                r'''
printf '%s\n' 'WARNING: DATA RACE'
exit 1
''',
                env_overrides={"PATH": f"{tmp}:{os.environ['PATH']}"},
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("first pass reported WARNING: DATA RACE", result.stderr)

    def test_capture_failure_cannot_be_retried_to_green(self) -> None:
        real_tee = shutil.which("tee")
        self.assertIsNotNone(real_tee)

        with tempfile.TemporaryDirectory() as tmp:
            fake_tee = Path(tmp) / "tee"
            fake_tee.write_text(
                f'''#!/bin/sh
"{real_tee}" "$@"
status=$?
case "$*" in
  *first.stdout*) exit 7 ;;
esac
exit "$status"
''',
                encoding="utf-8",
            )
            fake_tee.chmod(0o700)
            result = run_wrapper(
                "exit 0",
                env_overrides={"PATH": f"{tmp}:{os.environ['PATH']}"},
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("failed to capture complete test output", result.stderr)
        self.assertNotIn("FLAKE RETRY", result.stderr)

    def test_child_exit_125_is_not_mistaken_for_capture_failure(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestHang","Output":"panic: test timed out after 15m0s\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
  exit 125
fi
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("failed then passed on rerun", result.stderr)

    def test_ordinary_assertion_failure_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestPolicy","Output":"policy_test.go:42: got allow, want block\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Test":"TestPolicy","Elapsed":1}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
  exit 1
fi
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("was not a verified go test timeout", result.stderr)
        self.assertNotIn("FLAKE RETRY", result.stderr)

    def test_raw_timeout_lookalike_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' 'panic: test timed out after 15m0s'
printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
exit 1
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("was not a verified go test timeout", result.stderr)
        self.assertNotIn("FLAKE RETRY", result.stderr)

    def test_testmain_timeout_spoof_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Output":"panic: test timed out after 15m0s\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
  exit 1
fi
exit 0
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("was not a verified go test timeout", result.stderr)
        self.assertNotIn("FLAKE RETRY", result.stderr)

    def test_timeout_cannot_launder_another_packages_assertion_failure(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/slow","Test":"TestHang","Output":"panic: test timed out after 15m0s\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/slow","Elapsed":900}'
  printf '%s\n' '{"Action":"output","Package":"example.com/p/policy","Test":"TestPolicy","Output":"got allow, want block\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/policy","Test":"TestPolicy","Elapsed":1}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/policy","Elapsed":1}'
  exit 1
fi
exit 0
''',
            packages="example.com/p/slow example.com/p/policy",
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("was not a verified go test timeout", result.stderr)
        self.assertNotIn("FLAKE RETRY", result.stderr)

    def test_test_failure_in_timed_out_package_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestHang","Output":"panic: test timed out after 15m0s\n"}'
printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Test":"TestPolicy","Elapsed":1}'
printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":900}'
exit 1
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("was not a verified go test timeout", result.stderr)
        self.assertNotIn("FLAKE RETRY", result.stderr)

    def test_zero_duration_timeout_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestHang","Output":"panic: test timed out after 0m0s\n"}'
printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
exit 1
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("was not a verified go test timeout", result.stderr)
        self.assertNotIn("FLAKE RETRY", result.stderr)

    def test_retry_pass_race_output_fails_closed_even_with_zero_exit(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestHang","Output":"panic: test timed out after 15m0s\n"}'
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
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestHang","Output":"panic: test timed out after 15m0s\n"}'
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
  printf '%s\n' '{{"Action":"output","Package":"example.com/p/pkg","Test":"TestHang","Output":"panic: test timed out after 15m0s\n"}}'
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

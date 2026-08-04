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
        env["GITHUB_ACTIONS"] = "true"
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

    def test_assertion_message_with_cannot_is_not_misclassified_as_build_failure(
        self,
    ) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestPolicy","Output":"policy_test.go:42: cannot allow request\n"}'
printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Test":"TestPolicy","Elapsed":1}'
printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
exit 1
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("was not a verified go test timeout", result.stderr)
        self.assertNotIn("looked like a build/setup failure", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_structured_build_failure_is_still_refused(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Output":"pkg.go:42:2: undefined: missingSymbol\n"}'
printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}'
exit 1
'''
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("looked like a build/setup failure", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_incomplete_sigterm_without_test_failure_retries_once(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"run","Package":"example.com/p/pkg","Test":"TestSlow"}'
  kill -TERM "$$"
fi
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("confirmed empty before rerun", result.stderr)
        self.assertIn("first pass exited 143 during running test(s)", result.stderr)
        self.assertIn("does not prove the first attempt", result.stderr)
        self.assertIn("SIGTERM-interrupted shard passed on rerun", result.stderr)

    def test_sigterm_descendant_is_killed_before_retry(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
descendant_file="${state}.descendant"
ready_file="${state}.ready"
if [ ! -e "$state" ]; then
  : >"$state"
  DESCENDANT_READY="$ready_file" python3 -c 'import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(os.environ["DESCENDANT_READY"], "w").close(); time.sleep(3600)' </dev/null >/dev/null 2>&1 &
  echo "$!" >"$descendant_file"
  while [ ! -e "$ready_file" ]; do :; done
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"run","Package":"example.com/p/pkg","Test":"TestSlow"}'
  kill -TERM "$$"
fi
descendant=$(cat "$descendant_file")
if kill -0 "$descendant" 2>/dev/null; then
  kill -KILL "$descendant" 2>/dev/null || true
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Test":"TestOverlap","Elapsed":1}'
  exit 97
fi
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("sending KILL", result.stderr)
        self.assertIn("confirmed empty after KILL", result.stderr)
        self.assertNotIn("TestOverlap", result.stdout)

    def test_sigterm_outside_github_actions_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
printf '%s\n' '{"Action":"run","Package":"example.com/p/pkg","Test":"TestSlow"}'
exit 143
''',
            env_overrides={"GITHUB_ACTIONS": ""},
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_sigterm_with_unstructured_output_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
printf '%s\n' '{"Action":"run","Package":"example.com/p/pkg","Test":"TestSlow"}'
printf '%s\n' 'unstructured output whose meaning is unknown'
exit 143
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_sigterm_with_stderr_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
printf '%s\n' '{"Action":"run","Package":"example.com/p/pkg","Test":"TestSlow"}'
printf '%s\n' 'unattributed termination diagnostic' >&2
exit 143
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_sigterm_before_any_test_runs_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
exit 143
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_cleanup_failure_refuses_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bash_env = Path(tmp) / "bash-env"
            bash_env.write_text(
                r'''kill() {
  if [ "$1" = "-0" ]; then
    return 0
  fi
  builtin kill "$@" 2>/dev/null || true
}
''',
                encoding="utf-8",
            )
            result = run_wrapper(
                r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestSlow","Output":"=== RUN   TestSlow\n"}'
  kill -TERM "$$"
fi
printf '%s\n' 'RETRY RAN'
exit 0
''',
                env_overrides={"BASH_ENV": str(bash_env)},
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("remained live after KILL", result.stderr)
        self.assertNotIn("RETRY RAN", result.stdout)
        self.assertNotIn("rerunning", result.stderr)

    def test_sigterm_with_test_failure_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Test":"TestPolicy","Output":"--- FAIL: TestPolicy (0.01s)\n"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg","Test":"TestPolicy","Elapsed":1}'
  kill -TERM "$$"
fi
printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
exit 0
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_sigterm_with_failing_package_line_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"output","Package":"example.com/p/pkg","Output":"FAIL\texample.com/p/pkg\t1.00s\n"}'
  kill -TERM "$$"
fi
exit 0
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_sigterm_after_normal_package_completion_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}'
  exit 143
fi
exit 0
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_sigterm_after_skipped_package_completion_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"skip","Package":"example.com/p/pkg","Elapsed":1}'
  exit 143
fi
exit 0
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

    def test_sigterm_with_truncated_failure_event_is_not_retried(self) -> None:
        result = run_wrapper(
            r'''
state=${CI_RETRY_STATE:?}
if [ ! -e "$state" ]; then
  : >"$state"
  printf '%s\n' '{"Action":"start","Package":"example.com/p/pkg"}'
  printf '%s\n' '{"Action":"fail","Package":"example.com/p/pkg"'
  exit 143
fi
exit 0
'''
        )

        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn("evidence was not strict", result.stderr)
        self.assertNotIn("RETRY:", result.stderr)

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

    def test_coverage_retry_preserves_first_attempt_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            coverage = Path(tmp) / "coverage.out"
            first_coverage = Path(f"{coverage}.first-attempt")
            result = run_wrapper(
                rf'''
state=${{CI_RETRY_STATE:?}}
if [ ! -e "$state" ]; then
  : >"$state"
  printf 'mode: first\n' >{str(coverage)!r}
  printf '%s\n' '{{"Action":"output","Package":"example.com/p/pkg","Test":"TestHang","Output":"panic: test timed out after 15m0s\n"}}'
  printf '%s\n' '{{"Action":"fail","Package":"example.com/p/pkg","Elapsed":1}}'
  exit 1
fi
printf 'mode: retry\n' >{str(coverage)!r}
printf '%s\n' '{{"Action":"pass","Package":"example.com/p/pkg","Elapsed":1}}'
exit 0
''',
                args=[f"-coverprofile={coverage}"],
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(coverage.read_text(encoding="utf-8"), "mode: retry\n")
            self.assertEqual(
                first_coverage.read_text(encoding="utf-8"), "mode: first\n"
            )
            self.assertIn(str(first_coverage), result.stderr)


if __name__ == "__main__":
    unittest.main()

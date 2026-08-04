#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

# Run one CI go-test shard once, then retry a starvation-looking failure or a
# narrowly classified incomplete SIGTERM run once. DATA RACE, test failures,
# build/setup errors, and non-timeout panics fail closed because retrying those
# away would hide the bugs this CI job exists to catch.
#
# Guarantee: any failure visible in captured output prevents retry; a passing
# SIGTERM rerun does not prove the terminated attempt had no unflushed failure.
set -euo pipefail

usage() {
  echo "usage: ci-test-with-retry.sh --packages \"./pkg ...\" -- go test [flags]" >&2
}

packages=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --packages)
      if [ "$#" -lt 2 ]; then
        usage
        exit 2
      fi
      packages="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [ "$#" -eq 0 ] || [ -z "$packages" ]; then
  usage
  exit 2
fi

read -r -a package_args <<<"$packages"
if [ "${#package_args[@]}" -eq 0 ]; then
  echo "ci-test-with-retry: no packages were provided" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"

capture_failed=0
process_cleanup_failed=0
last_process_group=""
active_process_group=""

process_group_is_alive() {
  local process_group="$1"

  kill -0 -- "-${process_group}" 2>/dev/null
}

wait_for_process_group_exit() {
  local process_group="$1"
  local checks="$2"
  local check=0

  while [ "$check" -lt "$checks" ]; do
    if ! process_group_is_alive "$process_group"; then
      return 0
    fi
    sleep 1
    check=$((check + 1))
  done

  ! process_group_is_alive "$process_group"
}

cleanup_process_group() {
  local process_group="$1"
  local pass_label="$2"

  if ! process_group_is_alive "$process_group"; then
    return 0
  fi

  echo "PROCESS CLEANUP: ${pass_label} process group ${process_group} still has live processes; sending TERM" >&2
  kill -TERM -- "-${process_group}" 2>/dev/null || true
  if wait_for_process_group_exit "$process_group" 3; then
    echo "PROCESS CLEANUP: ${pass_label} process group ${process_group} confirmed empty after TERM" >&2
    return 0
  fi

  echo "PROCESS CLEANUP: ${pass_label} process group ${process_group} still has live processes after TERM grace period; sending KILL" >&2
  kill -KILL -- "-${process_group}" 2>/dev/null || true
  if wait_for_process_group_exit "$process_group" 3; then
    echo "PROCESS CLEANUP: ${pass_label} process group ${process_group} confirmed empty after KILL" >&2
    return 0
  fi

  echo "ci-test-with-retry: refusing continuation because ${pass_label} process group ${process_group} remained live after KILL" >&2
  return 1
}

cleanup_on_exit() {
  local status=$?

  trap - EXIT INT TERM
  if [ -n "$active_process_group" ]; then
    if ! cleanup_process_group "$active_process_group" "interrupted pass"; then
      status=1
    fi
  fi
  rm -rf "$tmpdir"
  exit "$status"
}

trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_and_tee() {
  local pass_label="$1"
  local stdout_file="$2"
  local stderr_file="$3"
  shift 3

  local stdout_fifo="${stdout_file}.fifo"
  local stderr_fifo="${stderr_file}.fifo"
  mkfifo "$stdout_fifo" "$stderr_fifo"

  tee "$stdout_file" <"$stdout_fifo" &
  local stdout_tee_pid=$!
  tee "$stderr_file" <"$stderr_fifo" >&2 &
  local stderr_tee_pid=$!

  # Python creates a new session without relying on non-standard setsid(1)
  # flags. execvp keeps its PID as the session and process-group ID.
  python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@" >"$stdout_fifo" 2>"$stderr_fifo" &
  local command_pid=$!
  last_process_group="$command_pid"
  active_process_group="$command_pid"

  local command_status=0
  wait "$command_pid" || command_status=$?

  # Descendants can inherit the FIFO writers. Clean the process group before
  # waiting for tee, or an orphan could keep capture open indefinitely.
  if ! cleanup_process_group "$command_pid" "$pass_label"; then
    process_cleanup_failed=1
    active_process_group=""
    rm -f -- "$stdout_fifo" "$stderr_fifo"
    return "$command_status"
  fi
  active_process_group=""

  local stdout_tee_status=0
  local stderr_tee_status=0
  wait "$stdout_tee_pid" || stdout_tee_status=$?
  wait "$stderr_tee_pid" || stderr_tee_status=$?
  rm -f -- "$stdout_fifo" "$stderr_fifo"

  if [ "$stdout_tee_status" -ne 0 ] || [ "$stderr_tee_status" -ne 0 ]; then
    echo "ci-test-with-retry: failed to capture complete test output" >&2
    capture_failed=1
  fi
  return "$command_status"
}

has_data_race() {
  local output_file="$1"

  grep -q 'WARNING: DATA RACE' "$output_file" ||
    (grep -q 'WARNING:' "$output_file" && grep -q 'DATA RACE' "$output_file")
}

has_non_timeout_panic() {
  local output_file="$1"

  awk '
    /panic:/ && $0 !~ /panic: test timed out after [0-9][0-9.hmsu]*((\\n)|"|$)/ {
      found=1
    }
    END { exit !found }
  ' "$output_file"
}

has_go_test_timeout() {
  local output_file="$1"

  python3 - "$output_file" <<'PY'
import json
import re
import sys

duration = r"(?P<duration>(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|s|m|h))+)"
timeout_re = re.compile(rf"^panic: test timed out after {duration}$")
timeout_packages = set()
failed_packages = set()
saw_test_failure = False

with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        package = event.get("Package")
        if not isinstance(package, str) or not package:
            continue
        if event.get("Action") == "fail":
            if event.get("Test"):
                saw_test_failure = True
            else:
                failed_packages.add(package)
            continue
        if event.get("Action") != "output":
            continue
        output = event.get("Output")
        test = event.get("Test")
        if isinstance(output, str) and isinstance(test, str) and test:
            match = timeout_re.fullmatch(output.rstrip("\r\n"))
            if match and any(char in "123456789" for char in match.group("duration")):
                timeout_packages.add(package)

verified = bool(failed_packages) and failed_packages <= timeout_packages and not saw_test_failure
raise SystemExit(0 if verified else 1)
PY
}

has_incomplete_sigterm() {
  local command_status="$1"
  local output_file="$2"
  local stderr_file="$3"

  if [ "$command_status" -ne 143 ]; then
    return 1
  fi
  if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    return 1
  fi
  if [ -s "$stderr_file" ]; then
    return 1
  fi

  python3 - "$output_file" <<'PY'
import json
import re
import sys

test_failure_re = re.compile(r"^\s*--- FAIL:")
package_failure_re = re.compile(r"^FAIL(?:\s|$)")
valid_actions = {"bench", "cont", "fail", "output", "pass", "pause", "run", "skip", "start"}
started_packages = set()
terminal_packages = set()
saw_running_test = set()
saw_failure = False
saw_invalid_event = False

with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            saw_invalid_event = True
            continue

        if not isinstance(event, dict):
            saw_invalid_event = True
            continue
        package = event.get("Package")
        action = event.get("Action")
        if (
            not isinstance(package, str)
            or not package
            or action not in valid_actions
        ):
            saw_invalid_event = True
            continue
        if action == "start":
            started_packages.add(package)
        if action == "run" and isinstance(event.get("Test"), str) and event["Test"]:
            saw_running_test.add(package)
        if action in {"pass", "fail", "skip"} and not event.get("Test"):
            terminal_packages.add(package)
        if action == "fail":
            saw_failure = True

        if action != "output":
            continue
        output = event.get("Output")
        if not isinstance(output, str):
            continue
        for output_line in output.splitlines():
            if test_failure_re.match(output_line) or package_failure_re.match(output_line):
                saw_failure = True

incomplete_packages = sorted(started_packages - terminal_packages)
if (
    saw_failure
    or saw_invalid_event
    or not incomplete_packages
    or not set(incomplete_packages) <= saw_running_test
):
    raise SystemExit(1)

for package in incomplete_packages:
    print(package)
PY
}

has_build_setup_failure() {
  local output_file="$1"

  python3 - "$output_file" <<'PY'
import json
import re
import sys

marker_re = re.compile(r"\b(?:build failed|cannot|undefined)\b", re.IGNORECASE)
raw_compiler_re = re.compile(r"^(?:# \S+|\S+\.go:\d+(?::\d+)?:)")
raw_build_context = False

with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if line.startswith("# "):
                raw_build_context = True
            if (
                (raw_build_context or raw_compiler_re.match(line))
                and marker_re.search(line)
            ):
                raise SystemExit(0)
            continue
        raw_build_context = False
        if event.get("Action") != "output" or event.get("Test"):
            continue
        output = event.get("Output")
        if not isinstance(output, str):
            continue
        structured_build_context = False
        for output_line in output.splitlines():
            if output_line.startswith("# "):
                structured_build_context = True
            if (
                (structured_build_context or raw_compiler_re.match(output_line))
                and marker_re.search(output_line)
            ):
                raise SystemExit(0)

raise SystemExit(1)
PY
}

refuse_forbidden_output() {
  local output_file="$1"
  local pass_label="$2"

  if has_data_race "$output_file"; then
    echo "ci-test-with-retry: refusing retry because ${pass_label} reported WARNING: DATA RACE" >&2
    return 0
  fi

  if has_build_setup_failure "$output_file"; then
    echo "ci-test-with-retry: refusing retry because ${pass_label} looked like a build/setup failure" >&2
    return 0
  fi

  if has_non_timeout_panic "$output_file"; then
    echo "ci-test-with-retry: refusing retry because ${pass_label} contained a non-timeout panic" >&2
    return 0
  fi

  return 1
}

first_stdout="$tmpdir/first.stdout"
first_stderr="$tmpdir/first.stderr"

set +e
run_and_tee "first pass" "$first_stdout" "$first_stderr" "$@" "${package_args[@]}"
first_status=$?
first_process_group="$last_process_group"
set -e

if [ "$capture_failed" -ne 0 ] || [ "$process_cleanup_failed" -ne 0 ]; then
  exit 1
fi

if [ "$first_status" -eq 0 ]; then
  exit 0
fi

combined_first="$tmpdir/first.combined"
cat "$first_stdout" "$first_stderr" >"$combined_first"

if refuse_forbidden_output "$combined_first" "first pass"; then
  exit "$first_status"
fi

retry_kind=""
failed_packages=()
incomplete_packages=()

if has_go_test_timeout "$first_stdout"; then
  retry_kind="timeout"
  mapfile -t failed_packages < <(
    python3 - "$first_stdout" <<'PY'
import json
import sys

failed = []
seen = set()
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("Action") != "fail" or event.get("Test"):
            continue
        package = event.get("Package")
        if isinstance(package, str) and package and package not in seen:
            seen.add(package)
            failed.append(package)

for package in failed:
    print(package)
PY
  )
else
  if [ "$first_status" -eq 143 ]; then
    incomplete_file="$tmpdir/incomplete-packages"
    if has_incomplete_sigterm "$first_status" "$first_stdout" "$first_stderr" >"$incomplete_file"; then
      retry_kind="sigterm"
      mapfile -t incomplete_packages <"$incomplete_file"
    else
      echo "ci-test-with-retry: refusing retry because SIGTERM evidence was not strict, structured, failure-free GitHub Actions output from an interrupted running test" >&2
      exit "$first_status"
    fi
  else
    echo "ci-test-with-retry: refusing retry because first pass was not a verified go test timeout" >&2
    exit "$first_status"
  fi
fi

retry_packages=("${failed_packages[@]}")
retry_scope="failed package(s)"
if [ "${#retry_packages[@]}" -eq 0 ]; then
  retry_packages=("${package_args[@]}")
  retry_scope="whole shard; no failed package list was isolated"
fi

coverage_profile=""
first_coverage_profile=""
cmd_args=("$@")
for ((i = 0; i < ${#cmd_args[@]}; i++)); do
  arg="${cmd_args[$i]}"
  if [[ "$arg" == -coverprofile || "$arg" == -coverprofile=* ]]; then
    if [[ "$arg" == -coverprofile=* ]]; then
      coverage_profile="${arg#-coverprofile=}"
    elif [ "$i" -lt "$((${#cmd_args[@]} - 1))" ]; then
      coverage_profile="${cmd_args[$((i + 1))]}"
    fi
    retry_packages=("${package_args[@]}")
    retry_scope="whole shard to preserve the complete coverage profile"
    break
  fi
done

failed_label="${failed_packages[*]:-${package_args[*]}}"
if [ "$retry_kind" = "sigterm" ]; then
  incomplete_label="${incomplete_packages[*]}"
  echo "PROCESS CLEANUP: first pass process group ${first_process_group} confirmed empty before rerun; first-attempt stdout and stderr remain in the job log" >&2
  echo "SIGTERM RETRY RISK: GitHub Actions exposes no trusted in-step cause attribution; a passing rerun does not prove the first attempt had no unflushed failure. Repeated SIGTERM retries indicate unresolved runner-resource or test instability." >&2
  echo "INFRASTRUCTURE RETRY: first pass exited 143 during running test(s) before package(s) completed: ${incomplete_label}; rerunning ${retry_scope} once" >&2
else
  echo "FLAKE RETRY: first pass failed for package(s): ${failed_label}; rerunning ${retry_scope} once" >&2
fi

retry_stdout="$tmpdir/retry.stdout"
retry_stderr="$tmpdir/retry.stderr"

if [ -n "$coverage_profile" ]; then
  first_coverage_profile="${coverage_profile}.first-attempt"
  if [ -e "$coverage_profile" ]; then
    mv -f -- "$coverage_profile" "$first_coverage_profile"
    echo "RETRY ARTIFACT: preserved first-attempt coverage at ${first_coverage_profile}" >&2
  fi
fi

set +e
capture_failed=0
process_cleanup_failed=0
run_and_tee "retry pass" "$retry_stdout" "$retry_stderr" "$@" "${retry_packages[@]}"
retry_status=$?
set -e

if [ "$capture_failed" -ne 0 ] || [ "$process_cleanup_failed" -ne 0 ]; then
  exit 1
fi

combined_retry="$tmpdir/retry.combined"
cat "$retry_stdout" "$retry_stderr" >"$combined_retry"

if refuse_forbidden_output "$combined_retry" "retry pass"; then
  if [ "$retry_status" -eq 0 ]; then
    exit 1
  fi
  exit "$retry_status"
fi

if [ "$retry_status" -eq 0 ]; then
  if [ -n "$coverage_profile" ] && [ ! -s "$coverage_profile" ]; then
    echo "ci-test-with-retry: refusing successful coverage retry because ${coverage_profile} was not recreated" >&2
    exit 1
  fi
  if [ "$retry_kind" = "sigterm" ]; then
    echo "INFRASTRUCTURE RETRY: SIGTERM-interrupted shard passed on rerun with residual first-attempt uncertainty; original incomplete package(s): ${incomplete_label}" >&2
  else
    echo "FLAKE RETRY: package(s) ${failed_label} failed then passed on rerun" >&2
  fi
  exit 0
fi

if [ "$retry_kind" = "sigterm" ]; then
  echo "INFRASTRUCTURE RETRY: SIGTERM-interrupted shard failed on rerun; original incomplete package(s): ${incomplete_label}" >&2
else
  echo "FLAKE RETRY: package(s) ${failed_label} failed again on rerun" >&2
fi
exit "$retry_status"

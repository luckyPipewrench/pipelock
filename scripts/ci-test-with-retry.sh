#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

# Run one CI go-test shard once, then retry a starvation-looking failure once.
# DATA RACE, build/setup errors, and non-timeout panics fail closed because
# retrying those away would hide the bugs this CI job exists to catch.
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
trap 'rm -rf "$tmpdir"' EXIT

capture_failed=0

run_and_tee() {
  local stdout_file="$1"
  local stderr_file="$2"
  shift 2

  local stdout_fifo="${stdout_file}.fifo"
  local stderr_fifo="${stderr_file}.fifo"
  mkfifo "$stdout_fifo" "$stderr_fifo"

  tee "$stdout_file" <"$stdout_fifo" &
  local stdout_tee_pid=$!
  tee "$stderr_file" <"$stderr_fifo" >&2 &
  local stderr_tee_pid=$!

  "$@" >"$stdout_fifo" 2>"$stderr_fifo"
  local command_status=$?

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

refuse_forbidden_output() {
  local output_file="$1"
  local pass_label="$2"

  if has_data_race "$output_file"; then
    echo "ci-test-with-retry: refusing retry because ${pass_label} reported WARNING: DATA RACE" >&2
    return 0
  fi

  if grep -Eiq '\b(build failed|cannot|undefined)\b' "$output_file"; then
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
run_and_tee "$first_stdout" "$first_stderr" "$@" "${package_args[@]}"
first_status=$?
set -e

if [ "$capture_failed" -ne 0 ]; then
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

if ! has_go_test_timeout "$first_stdout"; then
  echo "ci-test-with-retry: refusing retry because first pass was not a verified go test timeout" >&2
  exit "$first_status"
fi

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

retry_packages=("${failed_packages[@]}")
retry_scope="failed package(s)"
if [ "${#retry_packages[@]}" -eq 0 ]; then
  retry_packages=("${package_args[@]}")
  retry_scope="whole shard; no failed package list was isolated"
fi

coverage_profile=""
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
echo "FLAKE RETRY: first pass failed for package(s): ${failed_label}; rerunning ${retry_scope} once" >&2

retry_stdout="$tmpdir/retry.stdout"
retry_stderr="$tmpdir/retry.stderr"

if [ -n "$coverage_profile" ]; then
  rm -f -- "$coverage_profile"
fi

set +e
capture_failed=0
run_and_tee "$retry_stdout" "$retry_stderr" "$@" "${retry_packages[@]}"
retry_status=$?
set -e

if [ "$capture_failed" -ne 0 ]; then
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
  echo "FLAKE RETRY: package(s) ${failed_label} failed then passed on rerun" >&2
  exit 0
fi

echo "FLAKE RETRY: package(s) ${failed_label} failed again on rerun" >&2
exit "$retry_status"

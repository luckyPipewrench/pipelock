#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Run one repository-defined race-test selection. Keep the scheduler shape here
# so local shard targets and release verification cannot quietly disagree about
# fan-out, repeat count, or deadline.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-race-test.sh (--shard NAME | --packages "./pkg ...") [options]

Options:
  --tags TAGS             Go build tags (for example: enterprise)
  --run PATTERN           Go test -run pattern
  --coverprofile PATH     Write a Go coverage profile
  --json                  Emit go test JSON
  --print-command         Print the command without running it
EOF
}

shard=""
package_list=""
tags=""
run_pattern=""
coverprofile=""
json=false
print_command=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shard)
      shard="${2:-}"
      shift 2
      ;;
    --packages)
      package_list="${2:-}"
      shift 2
      ;;
    --tags)
      tags="${2:-}"
      shift 2
      ;;
    --run)
      run_pattern="${2:-}"
      shift 2
      ;;
    --coverprofile)
      coverprofile="${2:-}"
      shift 2
      ;;
    --json)
      json=true
      shift
      ;;
    --print-command)
      print_command=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "run-race-test.sh: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -n "$shard" && -n "$package_list" ]] || [[ -z "$shard" && -z "$package_list" ]]; then
  echo "run-race-test.sh: pass exactly one of --shard or --packages" >&2
  usage
  exit 2
fi

package_parallelism=2
if [[ -n "$shard" ]]; then
  package_args=(--shard "$shard")
  if [[ -n "$tags" ]]; then
    package_args=(--tags "$tags" "${package_args[@]}")
  fi
  package_list="$(python3 scripts/ci_test_packages.py "${package_args[@]}")"
  if [[ "$shard" == "proxy" ]]; then
    # The proxy shard has two race-instrumented packages. Keep them sequential
    # while leaving t.Parallel tests inside each package at the common limit.
    package_parallelism=1
  fi
fi

read -r -a packages <<<"$package_list"
if [[ ${#packages[@]} -eq 0 ]]; then
  echo "run-race-test.sh: package selection was empty" >&2
  exit 1
fi

cmd=(go test -race "-p=$package_parallelism" -parallel=2 -count=1 -timeout=15m)
if [[ -n "$tags" ]]; then
  cmd+=(-tags "$tags")
fi
if [[ -n "$run_pattern" ]]; then
  cmd+=(-run "$run_pattern")
fi
if [[ -n "$coverprofile" ]]; then
  cmd+=("-coverprofile=$coverprofile")
fi
if [[ "$json" == true ]]; then
  cmd+=(-json)
fi
cmd+=("${packages[@]}")

if [[ "$print_command" == true ]]; then
  printf '%q ' "${cmd[@]}"
  printf '\n'
  exit 0
fi

exec "${cmd[@]}"

#!/usr/bin/env bash
# bench/egress/run-all.sh - run the agent-egress overhead benchmark.
#
# Defaults to quick mode (usually 1-3 minutes). Use --release to run the full suite
# with 30-minute memory sampling (used to generate numbers for the public
# /learn/performance/ page).

set -euo pipefail

cd "$(dirname "$0")/../.."

mode="quick"
output="bench/egress/results.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      mode="release"
      shift
      ;;
    --long)
      # --long enables steady-state memory measurement at default duration
      # (30 min) without bumping iteration counts. Useful when you want
      # memory numbers but the same latency precision as quick mode.
      mode="long"
      shift
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--release|--long] [--output PATH]

  --release   full iteration counts + 30 min memory sampling
  --long      quick latency + 30 min memory sampling
  --output    JSON output path (default: bench/egress/results.json)
EOF
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 1
      ;;
  esac
done

echo "[run-all] building pipelock binary"
go build -o ./pipelock ./cmd/pipelock

echo "[run-all] building bench-egress binary"
go build -o ./bench-egress ./bench/egress/cmd/bench-egress

echo "[run-all] building mcpstdio mock binary"
go build -o ./bench-mcpstdio ./bench/egress/mocks/mcpstdio

bench_args=(
  --pipelock-binary ./pipelock
  --mcpstdio-binary ./bench-mcpstdio
  --config-dir bench/egress/configs
  --output "$output"
)

case "$mode" in
  release)
    bench_args+=(--release)
    ;;
  long)
    bench_args+=(--memory-duration 30m)
    ;;
esac

echo "[run-all] running bench-egress (mode=$mode)"
./bench-egress "${bench_args[@]}"

echo "[run-all] results written to $output"

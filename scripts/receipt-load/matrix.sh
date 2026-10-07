#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ $# -lt 3 || $# -gt 5 ]]; then
  echo "usage: $0 PIPELOCK_BINARY RECEIPT_LOAD_BINARY NEW_OUTPUT_DIRECTORY [REQUESTS=20000] [SAMPLES=3]" >&2
  exit 2
fi

pipelock=$1
load=$2
out=$3
requests=${4:-20000}
samples=${5:-3}
modes=${RECEIPT_LOAD_MODES:-off,best,required}
if [[ ! -x $pipelock || ! -x $load || -e $out || ! $requests =~ ^[1-9][0-9]*$ || ! $samples =~ ^[1-9][0-9]*$ ]]; then
  echo "binaries must be executable, output must be new, and requests/samples must be positive integers" >&2
  exit 2
fi
if ! command -v systemd-run >/dev/null || ! command -v python3 >/dev/null; then
  echo "systemd-run and python3 are required" >&2
  exit 2
fi

mkdir -p "$out"
runtime_dir=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
bus=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$runtime_dir/bus}
warmup_requests=$requests
if ((warmup_requests > 1000)); then
  warmup_requests=1000
fi

run_cell() {
  local cell=$1 count=$2
  mkdir -p "$cell"
  /usr/bin/env XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus" \
    systemd-run --user --scope -p "CPUQuota=$((cores*100))%" \
    /usr/bin/env GOMAXPROCS="$cores" "$load" \
    --binary "$pipelock" --out "$cell" --requests "$count" \
    --concurrency 128 --modes "$modes" --chains "$chains" \
    >"$cell/scope.log" 2>&1 || {
      cat "$cell/scope.log" >&2
      return 1
    }
}

for cores in 2 4 8; do
  for chains in 1 2 4 8; do
    run_cell "$out/cpu-$cores/chains-$chains/warmup" "$warmup_requests"
    for ((sample=1; sample<=samples; sample++)); do
      cell="$out/cpu-$cores/chains-$chains/sample-$sample"
      run_cell "$cell" "$requests"
    done
  done
done

python3 - "$out" "$samples" "$modes" <<'PY'
import csv
import json
import statistics
import sys
from pathlib import Path

root = Path(sys.argv[1])
samples = int(sys.argv[2])
modes = sys.argv[3].split(",")
with (root / "summary.csv").open("w", newline="") as output:
    writer = csv.writer(output)
    writer.writerow(["cpu_cores", "chains", "mode", "samples", "median_req_s", "min_req_s", "max_req_s", "median_p95_ms", "median_p99_ms", "median_cpu_cores", "missing", "errors", "verify_failures"])
    for cores in (2, 4, 8):
        for chains in (1, 2, 4, 8):
            for mode in modes:
                rows = []
                for sample in range(1, samples + 1):
                    name = mode if chains == 1 else f"chains-{chains}-{mode}"
                    path = root / f"cpu-{cores}" / f"chains-{chains}" / f"sample-{sample}" / name / "result.json"
                    rows.append(json.loads(path.read_text()))
                writer.writerow([
                    cores, chains, mode, samples,
                    round(statistics.median(row["requests_per_second"] for row in rows), 1),
                    round(min(row["requests_per_second"] for row in rows), 1),
                    round(max(row["requests_per_second"] for row in rows), 1),
                    round(statistics.median(row["p95_ms"] for row in rows), 1),
                    round(statistics.median(row["p99_ms"] for row in rows), 1),
                    round(statistics.median(row["cpu_cores_average"] for row in rows), 2),
                    sum(row["receipt_missing"] for row in rows),
                    sum(row["errors"] + row["unexpected"] for row in rows),
                    sum(row["verify_exit"] != 0 for row in rows),
                ])
PY
echo "matrix summary: $out/summary.csv"

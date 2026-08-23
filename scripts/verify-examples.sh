#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Run every shipped example verifier and IDE installation E2E. A verifier that
# cannot run must print a numeric SKIP summary; this runner keeps skips separate
# from passes and returns nonzero only when a verifier fails.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIPELOCK_BIN="${PIPELOCK_BIN:-$ROOT_DIR/pipelock}"
export PIPELOCK_BIN

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
SKIP=0
PASSED_CASES=()
FAILED_CASES=()
SKIPPED_CASES=()
RUN_STARTED="$(date +%s)"

run_case() {
  local label="$1"
  shift
  local log_file="$WORK/case-$((PASS + FAIL + SKIP)).log"
  local started rc skip_count elapsed

  printf '\n=== %s ===\n' "$label"
  started="$(date +%s)"
  rc=0
  "$@" >"$log_file" 2>&1 || rc=$?
  sed -n '1,$p' "$log_file"
  elapsed=$(( $(date +%s) - started ))
  skip_count="$(awk '/^SKIP: [0-9]+$/ { count = $2 } END { print count + 0 }' "$log_file")"

  if [[ "$rc" -ne 0 ]]; then
    FAIL=$((FAIL + 1))
    FAILED_CASES+=("$label (exit $rc, ${elapsed}s)")
    printf 'RESULT: FAIL (%s, exit %s)\n' "$label" "$rc"
  elif [[ "$skip_count" -gt 0 ]]; then
    SKIP=$((SKIP + 1))
    SKIPPED_CASES+=("$label (${skip_count} skipped assertion(s), ${elapsed}s)")
    printf 'RESULT: SKIP (%s, %s skipped assertion(s))\n' "$label" "$skip_count"
  else
    PASS=$((PASS + 1))
    PASSED_CASES+=("$label (${elapsed}s)")
    printf 'RESULT: PASS (%s)\n' "$label"
  fi
}

run_quickstart() {
  local go_binary="${PIPELOCK_VERIFY_GO:-go}"
  local local_binary="$WORK/quickstart-pipelock"
  local override="$WORK/quickstart.override.yaml"
  local expected_commit

  if ! command -v docker >/dev/null 2>&1; then
    printf 'SKIP: quickstart verification (docker is not available)\n'
    printf 'SKIP: 1\n'
    return 0
  fi
  if ! docker compose version >/dev/null 2>&1; then
    printf 'SKIP: quickstart verification (docker compose is not available)\n'
    printf 'SKIP: 1\n'
    return 0
  fi
  if ! docker info >/dev/null 2>&1; then
    printf 'SKIP: quickstart verification (the Docker daemon is not available)\n'
    printf 'SKIP: 1\n'
    return 0
  fi

  expected_commit="$(git -C "$ROOT_DIR" rev-parse --short=10 HEAD)"
  (
    cd "$ROOT_DIR"
    CGO_ENABLED=0 "$go_binary" build -trimpath \
      -ldflags "-s -w -X github.com/luckyPipewrench/pipelock/internal/cliutil.GitCommit=$expected_commit" \
      -o "$local_binary" ./cmd/pipelock
  )
  {
    printf 'services:\n'
    printf '  pipelock:\n'
    printf '    image: alpine:3.21\n'
    printf '    pull_policy: missing\n'
    printf '    entrypoint: ["/pipelock"]\n'
    printf '    volumes:\n'
    printf '      - "%s:/pipelock:ro,Z"\n' "$local_binary"
    printf '  verify:\n'
    printf '    image: alpine:3.21\n'
    printf '    pull_policy: missing\n'
    printf '    environment:\n'
    printf '      PIPELOCK_VERIFY_COMMIT: "%s"\n' "$expected_commit"
    printf '    volumes:\n'
    printf '      - "%s:/pipelock:ro,Z"\n' "$local_binary"
  } >"$override"

  (
    cd "$ROOT_DIR/examples/quickstart"
    trap 'docker compose -f docker-compose.yml -f "$override" --profile verify down -v >/dev/null 2>&1 || true' EXIT
    docker compose -f docker-compose.yml -f "$override" --profile verify up \
      --build \
      --abort-on-container-exit \
      --exit-code-from verify
  )
}

if [[ ! -x "$PIPELOCK_BIN" ]]; then
  printf 'ERROR: pipelock binary is not executable: %s\n' "$PIPELOCK_BIN" >&2
  exit 1
fi

mapfile -t example_scripts < <(find "$ROOT_DIR/examples" -mindepth 2 -maxdepth 2 -type f -name verify.sh | sort)
if [[ "${#example_scripts[@]}" -eq 0 ]]; then
  printf 'ERROR: no example verify.sh files found\n' >&2
  exit 1
fi

for script in "${example_scripts[@]}"; do
  relative="${script#"$ROOT_DIR/"}"
  if [[ "$relative" == "examples/quickstart/verify.sh" ]]; then
    run_case "$relative" run_quickstart
  else
    run_case "$relative" bash "$script"
  fi
done

run_case "scripts/e2e/cline-install.sh" bash "$ROOT_DIR/scripts/e2e/cline-install.sh"
run_case "scripts/e2e/opencode-install.sh" bash "$ROOT_DIR/scripts/e2e/opencode-install.sh"
run_case "scripts/e2e/cline-mcp-runtime.py" python3 "$ROOT_DIR/scripts/e2e/cline-mcp-runtime.py"
run_case "scripts/e2e/opencode-mcp-runtime.py" python3 "$ROOT_DIR/scripts/e2e/opencode-mcp-runtime.py"

printf '\n=== Verification summary ===\n'
printf 'PASS: %s\n' "$PASS"
printf 'FAIL: %s\n' "$FAIL"
printf 'SKIP: %s\n' "$SKIP"
printf 'RUNTIME_SECONDS: %s\n' "$(( $(date +%s) - RUN_STARTED ))"

if [[ "$FAIL" -gt 0 ]]; then
  printf '\nFailed checks:\n'
  printf '  %s\n' "${FAILED_CASES[@]}"
fi
if [[ "$SKIP" -gt 0 ]]; then
  printf '\nSkipped checks (not covered by this run):\n'
  printf '  %s\n' "${SKIPPED_CASES[@]}"
fi

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi

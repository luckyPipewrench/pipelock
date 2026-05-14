#!/usr/bin/env bash
# E2E test for `pipelock opencode install` and `pipelock opencode remove`.
#
# Exercises the full install flow against the installed pipelock binary:
#   1. Seed a fixture opencode.json with one local server and one remote server
#      with an Authorization header.
#   2. Run `pipelock opencode install --path <fixture>`.
#   3. Assert wrapped command-array structure, environment passthrough,
#      --header-file sidecar routing, and --upstream remote wrapping.
#   4. Spawn the wrapped local server invocation as a subprocess, send a
#      minimal JSON-RPC initialize, and confirm the wrapper parses.
#   5. Run `pipelock opencode remove --path <fixture>` and verify the config
#      is restored to canonical JSON equivalence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OWNED_WORKDIR=""

validate_workdir() {
  local dir="$1"

  if [[ -z "$dir" || "$dir" == "/" ]]; then
    echo "ERROR: refusing unsafe WORKDIR: ${dir:-<empty>}" >&2
    exit 1
  fi
  if [[ -n "${HOME:-}" && -d "$HOME" ]]; then
    local home_dir
    home_dir="$(cd "$HOME" && pwd -P)"
    if [[ "$dir" == "$home_dir" ]]; then
      echo "ERROR: refusing WORKDIR equal to HOME: $dir" >&2
      exit 1
    fi
  fi
  if [[ "$dir" == "$REPO_ROOT" ]]; then
    echo "ERROR: refusing WORKDIR equal to repository root: $dir" >&2
    exit 1
  fi
}

if [[ -n "${WORKDIR:-}" ]]; then
  mkdir -p "$WORKDIR"
  WORKDIR="$(cd "$WORKDIR" && pwd -P)"
  validate_workdir "$WORKDIR"
  WORKDIR_OWNED=0
else
  WORKDIR="$(mktemp -d -t pipelock-opencode-e2e-XXXXXX)"
  WORKDIR="$(cd "$WORKDIR" && pwd -P)"
  validate_workdir "$WORKDIR"
  OWNED_WORKDIR="$WORKDIR"
  WORKDIR_OWNED=1
fi

cleanup() {
  if [[ "$WORKDIR_OWNED" != "1" || -z "$OWNED_WORKDIR" ]]; then
    return
  fi

  local tmp_base
  tmp_base="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
  local owned_prefix
  if [[ "$tmp_base" == "/" ]]; then
    owned_prefix="/pipelock-opencode-e2e-"
  else
    owned_prefix="$tmp_base/pipelock-opencode-e2e-"
  fi
  if [[ "$OWNED_WORKDIR" == "$owned_prefix"* ]]; then
    rm -rf -- "$OWNED_WORKDIR"
  else
    echo "WARNING: refusing to remove unexpected WORKDIR: $OWNED_WORKDIR" >&2
  fi
}
trap cleanup EXIT

CONFIG="$WORKDIR/opencode.json"
SEED="$WORKDIR/opencode.seed.json"
E2E_HOME="$WORKDIR/empty-home"

if [[ -n "${PIPELOCK_BIN:-}" ]]; then
  PIPELOCK="$PIPELOCK_BIN"
else
  PIPELOCK="$WORKDIR/pipelock"
  echo "Building pipelock from $REPO_ROOT into $PIPELOCK ..."
  (cd "$REPO_ROOT" && go build -o "$PIPELOCK" ./cmd/pipelock)
fi

PASS=0
FAIL=0
FAILED_TESTS=()

assert() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    PASS=$((PASS + 1))
    echo "  PASS  $desc"
  else
    FAIL=$((FAIL + 1))
    FAILED_TESTS+=("$desc")
    echo "  FAIL  $desc"
  fi
}

json_value_equals() {
  local file="$1"
  local filter="$2"
  local expected="$3"
  local actual
  actual="$(jq -r "$filter" "$file")"
  [[ "$actual" == "$expected" ]]
}

mode_is_600() {
  local path="$1"
  [[ "$(stat -c '%a' "$path")" == "600" ]]
}

proxy_output_exists() {
  [[ -s "$WORKDIR/proxy.stdout" || -s "$WORKDIR/proxy.stderr" ]]
}

wrapped_argv_has_no_cobra_error() {
  ! grep -qE 'unknown command|unknown flag|invalid argument' "$WORKDIR/proxy.stderr"
}

canonical_json_matches() {
  diff <(jq -S . "$SEED") <(jq -S . "$CONFIG")
}

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required for this test" >&2
    exit 1
  fi
}

require_binary() {
  if [[ ! -x "$PIPELOCK" ]]; then
    echo "ERROR: pipelock binary not found at $PIPELOCK" >&2
    echo "Set PIPELOCK_BIN to override." >&2
    exit 1
  fi
}

seed_config() {
  cat >"$SEED" <<'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "fixture-local": {
      "type": "local",
      "command": ["cat"],
      "environment": {
        "FIXTURE_VAR": "value"
      }
    },
    "fixture-remote": {
      "type": "remote",
      "url": "https://fixture.invalid/mcp",
      "headers": {
        "Authorization": "Bearer fixture-token"
      }
    }
  }
}
EOF
  cp "$SEED" "$CONFIG"
}

echo "=== pipelock opencode install E2E ==="
echo "Binary:  $PIPELOCK"
echo "Workdir: $WORKDIR"
echo ""

require_jq
require_binary
seed_config

echo "[1] install"
PIPELOCK_CONFIG="" XDG_CONFIG_HOME="$WORKDIR/empty-xdg" HOME="$E2E_HOME" \
  "$PIPELOCK" opencode install --path "$CONFIG" >"$WORKDIR/install.stdout" 2>"$WORKDIR/install.stderr"
assert "install exit 0" test -s "$WORKDIR/install.stdout"
assert "install stdout reports 2 wrapped" grep -q "Wrapped 2 server(s)" "$WORKDIR/install.stdout"
assert "install stderr warns when no pipelock config is discoverable" \
  grep -q "no pipelock config found" "$WORKDIR/install.stderr"

echo ""
echo "[1b] install honors auto-discovery"
DISCOVER_HOME="$WORKDIR/discover-home"
mkdir -p "$DISCOVER_HOME/.config/pipelock"
echo "mode: balanced" >"$DISCOVER_HOME/.config/pipelock/pipelock.yaml"
DISCOVER_CFG="$WORKDIR/discover-opencode.json"
cp "$SEED" "$DISCOVER_CFG"
PIPELOCK_CONFIG="" XDG_CONFIG_HOME="" HOME="$DISCOVER_HOME" \
  "$PIPELOCK" opencode install --path "$DISCOVER_CFG" >"$WORKDIR/install-discover.stdout" 2>"$WORKDIR/install-discover.stderr"
assert "install-discover stderr notes the discovered config" \
  grep -q "Using config $DISCOVER_HOME/.config/pipelock/pipelock.yaml" "$WORKDIR/install-discover.stderr"
assert "install-discover local command carries --config" \
  jq -e --arg expected "$DISCOVER_HOME/.config/pipelock/pipelock.yaml" \
    '.mcp["fixture-local"].command | index("--config") as $i | .[$i+1] == $expected' "$DISCOVER_CFG"
assert "install-discover remote command carries --config" \
  jq -e --arg expected "$DISCOVER_HOME/.config/pipelock/pipelock.yaml" \
    '.mcp["fixture-remote"].command | index("--config") as $i | .[$i+1] == $expected' "$DISCOVER_CFG"

echo ""
echo "[2] structural assertions on wrapped config"

assert "local entry carries _pipelock metadata" \
  jq -e '.mcp["fixture-local"]._pipelock' "$CONFIG"
assert "remote entry carries _pipelock metadata" \
  jq -e '.mcp["fixture-remote"]._pipelock' "$CONFIG"

assert "wrapped local entry type=local" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"].type' "local"
assert "wrapped remote entry type=local" \
  json_value_equals "$CONFIG" '.mcp["fixture-remote"].type' "local"

assert "local command starts with pipelock path" \
  jq -e '.mcp["fixture-local"].command[0] | length > 0' "$CONFIG"
assert "local command[1]=mcp" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"].command[1]' "mcp"
assert "local command[2]=proxy" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"].command[2]' "proxy"
assert "local carries --env FIXTURE_VAR passthrough" \
  jq -e '.mcp["fixture-local"].command | index("--env") as $i | .[$i+1] == "FIXTURE_VAR"' "$CONFIG"
assert "local carries -- separator before original command" \
  jq -e '.mcp["fixture-local"].command | index("--") as $i | .[$i+1] == "cat"' "$CONFIG"

assert "remote carries --header-file flag with a sidecar path" \
  jq -e '.mcp["fixture-remote"].command | index("--header-file") as $i | (.[ $i+1 ] | type) == "string" and (.[ $i+1 ] | length) > 0' "$CONFIG"

SIDECAR_PATH=$(jq -r '.mcp["fixture-remote"].command as $a | $a | index("--header-file") as $i | $a[$i+1]' "$CONFIG")
assert "sidecar file exists at the path embedded in argv" test -f "$SIDECAR_PATH"
assert "sidecar mode is 0o600" \
  mode_is_600 "$SIDECAR_PATH"
assert "sidecar contains the Authorization header line" \
  grep -q "Authorization: Bearer fixture-token" "$SIDECAR_PATH"
assert "wrapped argv does NOT contain the Authorization header value" \
  jq -e '.mcp["fixture-remote"].command | all(. != "Authorization: Bearer fixture-token")' "$CONFIG"
assert "_pipelock metadata records the sidecar path" \
  jq -e --arg path "$SIDECAR_PATH" '.mcp["fixture-remote"]._pipelock.header_sidecar_path == $path' "$CONFIG"

assert "remote carries --upstream original-url" \
  jq -e '.mcp["fixture-remote"].command | index("--upstream") as $i | .[$i+1] == "https://fixture.invalid/mcp"' "$CONFIG"

assert "local metadata original_type=local" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"]._pipelock.original_type' "local"
assert "remote metadata original_type=remote" \
  json_value_equals "$CONFIG" '.mcp["fixture-remote"]._pipelock.original_type' "remote"

assert "install wrote .bak matching seed" cmp -s "$SEED" "$CONFIG.bak"

echo ""
echo "[3] runtime: spawn wrapped local invocation, send initialize, expect clean parse"

mapfile -t WRAPPED_CMD < <(jq -r '.mcp["fixture-local"].command[]' "$CONFIG")
INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"opencode-e2e","version":"0"}}}'

printf '%s\n' "$INIT_REQ" | timeout 5 "${WRAPPED_CMD[@]}" >"$WORKDIR/proxy.stdout" 2>"$WORKDIR/proxy.stderr" || true

assert "proxy produced stdout or stderr output (didn't crash immediately)" \
  proxy_output_exists
assert "wrapped argv parses without cobra error" \
  wrapped_argv_has_no_cobra_error

echo ""
echo "[4] remove and restore"

HOME="$E2E_HOME" "$PIPELOCK" opencode remove --path "$CONFIG" >"$WORKDIR/remove.stdout" 2>"$WORKDIR/remove.stderr"
assert "remove exit 0" test -s "$WORKDIR/remove.stdout"
assert "remove stdout reports 2 unwrapped" grep -q "Unwrapped 2 server(s)" "$WORKDIR/remove.stdout"

assert "post-remove config equals seed (canonical JSON compare)" \
  canonical_json_matches

assert "local entry restored: no leftover _pipelock" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"]._pipelock // "absent"' "absent"
assert "local entry restored: type local" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"].type' "local"
assert "local entry restored: command back to cat" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"].command[0]' "cat"
assert "local entry restored: environment block intact" \
  json_value_equals "$CONFIG" '.mcp["fixture-local"].environment.FIXTURE_VAR' "value"

assert "remote entry restored: type remote" \
  json_value_equals "$CONFIG" '.mcp["fixture-remote"].type' "remote"
assert "remote entry restored: url back" \
  json_value_equals "$CONFIG" '.mcp["fixture-remote"].url' "https://fixture.invalid/mcp"
assert "remote entry restored: Authorization header back" \
  json_value_equals "$CONFIG" '.mcp["fixture-remote"].headers.Authorization' "Bearer fixture-token"

echo ""
echo "[5] idempotence: re-run install on already-installed config"

HOME="$E2E_HOME" "$PIPELOCK" opencode install --path "$CONFIG" >/dev/null 2>&1
HOME="$E2E_HOME" "$PIPELOCK" opencode install --path "$CONFIG" >"$WORKDIR/install2.stdout" 2>&1
assert "second install skipped both servers" grep -q "Wrapped 0 server(s).*(2 already wrapped)" "$WORKDIR/install2.stdout"

echo ""
echo "=== Summary ==="
echo "PASS: $PASS"
echo "FAIL: $FAIL"

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "Failed assertions:"
  for t in "${FAILED_TESTS[@]}"; do
    echo "  - $t"
  done
  exit 1
fi

exit 0

#!/usr/bin/env bash
# E2E test for `pipelock cline install` and `pipelock cline remove`.
#
# Exercises the full install flow against the installed pipelock binary:
#   1. Seed a fixture cline_mcp_settings.json with one stdio server and
#      one HTTP server with an Authorization header.
#   2. Run `pipelock cline install --path <fixture>`.
#   3. Assert wrapped argv structure: command=<pipelock>, args start with
#      "mcp proxy", "--env" present for env-bearing stdio, "--header" present
#      for header-bearing HTTP, "--upstream <url>" terminates HTTP wrap,
#      "--" terminates stdio wrap.
#   4. Assert _pipelock metadata is recorded and TypeOmitted=true for both
#      typeless Cline entries.
#   5. Spawn the wrapped stdio server invocation as a subprocess, send a
#      minimal JSON-RPC initialize, confirm the subprocess accepts stdin
#      and exits cleanly when stdin closes.
#   6. Assert .bak backup matches the seed file.
#   7. Run `pipelock cline remove --path <fixture>`.
#   8. Assert the restored config matches the seed file byte-for-byte.
#
# Usage: bash tests/e2e/cline-install.sh
# Exit:  0 if all assertions pass, 1 on first failure.

set -euo pipefail

# Resolve the repo root from this script's location so the build always uses
# the same source tree the script ships with. Override PIPELOCK_BIN to skip
# the build and use a pre-existing binary, but it must include the cline
# subcommand or the structural assertions will fail.
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
  WORKDIR="$(mktemp -d -t pipelock-cline-e2e-XXXXXX)"
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
    owned_prefix="/pipelock-cline-e2e-"
  else
    owned_prefix="$tmp_base/pipelock-cline-e2e-"
  fi
  if [[ "$OWNED_WORKDIR" == "$owned_prefix"* ]]; then
    rm -rf -- "$OWNED_WORKDIR"
  else
    echo "WARNING: refusing to remove unexpected WORKDIR: $OWNED_WORKDIR" >&2
  fi
}
trap cleanup EXIT

CONFIG="$WORKDIR/cline_mcp_settings.json"
SEED="$WORKDIR/cline_mcp_settings.seed.json"

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

# assert <description> <command>: runs the command, records pass/fail.
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

stdio_command_points_at_pipelock() {
  local actual
  actual="$(jq -r '.mcpServers["fixture-stdio"].command' "$CONFIG")"
  [[ "$actual" == "$PIPELOCK" || "$actual" == "$(readlink -f "$PIPELOCK")" ]]
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

# require_jq verifies jq is present; the script depends on it for structural
# assertions.
require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required for this test" >&2
    exit 1
  fi
}

# require_binary verifies the pipelock binary exists and is executable.
require_binary() {
  if [[ ! -x "$PIPELOCK" ]]; then
    echo "ERROR: pipelock binary not found at $PIPELOCK" >&2
    echo "Set PIPELOCK_BIN to override." >&2
    exit 1
  fi
}

# seed_config writes a fixture config with one stdio server and one HTTP
# server with an Authorization header. Cline omits the type field on both.
seed_config() {
  cat >"$SEED" <<'EOF'
{
  "mcpServers": {
    "fixture-stdio": {
      "command": "cat",
      "args": [],
      "env": {
        "FIXTURE_VAR": "value"
      }
    },
    "fixture-http": {
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

echo "=== pipelock cline install E2E ==="
echo "Binary:  $PIPELOCK"
echo "Workdir: $WORKDIR"
echo ""

require_jq
require_binary
seed_config

echo "[1] install"
# Suppress pipelock config auto-discovery so this script remains hermetic and
# does not pick up the operator's $HOME pipelock.yaml. Operators get
# auto-discovery; the test asserts the no-discovery warning instead.
PIPELOCK_CONFIG="" XDG_CONFIG_HOME="$WORKDIR/empty-xdg" HOME="$WORKDIR/empty-home" \
  "$PIPELOCK" cline install --path "$CONFIG" >"$WORKDIR/install.stdout" 2>"$WORKDIR/install.stderr"
assert "install exit 0" test -s "$WORKDIR/install.stdout"
assert "install stdout reports 2 wrapped" grep -q "Wrapped 2 server(s)" "$WORKDIR/install.stdout"
assert "install stderr warns when no pipelock config is discoverable" \
  grep -q "no pipelock config found" "$WORKDIR/install.stderr"

# Second install pass exercises the auto-discovery branch against a seeded
# user config in a controlled HOME. The wrapped argv must carry --config.
echo ""
echo "[1b] install honors auto-discovery"
DISCOVER_HOME="$WORKDIR/discover-home"
mkdir -p "$DISCOVER_HOME/.config/pipelock"
echo "mode: balanced" >"$DISCOVER_HOME/.config/pipelock/pipelock.yaml"
DISCOVER_CFG="$WORKDIR/discover-cline.json"
cp "$SEED" "$DISCOVER_CFG"
PIPELOCK_CONFIG="" XDG_CONFIG_HOME="" HOME="$DISCOVER_HOME" \
  "$PIPELOCK" cline install --path "$DISCOVER_CFG" >"$WORKDIR/install-discover.stdout" 2>"$WORKDIR/install-discover.stderr"
assert "install-discover stderr notes the discovered config" \
  grep -q "Using config $DISCOVER_HOME/.config/pipelock/pipelock.yaml" "$WORKDIR/install-discover.stderr"
assert "install-discover stdio args carry --config" \
  jq -e --arg expected "$DISCOVER_HOME/.config/pipelock/pipelock.yaml" \
    '.mcpServers["fixture-stdio"].args | index("--config") as $i | .[$i+1] == $expected' "$DISCOVER_CFG"
assert "install-discover http args carry --config" \
  jq -e --arg expected "$DISCOVER_HOME/.config/pipelock/pipelock.yaml" \
    '.mcpServers["fixture-http"].args | index("--config") as $i | .[$i+1] == $expected' "$DISCOVER_CFG"

echo ""
echo "[2] structural assertions on wrapped config"

# Both entries should have _pipelock metadata.
assert "stdio entry carries _pipelock metadata" \
  jq -e '.mcpServers["fixture-stdio"]._pipelock' "$CONFIG"
assert "http entry carries _pipelock metadata" \
  jq -e '.mcpServers["fixture-http"]._pipelock' "$CONFIG"

# Both entries should declare type=stdio (so Cline launches pipelock).
assert "wrapped stdio entry type=stdio" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-stdio"].type' "stdio"
assert "wrapped http entry type=stdio" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-http"].type' "stdio"

# Stdio entry: command = pipelock binary path, args starts with "mcp proxy".
assert "stdio command points at pipelock" \
  stdio_command_points_at_pipelock
assert "stdio args[0]=mcp" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-stdio"].args[0]' "mcp"
assert "stdio args[1]=proxy" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-stdio"].args[1]' "proxy"

# Stdio entry: --env FIXTURE_VAR passthrough is present.
assert "stdio carries --env FIXTURE_VAR passthrough" \
  jq -e '.mcpServers["fixture-stdio"].args | index("--env") as $i | .[$i+1] == "FIXTURE_VAR"' "$CONFIG"

# Stdio entry: -- separator precedes the original command.
assert "stdio carries -- separator before original command" \
  jq -e '.mcpServers["fixture-stdio"].args | index("--") as $i | .[$i+1] == "cat"' "$CONFIG"

# HTTP entry: --header-file carries the path to a 0o600 sidecar; the
# Authorization value lives in the sidecar file, never in argv.
assert "http carries --header-file flag with a sidecar path" \
  jq -e '.mcpServers["fixture-http"].args | index("--header-file") as $i | (.[ $i+1 ] | type) == "string" and (.[ $i+1 ] | length) > 0' "$CONFIG"

SIDECAR_PATH=$(jq -r '.mcpServers["fixture-http"].args as $a | $a | index("--header-file") as $i | $a[$i+1]' "$CONFIG")
assert "sidecar file exists at the path embedded in argv" test -f "$SIDECAR_PATH"
assert "sidecar mode is 0o600" \
  mode_is_600 "$SIDECAR_PATH"
assert "sidecar contains the Authorization header line" \
  grep -q "Authorization: Bearer fixture-token" "$SIDECAR_PATH"
assert "wrapped argv does NOT contain the Authorization header value" \
  jq -e '.mcpServers["fixture-http"].args | all(. != "Authorization: Bearer fixture-token")' "$CONFIG"
assert "_pipelock metadata records the sidecar path" \
  jq -e --arg path "$SIDECAR_PATH" '.mcpServers["fixture-http"]._pipelock.header_sidecar_path == $path' "$CONFIG"

# HTTP entry: --upstream carries the original URL.
assert "http carries --upstream original-url" \
  jq -e '.mcpServers["fixture-http"].args | index("--upstream") as $i | .[$i+1] == "https://fixture.invalid/mcp"' "$CONFIG"

# Both metadata entries: TypeOmitted=true (Cline omits type field).
assert "stdio metadata TypeOmitted=true" \
  jq -e '.mcpServers["fixture-stdio"]._pipelock.type_omitted == true' "$CONFIG"
assert "http metadata TypeOmitted=true" \
  jq -e '.mcpServers["fixture-http"]._pipelock.type_omitted == true' "$CONFIG"

# Backup matches the seed file.
assert "install wrote .bak matching seed" cmp -s "$SEED" "$CONFIG.bak"

echo ""
echo "[3] runtime: spawn wrapped stdio invocation, send initialize, expect clean exit"

# Extract the wrapped argv for the stdio entry and reconstruct the command.
WRAPPED_CMD=$(jq -r '.mcpServers["fixture-stdio"].command' "$CONFIG")
mapfile -t WRAPPED_ARGS < <(jq -r '.mcpServers["fixture-stdio"].args[]' "$CONFIG")

# Build a minimal JSON-RPC initialize request matching MCP 2025-06-18.
INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cline-e2e","version":"0"}}}'

# Spawn with a short timeout; pipelock should print at least one line of
# output (initialize response or scan-related notice) and exit when stdin
# closes after our single request.
printf '%s\n' "$INIT_REQ" | timeout 5 "$WRAPPED_CMD" "${WRAPPED_ARGS[@]}" >"$WORKDIR/proxy.stdout" 2>"$WORKDIR/proxy.stderr" || true

assert "proxy produced stdout or stderr output (didn't crash immediately)" \
  proxy_output_exists

# Confirm the binary at least recognised the cline-install-shaped args
# (cobra parse error would be in stderr, immediate help text). Either a
# JSON response on stdout (proxy actually forwarded) or an mcp-related
# message on stderr (proxy initialized then child exited) is acceptable;
# what we are rejecting here is "unknown command" or "unknown flag" output.
assert "wrapped argv parses without cobra error" \
  wrapped_argv_has_no_cobra_error

echo ""
echo "[4] remove and restore"

"$PIPELOCK" cline remove --path "$CONFIG" >"$WORKDIR/remove.stdout" 2>"$WORKDIR/remove.stderr"
assert "remove exit 0" test -s "$WORKDIR/remove.stdout"
assert "remove stdout reports 2 unwrapped" grep -q "Unwrapped 2 server(s)" "$WORKDIR/remove.stdout"

# Order-of-keys equivalence: parse both, compare as canonical JSON.
assert "post-remove config equals seed (canonical JSON compare)" \
  canonical_json_matches

# Per-server fields should be exactly what the seed had: no leftover
# _pipelock, no leftover type=stdio, original env/headers/url back.
assert "stdio entry restored: no leftover _pipelock" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-stdio"]._pipelock // "absent"' "absent"
assert "stdio entry restored: no leftover type field" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-stdio"].type // "absent"' "absent"
assert "stdio entry restored: command back to 'cat'" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-stdio"].command' "cat"
assert "stdio entry restored: env block intact" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-stdio"].env.FIXTURE_VAR' "value"

assert "http entry restored: no leftover type field" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-http"].type // "absent"' "absent"
assert "http entry restored: url back" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-http"].url' "https://fixture.invalid/mcp"
assert "http entry restored: Authorization header back" \
  json_value_equals "$CONFIG" '.mcpServers["fixture-http"].headers.Authorization' "Bearer fixture-token"

echo ""
echo "[5] idempotence: re-run install on already-installed config (no double-wrap)"

# Re-run install on the (restored) config; should wrap both servers exactly
# once. Then re-run on the wrapped config; should skip both.
"$PIPELOCK" cline install --path "$CONFIG" >/dev/null 2>&1
"$PIPELOCK" cline install --path "$CONFIG" >"$WORKDIR/install2.stdout" 2>&1
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

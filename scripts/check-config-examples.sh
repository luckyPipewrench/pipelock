#!/usr/bin/env bash
# check-config-examples.sh — shipped config snippets must actually START.
#
# `pipelock check` is a parse/semantic pass; it does not exercise runtime startup
# preconditions. A snippet can therefore pass `check` and still kill `pipelock run`
# at boot — a config we ship that bricks the user who trusted the guide.
#
# This catches the CLASS: any doc/example config that `check` blesses but the
# runtime refuses. Config examples are executable claims — render and RUN them.
#
# Scope discipline (deliberately conservative — no false positives):
#   Every recognized block that passes `check` is booted. A startup refusal is
#   skipped only when its actual error identifies an unavailable external input
#   (key/license/cert, placeholder destination, or required watched resource).
#   Merely mentioning one cannot exempt an unrelated broken config. What remains
#   is a pure SHAPE failure — e.g. sign_checkpoints:true with a persisted dir and
#   no signing_key_path named at all. Skips and check rejections are both printed.
#
# Usage:  scripts/check-config-examples.sh [path/to/pipelock]
# Exit:   0 = every bootable snippet starts;  1 = a shipped snippet won't start.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORK="$(mktemp -d)"
RUN_PID=""
cleanup() {
    if [ -n "$RUN_PID" ]; then
        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

BIN="${1:-}"
if [ -z "$BIN" ]; then
    BIN="$WORK/pipelock"
    echo "config-examples: building pipelock..."
    go build -o "$BIN" ./cmd/pipelock
fi
[ -x "$BIN" ] || { echo "config-examples: no usable pipelock binary at '$BIN'" >&2; exit 1; }

# Fixture a real recorder signing key. Without this the check is CIRCULAR: a snippet
# that correctly sets signing_key_path names a file this host does not have, gets
# skipped as environment-dependent, and is never booted — so the policy would not
# exercise the very examples it exists to protect. A signing key is trivially
# fixture-creatable (init generates one), so it must be fixtured, not skipped. Skips
# are reserved for dependencies that cannot reasonably be created here (a real signed
# license, an operator's CA). `init` writes keys/ next to the config it generates.
FIXTURE_KEY=""
if "$BIN" init --output "$WORK/keygen/pipelock.yaml" --skip-canary --skip-validate >/dev/null 2>&1 \
    && [ -s "$WORK/keygen/keys/flight-recorder-signing.key" ]; then
    FIXTURE_KEY="$WORK/keygen/keys/flight-recorder-signing.key"
else
    echo "config-examples: WARNING - could not fixture a recorder signing key;" >&2
    echo "  snippets naming signing_key_path will be skipped instead of booted." >&2
fi

# Top-level keys of config.Config. A yaml block is a pipelock config only if every
# top-level key it declares is one of these — that excludes k8s manifests, Helm
# values, CI workflows, and JSON without hand-maintaining an ignore list.
CONFIG_KEYS="$(sed -n '/^type Config struct {/,/^}/p' internal/config/schema.go \
    | grep -oP 'yaml:"\K[a-z_0-9]+' | sort -u)"
[ -n "$CONFIG_KEYS" ] || { echo "config-examples: could not read Config keys from schema.go" >&2; exit 1; }

total=0; booted=0; skipped=0; rejected=0; failed=0
FAILURES="$WORK/failures.txt"; : >"$FAILURES"
SKIPS="$WORK/skips.txt"; : >"$SKIPS"
REJECTED="$WORK/rejected.txt"; : >"$REJECTED"

# KNOWN LIMIT (deliberate): a block is only booted when EVERY top-level key is a
# Config field. A pipelock config carrying a typo'd top-level key (`flight_recoder:`)
# therefore drops out of this check silently, and yaml would ignore that key at
# runtime too. Gating on "some known + some unknown" was tried and rejected: every
# real occurrence is a DIFFERENT schema that merely shares a key name — Helm values
# (image/license), docker-compose (services/networks), the rules bundle
# (format_version/tier), the policy spec — so it produced 11 noise rows and zero
# signal, and a noisy tripwire gets deleted. The real fix is explicit fence intent
# (mark a block complete-config vs fragment) and is tracked separately.
is_config_block() {
    local keys
    keys="$(grep -oP '^[a-z_0-9]+(?=:)' "$1" 2>/dev/null | sort -u)" || return 1
    [ -n "$keys" ] || return 1
    while IFS= read -r k; do
        grep -qxF "$k" <<<"$CONFIG_KEYS" || return 1
    done <<<"$keys"
    return 0
}

# Classify a refusal as environment-dependent only after it actually occurs.
# Merely mentioning a path or placeholder host must not exempt the entire block:
# allowlists, regexes, optional sentinel files, and output paths do not need those
# resources at startup and must still exercise the runtime.
environment_failure_reason() {
    local cfg="$1" out="$2"

    if grep -qE "^[[:space:]]*(license_file|license_crl_file|license_intermediate_file|trust_roster_path|server_ca_file|client_cert_path|client_key_path|enrollment_token_path|ca_cert|ca_key|secrets_file|signing_key_path|manifest_path|signature_path|keystore|roster_path):[[:space:]]*(\"[^\"]+\"|'[^']+'|[^\"'[:space:]#][^#]*)" "$cfg" \
        && grep -qiE '(no such file|permission denied|not found|cannot (open|read)|failed to (open|read|load)|load(ing)? .*(file|key|cert|roster|manifest))' "$out"; then
        echo "needs an external input file"
        return
    fi

    if grep -qE '\.(example|invalid|test)(\.[a-z]+)?\b' "$cfg" \
        && grep -qiE '(no such host|temporary failure in name resolution|name or service not known|network is unreachable|connection refused)' "$out"; then
        echo "placeholder destination is unavailable"
        return
    fi

    if grep -qE '^[[:space:]-]*required:[[:space:]]*true([[:space:]]*(#.*)?)?$' "$cfg" \
        && grep -qiE '(file sentry|watch).*(failed|missing|no such file|permission denied)' "$out"; then
        echo "required resource is unavailable"
        return
    fi

    if grep -qiE 'requires an enterprise build' "$out"; then
        echo "requires an enterprise build"
        return
    fi

    echo ""
}

choose_port() {
    local port i
    for ((i=0; i<40; i++)); do
        port=$((20000 + RANDOM % 30000))
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            echo "$port"
            return 0
        fi
    done
    return 1
}

http_ready() {
    local port="$1" status
    status="$({
        exec 3<>"/dev/tcp/127.0.0.1/$port"
        printf 'GET /health HTTP/1.0\r\n\r\n' >&3
        IFS= read -r -t 1 status <&3
        printf '%s' "$status"
    } 2>/dev/null)" || return 1
    [[ "$status" == HTTP/* ]]
}

probe() {
    local snippet="$1" label="$2"
    is_config_block "$snippet" || return 0
    total=$((total+1))

    # Relocate runtime-created OUTPUT paths into the sandbox so a doc's /var/lib
    # path is not a permission failure caused by this check. Covers output files
    # (spool_file/cursor_file) as well as dirs: they are created at startup, so a
    # doc pointing them at /var/lib fails on permissions, not on config shape.
    # Relocating them keeps the block booted; skipping it would hollow out cover.
    # Input dirs such as rules_dir and learn_lock.store_dir are deliberately
    # excluded: replacing them with an empty directory could conceal a refusal.
    local run_cfg="$WORK/run-$total.yaml"
    sed -E "s@^([[:space:]]*(dir|profile_dir|bundle_cache_dir|durable_audit_queue_dir|quarantine_dir|capture_dir):[[:space:]])(\"[^\"]+\"|'[^']+'|[^\"'[:space:]#]([^#]*[^[:space:]#])?)([[:space:]]*#.*)?\$@\1\"$WORK/d$total\"\5@" \
        "$snippet" \
    | sed -E "s@^([[:space:]]*(spool_file|cursor_file):[[:space:]])(\"[^\"]+\"|'[^']+'|[^\"'[:space:]#]([^#]*[^[:space:]#])?)([[:space:]]*#.*)?\$@\1\"$WORK/d$total/\2\"\5@" \
        >"$run_cfg"
    mkdir -p "$WORK/d$total"

    # Point signing_key_path at the fixtured key so a snippet that correctly names one
    # is BOOTED rather than skipped. This is what makes the policy actually verify the
    # recorder examples instead of only detecting a missing key line.
    if [ -n "$FIXTURE_KEY" ]; then
        local key_cfg="${run_cfg}.key.tmp"
        sed -E "s@^([[:space:]]*signing_key_path:[[:space:]])(\"[^\"]+\"|'[^']+'|[^\"'[:space:]#]([^#]*[^[:space:]#])?)([[:space:]]*#.*)?\$@\1\"$FIXTURE_KEY\"\4@" \
            "$run_cfg" >"$key_cfg"
        mv "$key_cfg" "$run_cfg"
    fi

    local check_ok=0 check_out="$WORK/check-$total.txt"
    "$BIN" check --config "$run_cfg" >"$check_out" 2>&1 && check_ok=1
    if [ "$check_ok" -eq 0 ]; then
        rejected=$((rejected+1))
        {
            echo "  check rejected: $label"
            echo "      $(grep -m1 -vE '^[[:space:]]*$' "$check_out" | head -c 180)"
        } >>"$REJECTED"
        return 0
    fi

    # The startup banner is printed before auxiliary and main listeners bind, so
    # it is not a readiness marker. Complete an HTTP exchange with the main
    # listener, then allow a short grace window for immediate post-bind failures.
    local port out_file="$WORK/out-$total.txt" ready attempt deadline
    for attempt in 1 2 3; do
        ready=0
        port="$(choose_port)" || { echo "config-examples: could not find a free probe port" >&2; exit 1; }
        "$BIN" run --listen "127.0.0.1:$port" --config "$run_cfg" >"$out_file" 2>&1 </dev/null &
        RUN_PID=$!
        # Generous backstop, not the gate: readiness is detected the instant /health
        # answers (~60ms), so a large deadline costs nothing on success and only
        # protects a legitimately slow boot (cold TLS cert generation, sandbox init)
        # on a loaded runner from being misreported as a config-shape failure. A
        # timeout here is NOT retried, so it must not be the thing that fires first.
        deadline=$((SECONDS + ${CONFIG_EXAMPLES_BOOT_TIMEOUT:-30}))
        while (( SECONDS < deadline )); do
            kill -0 "$RUN_PID" 2>/dev/null || break
            if http_ready "$port"; then
                ready=1
                break
            fi
            sleep 0.05
        done
        if [ "$ready" -eq 1 ]; then
            sleep 0.05
        fi

        if [ "$ready" -eq 1 ] && kill -0 "$RUN_PID" 2>/dev/null; then
            kill -TERM "$RUN_PID" 2>/dev/null || true
            wait "$RUN_PID" 2>/dev/null || true
            RUN_PID=""
            booted=$((booted+1))
            return 0
        fi

        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
        RUN_PID=""

        # Port selection is necessarily check-then-bind. If another process wins
        # that race, retry with a new port rather than creating a flaky failure.
        grep -qE "(fetch_proxy.listen|holds) .*127\\.0\\.0\\.1:$port" "$out_file" || break
    done

    # Gate on the DIVERGENCE (check PASS + run REFUSED), not on "run refused".
    #
    # That is deliberate and self-limiting in the right direction. A snippet `check`
    # also rejects is not silent — the user runs check and gets a clear error — and
    # gating on refusal alone floods on reference docs: docs/configuration.md and
    # docs/policy-spec-v0.1.md document ONE section per block, which by design does
    # not stand up as a whole config ("mcp_session_binding requires
    # mcp_tool_scanning"). Those are field references, not copy-paste configs, and
    # `check` filters them out for free.
    #
    # The dangerous case is exactly the one left: we told the operator the file was
    # VALID and then refused to boot on it. If a future release teaches `check` to
    # reject more shapes, this reports fewer rows — that is `check` doing its job,
    # not this going blind.
    #
    # Known limit: a snippet BOTH reject is reported above but is not gated.
    local why
    why="$(environment_failure_reason "$run_cfg" "$out_file")"
    if [ -n "$why" ]; then
        skipped=$((skipped+1))
        echo "  skip ($why): $label" >>"$SKIPS"
        return 0
    fi

    failed=$((failed+1))
    {
        echo "  ✗ $label"
        echo "      check: PASS   run: REFUSED   <- validator/runtime divergence"
        echo "      $(grep -vE '^[[:space:]]*$' "$out_file" | tail -1 | head -c 180)"
    } >>"$FAILURES"
}

mapfile -t FILES < <(git ls-files \
    'docs/*.md' 'docs/**/*.md' \
    'examples/**/*.yaml' 'examples/**/*.yml' \
    'charts/**/examples/*.yaml' \
    'configs/*.yaml' 2>/dev/null | sort -u)

for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    case "$f" in
    *.md)
        tag="$(tr '/' '_' <<<"$f")"
        awk -v outdir="$WORK" -v tag="$tag" '
            { sub(/\r$/, "") }
            /^[ ]?[ ]?[ ]?```ya?ml[[:space:]]*$/ { n++; inblk=1; out=outdir "/" tag "-" n ".yaml"; next }
            /^[ ]?[ ]?[ ]?```/                    { inblk=0; next }
            inblk        { print > out }
        ' "$f"
        n=0
        while :; do
            n=$((n+1))
            blk="$WORK/$tag-$n.yaml"
            [ -f "$blk" ] || break
            probe "$blk" "$f (yaml block $n)"
        done
        ;;
    *)
        probe "$f" "$f"
        ;;
    esac
done

echo ""
echo "config-examples: $total config blocks | $booted booted OK | $skipped skipped | $rejected check-rejected | $failed FAILED"
[ "$skipped" -gt 0 ] && { echo "skipped (not silently dropped):"; cat "$SKIPS"; }
[ "$rejected" -gt 0 ] && { echo "rejected by pipelock check (reference fragments, not gated):"; cat "$REJECTED"; }

if [ "$failed" -gt 0 ]; then
    echo ""
    echo "FAIL: shipped config snippet(s) pass 'pipelock check' but will not start:"
    cat "$FAILURES"
    echo ""
    echo "Each is a config a user can copy-paste that bricks their install."
    echo "Fix the snippet, or make 'pipelock check' reject the shape so the"
    echo "validator and the runtime agree."
    exit 1
fi

echo "config-examples: OK"

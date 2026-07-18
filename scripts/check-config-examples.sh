#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# check-config-examples.sh — shipped config snippets must actually START.
#
# `pipelock check` is a parse/semantic pass; it does not exercise runtime startup
# preconditions. A snippet can therefore pass `check` and still kill `pipelock run`
# at boot — a config we ship that bricks the user who trusted the guide.
#
# This catches the CLASS: any executable doc/example config that `check` rejects,
# or that `check` blesses but the runtime refuses. Config examples are executable
# claims — validate and RUN them. Deliberately incomplete field references must
# opt out visibly with a `yaml pipelock-fragment` fence.
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

# Stateful security paths correctly reject world-writable ancestors. The default
# /tmp parent would make the gate itself manufacture a refusal after relocating a
# documented /var/lib path, so keep the ephemeral sandbox beneath the checkout.
WORK="$(mktemp -d "$REPO_ROOT/.config-examples.XXXXXX")"
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

# Never inherit operator state from the machine running this gate. In particular,
# a real ~/.pipelock CA made TLS examples pass locally and fail on a clean CI
# runner. Give every probe a disposable HOME and fixture the default CA there.
PROBE_HOME="$WORK/home"
mkdir -p "$PROBE_HOME"
if ! HOME="$PROBE_HOME" "$BIN" tls init --out "$PROBE_HOME/.pipelock" >/dev/null 2>&1; then
    echo "config-examples: could not fixture the default TLS CA" >&2
    exit 1
fi

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
enterprise_skip_allowed() {
    local id
    id="$(metadata_value pipelock-enterprise-skip-id "$1")"
    case "$id" in
        conductor-production-follower | \
        conductor-follower-guide | \
        siem-durable-forwarder | \
        conductor-audit-sink-follower) return 0 ;;
        *) return 1 ;;
    esac
}

fragment_expected_error() {
    case "$1" in
        mcp-session-binding) echo "mcp_session_binding.enabled requires mcp_tool_scanning.enabled" ;;
        adaptive-enforcement) echo "adaptive_enforcement.enabled requires session_profiling.enabled" ;;
        license-path-precedence) echo "unmarshal errors" ;;
        license-complete-reference | license-container-layout | license-activation) echo "license" ;;
        trusted-rule-key) echo "public_key must be exactly 64 hex chars" ;;
        a2a-trusted-card-key) echo "trusted_agent_card_keys" ;;
        mediation-signing | federation-inbound-key) echo "mediation_envelope.verify_inbound.trust_list[0].public_key" ;;
        conductor-follower) echo "flight_recorder.signing_key_path required when conductor.enabled is true" ;;
        learn-lock) echo "learn_lock.pinned_root_fingerprint" ;;
        *) echo "" ;;
    esac
}

metadata_value() {
    local key="$1" cfg="$2"
    sed -nE "s/^#[[:space:]]*${key}:[[:space:]]*([a-z0-9-]+)[[:space:]]*$/\\1/p" "$cfg" | head -1
}

environment_failure_reason() {
    local cfg="$1" out="$2" phase="$3"

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

    # Entitlement/build gates are skippable only when they are the sole emitted
    # refusal. A broad substring match would let an enterprise message conceal a
    # second schema, path, or security-validation error in the same output.
    local enterprise_refusals other_refusals
    enterprise_refusals="$(grep -ciE 'requires an enterprise build|requires an Enterprise license that grants' "$out" || true)"
    if [ "$phase" = "run" ] && [ "$enterprise_refusals" -gt 0 ] && enterprise_skip_allowed "$cfg"; then
        # Count independent refusal lines after removing all entitlement
        # refusals. Entitlement lines are not guaranteed to contain an
        # "error:" prefix, so counting it as part of the generic total makes
        # equivalent OSS-build and missing-license failures classify
        # differently.
        other_refusals="$(grep -viE 'requires an enterprise build|requires an Enterprise license that grants' "$out" \
            | grep -ciE '(FAILED:|(^|[[:space:]])error:|invalid config:)' || true)"
        if [ "$other_refusals" -eq 0 ]; then
            echo "requires an enterprise build or license"
            return
        fi
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
    local snippet="$1" label="$2" intent="${3:-config}"
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
    HOME="$PROBE_HOME" "$BIN" check --config "$run_cfg" >"$check_out" 2>&1 && check_ok=1
    if [ "$check_ok" -eq 0 ]; then
        if [ "$intent" = "fragment" ]; then
            local fragment_id expected_fragment_error
            fragment_id="$(metadata_value pipelock-fragment-id "$run_cfg")"
            expected_fragment_error="$(fragment_expected_error "$fragment_id")"
            if [ -z "$expected_fragment_error" ]; then
                failed=$((failed+1))
                {
                    echo "  ✗ $label"
                    echo "      unknown or missing pipelock-fragment-id; add its exact expected refusal to fragment_expected_error"
                } >>"$FAILURES"
                return 0
            fi
            if ! grep -Fqi "$expected_fragment_error" "$check_out"; then
                failed=$((failed+1))
                {
                    echo "  ✗ $label"
                    echo "      fragment '$fragment_id' refusal changed; expected: $expected_fragment_error"
                    echo "      $(grep -m1 -vE '^[[:space:]]*$' "$check_out" | head -c 180)"
                } >>"$FAILURES"
                return 0
            fi
            rejected=$((rejected+1))
            {
                echo "  check rejected (declared fragment): $label"
                echo "      $(grep -m1 -vE '^[[:space:]]*$' "$check_out" | head -c 180)"
            } >>"$REJECTED"
            return 0
        fi

        local check_why
        check_why="$(environment_failure_reason "$run_cfg" "$check_out" check)"
        if [ -n "$check_why" ]; then
            skipped=$((skipped+1))
            echo "  skip ($check_why): $label" >>"$SKIPS"
            return 0
        fi

        failed=$((failed+1))
        {
            echo "  ✗ $label"
            echo "      check: REFUSED   <- invalid executable config example"
            echo "      $(grep -m1 -vE '^[[:space:]]*$' "$check_out" | head -c 180)"
        } >>"$FAILURES"
        return 0
    fi

    if [ "$intent" = "fragment" ]; then
        failed=$((failed+1))
        {
            echo "  ✗ $label"
            echo "      declared fragment unexpectedly became a valid config; remove the exemption or restore the incomplete example"
        } >>"$FAILURES"
        return 0
    fi

    # The startup banner is printed before auxiliary and main listeners bind, so
    # it is not a readiness marker. Complete an HTTP exchange with the main
    # listener, then allow a short grace window for immediate post-bind failures.
    local port out_file="$WORK/out-$total.txt" ready attempt deadline
    for attempt in 1 2 3; do
        ready=0
        port="$(choose_port)" || { echo "config-examples: could not find a free probe port" >&2; exit 1; }
        HOME="$PROBE_HOME" "$BIN" run --listen "127.0.0.1:$port" --config "$run_cfg" >"$out_file" 2>&1 </dev/null &
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

    # Reaching here means `check` accepted an executable example. A subsequent
    # startup refusal is a validator/runtime divergence unless the actual runtime
    # error proves that an operator-supplied resource is unavailable.
    local why
    why="$(environment_failure_reason "$run_cfg" "$out_file" run)"
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

# Stable metadata IDs replace brittle markdown block numbers. They are globally
# unique so moving a block cannot change its policy identity and copying one
# cannot silently inherit another block's exemption.
duplicate_metadata_ids="$(git grep -hE '^#[[:space:]]*pipelock-(fragment|enterprise-skip)-id:[[:space:]]*[a-z0-9-]+' -- 'docs/*.md' 'docs/**/*.md' \
    | sed -E 's/^#[[:space:]]*pipelock-(fragment|enterprise-skip)-id:[[:space:]]*([a-z0-9-]+).*/\2/' \
    | sort | uniq -d)"
if [ -n "$duplicate_metadata_ids" ]; then
    echo "config-examples: duplicate exemption metadata ID(s): $duplicate_metadata_ids" >&2
    exit 1
fi

for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    case "$f" in
    *.md)
        tag="$(tr '/' '_' <<<"$f")"
        awk -v outdir="$WORK" -v tag="$tag" '
            { sub(/\r$/, "") }
            /^[ ]?[ ]?[ ]?```ya?ml([[:space:]]+pipelock-fragment)?[[:space:]]*$/ {
                n++
                inblk=1
                out=outdir "/" tag "-" n ".yaml"
                kind=(index($0, "pipelock-fragment") ? "fragment" : "config")
                print kind > (out ".kind")
                next
            }
            /^[ ]?[ ]?[ ]?```/                    { inblk=0; next }
            inblk        { print > out }
        ' "$f"
        n=0
        while :; do
            n=$((n+1))
            blk="$WORK/$tag-$n.yaml"
            [ -f "$blk" ] || break
            kind="$(cat "${blk}.kind")"
            probe "$blk" "$f (yaml block $n)" "$kind"
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
[ "$rejected" -gt 0 ] && { echo "declared reference fragments rejected with their audited expected error:"; cat "$REJECTED"; }

if [ "$failed" -gt 0 ]; then
    echo ""
    echo "FAIL: shipped executable config snippet(s) are invalid or will not start:"
    cat "$FAILURES"
    echo ""
    echo "Each is presented as a config a user can copy-paste but cannot use."
    echo "Fix it, or label a deliberately incomplete field reference with"
    echo 'a ```yaml pipelock-fragment fence so the exception is explicit.'
    exit 1
fi

echo "config-examples: OK"

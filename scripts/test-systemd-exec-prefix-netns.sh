#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root: sudo bash $0 [agent-user]" >&2
    exit 2
fi

agent_user=${1:-pipelock-agent}
if ! getent passwd "$agent_user" >/dev/null; then
    echo "error: managed agent user $agent_user does not exist" >&2
    exit 2
fi

suffix=$$
target="pipelock-prefix-netns-target-$suffix"
plus="pipelock-prefix-netns-plus-$suffix"
bang="pipelock-prefix-netns-bang-$suffix"
target_file="/run/$target.ns"
plus_file="/run/$plus.ns"
bang_file="/run/$bang.ns"

cleanup() {
    systemctl stop "$target.service" >/dev/null 2>&1 || true
    systemctl reset-failed "$target.service" "$plus.service" "$bang.service" >/dev/null 2>&1 || true
    unlink "$target_file" 2>/dev/null || true
    unlink "$plus_file" 2>/dev/null || true
    unlink "$bang_file" 2>/dev/null || true
}
trap cleanup EXIT

systemd-run \
    --unit="$target" \
    --property=Type=simple \
    --property=PrivateNetwork=true \
    /bin/sh -c "readlink /proc/self/ns/net > '$target_file'; exec sleep 120" >/dev/null

for _attempt in {1..50}; do
    [[ -s $target_file ]] && break
    sleep 0.1
done
if [[ ! -s $target_file ]]; then
    echo "error: managed namespace unit did not publish its identity" >&2
    systemctl status "$target.service" --no-pager >&2 || true
    exit 1
fi

run_probe() {
    local label=$1
    local prefix=$2
    local unit=$3
    local output=$4

    # Pre-create the capture file owned by the agent. A "+" pre-start runs as
    # ROOT, so it would otherwise create this file root-owned and the main
    # process, which runs as the agent, could not append to it. The unit would
    # then fail for a reason that has nothing to do with the namespace question
    # being measured.
    : > "$output"
    chown "$agent_user" "$output"
    chmod 0600 "$output"

    # A failed unit is a RESULT here, not an error: the whole point is to learn
    # what each prefix does. Without this, set -e aborts before the verdict
    # prints and the script looks like it hung.
    local rc=0
    systemd-run \
        --wait \
        --collect \
        --unit="$unit" \
        --property=Type=oneshot \
        --property="User=$agent_user" \
        --property="Group=$agent_user" \
        --property=PrivateNetwork=true \
        --property="JoinsNamespaceOf=$target.service" \
        --property="ExecStartPre=${prefix}/bin/sh -c 'printf PRE_EUID= > $output; id -u >> $output; printf PRE_NETNS= >> $output; readlink /proc/self/ns/net >> $output'" \
        /bin/sh -c "printf MAIN_EUID= >> '$output'; id -u >> '$output'; printf MAIN_NETNS= >> '$output'; readlink /proc/self/ns/net >> '$output'" >/dev/null || rc=$?

    echo "$label raw result: (unit exit $rc)"
    sed 's/^/  /' "$output"
}

classify() {
    local observed=$1
    local target_ns=$2
    local host_ns=$3
    # An absent measurement must not present as a definite verdict. If the
    # probe never wrote its namespace, the honest answer is that we do not
    # know, not that it was somewhere other than the target.
    if [[ -z $observed ]]; then
        printf 'UNKNOWN_NOT_CAPTURED'
        return
    fi
    if [[ $observed == "$target_ns" ]]; then
        printf 'INSIDE'
    elif [[ $observed == "$host_ns" ]]; then
        printf 'OUTSIDE_HOST'
    else
        printf 'OUTSIDE_OTHER'
    fi
}

host_ns=$(readlink /proc/self/ns/net)
target_ns=$(<"$target_file")
echo "HOST_NETNS=$host_ns"
echo "MANAGED_NETNS=$target_ns"

run_probe PLUS + "$plus" "$plus_file"
run_probe BANG '!' "$bang" "$bang_file"

plus_pre=$(sed -n 's/^PRE_NETNS=//p' "$plus_file")
plus_main=$(sed -n 's/^MAIN_NETNS=//p' "$plus_file")
bang_pre=$(sed -n 's/^PRE_NETNS=//p' "$bang_file")
bang_main=$(sed -n 's/^MAIN_NETNS=//p' "$bang_file")
plus_uid=$(sed -n 's/^PRE_EUID=//p' "$plus_file")
bang_uid=$(sed -n 's/^PRE_EUID=//p' "$bang_file")

echo "PLUS_VERDICT=$(classify "$plus_pre" "$target_ns" "$host_ns") pre_euid=$plus_uid"
echo "BANG_VERDICT=$(classify "$bang_pre" "$target_ns" "$host_ns") pre_euid=$bang_uid"
echo "PLUS_MAIN_VERDICT=$(classify "$plus_main" "$target_ns" "$host_ns")"
echo "BANG_MAIN_VERDICT=$(classify "$bang_main" "$target_ns" "$host_ns")"

if [[ $plus_main != "$target_ns" || $bang_main != "$target_ns" ]]; then
    echo "HARNESS_INVALID: a service body failed to join the managed namespace" >&2
    exit 1
fi
if [[ $plus_uid != 0 || $bang_uid != 0 ]]; then
    echo "HARNESS_INVALID: a prefixed pre-start command did not run as root" >&2
    exit 1
fi

echo "RESULT: + is $(classify "$plus_pre" "$target_ns" "$host_ns"); ! is $(classify "$bang_pre" "$target_ns" "$host_ns")"

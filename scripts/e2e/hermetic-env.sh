#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Isolate verification commands from Pipelock state installed on the host.
# The caller owns root_dir and removes it through its existing EXIT trap.
pipelock_hermetic_env() {
  local root_dir="$1"

  if [[ "$root_dir" != /* ]]; then
    printf 'pipelock_hermetic_env: root must be absolute: %s\n' "$root_dir" >&2
    return 1
  fi

  if [[ -v HOME ]]; then
    PIPELOCK_VERIFY_ORIGINAL_HOME="$HOME"
    PIPELOCK_VERIFY_ORIGINAL_HOME_SET=1
  else
    PIPELOCK_VERIFY_ORIGINAL_HOME=""
    PIPELOCK_VERIFY_ORIGINAL_HOME_SET=0
  fi
  # Deliberately NOT exported. Exporting the host home path would hand it to
  # every command run under isolation, including the code under test, which
  # could then reach the very state this function exists to hide. Shell
  # variables still reach pipelock_host_tool, its only consumer.

  umask 077
  mkdir -p \
    "$root_dir/home" \
    "$root_dir/config" \
    "$root_dir/data" \
    "$root_dir/state" \
    "$root_dir/cache" \
    "$root_dir/posture"
  printf 'mode: balanced\n' >"$root_dir/pipelock.yaml"

  export HOME="$root_dir/home"
  export XDG_CONFIG_HOME="$root_dir/config"
  export XDG_DATA_HOME="$root_dir/data"
  export XDG_STATE_HOME="$root_dir/state"
  export XDG_CACHE_HOME="$root_dir/cache"
  export PIPELOCK_CONFIG="$root_dir/pipelock.yaml"
  export PIPELOCK_POSTURE_PROOF="$root_dir/posture/absent-proof.json"
}

# Host tool wrappers may live under the operator's real home. Restore HOME for
# those tools without exposing that home to the Pipelock process under test.
pipelock_host_tool() {
  if [[ "${PIPELOCK_VERIFY_ORIGINAL_HOME_SET:-0}" == "1" ]]; then
    HOME="$PIPELOCK_VERIFY_ORIGINAL_HOME" "$@"
  else
    env -u HOME "$@"
  fi
}

#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Install apt packages in CI without letting a slow mirror cancel the job.
#
# `apt-get update` normally takes about 50 seconds on a GitHub runner. When a
# mirror stalls it does not fail, it hangs, and the job hits its 5 minute limit
# and is cancelled with no project code having run. That happened three times in
# one day across the hardening and release workflows, each time reading as a red
# check on work that was fine.
#
# ci-retry.sh alone does not help, because a hung command never returns for the
# retry to fire. Bounding each attempt is what converts the hang into a fast
# failure that a retry can then absorb, and two bounded attempts plus backoff
# still fit inside the job budget.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: ci-apt-install.sh PACKAGE [PACKAGE...]" >&2
  exit 2
fi

# The runner image already carries some of these. Skipping the network entirely
# when every package is present is both faster and one less thing to stall.
missing=()
for pkg in "$@"; do
  if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
    missing+=("$pkg")
  fi
done
if [ "${#missing[@]}" -eq 0 ]; then
  echo "ci-apt-install: all packages already installed: $*"
  exit 0
fi

: "${CI_APT_TIMEOUT:=120}"

run_bounded() {
  # A non-zero status here is what lets ci-retry.sh try again. timeout exits 124
  # when it kills the command, which is the case this exists for.
  sudo timeout "$CI_APT_TIMEOUT" "$@"
}
export -f run_bounded
export CI_APT_TIMEOUT

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$script_dir/ci-retry.sh" bash -c 'run_bounded apt-get update'
bash "$script_dir/ci-retry.sh" bash -c "run_bounded apt-get install -y ${missing[*]}"

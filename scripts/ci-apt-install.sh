#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Install apt packages in CI without letting a slow mirror cancel the job.
#
# `apt-get update` normally takes about fifty seconds on a GitHub runner, and
# the install about twenty. When a mirror stalls neither fails, they hang, and
# the job hits its limit and is cancelled with no project code having run. That
# happened three times in one day across the hardening and release workflows,
# each time reading as a red check on work that was fine.
#
# A retry alone does not help, because a hung command never returns for the
# retry to fire. Bounding each command is what converts the hang into a fast
# failure that a retry can absorb.
#
# THE BUDGET IS THE WHOLE POINT, so the arithmetic is written out to be checked
# rather than trusted:
#
#   no-update probe    = PROBE_TIMEOUT                      = 45s
#   one attempt        = UPDATE_TIMEOUT + INSTALL_TIMEOUT = 90 + 60 = 150s
#   worst case overall = PROBE_TIMEOUT + (ATTEMPTS * 150s) + BACKOFF
#                      = 45s + (2 * 150s) + 10s
#                      = 355s
#
# The hardening jobs allow 480s, leaving about 125s for checkout and the audit
# work itself, against a job that normally finishes in well under two minutes.
#
# The probe is the common path and costs seconds, so it lowers the EXPECTED time
# while raising the worst case by its own bound. Both numbers still fit, and the
# expected case is what stops the coin flip.
#
# A bound that does not fit its job's limit is not a fix, it is a slower path to
# the same cancellation. The first version of this script used the shared
# three-attempt helper at 120s per attempt across two separate retried calls,
# which is 750s of worst case against a 300s limit: strictly worse than the hang
# it was written to prevent. If a workflow ever needs a larger package set,
# re-derive the numbers above against that job's timeout rather than raising a
# bound on its own.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: ci-apt-install.sh PACKAGE [PACKAGE...]" >&2
  exit 2
fi

readonly ATTEMPTS=2
readonly UPDATE_TIMEOUT=90
readonly INSTALL_TIMEOUT=60
readonly BACKOFF=10

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

# Package names reach apt-get as an argument array and are never rebuilt into a
# command string. Interpolating them into a shell program would re-parse them,
# so a name carrying whitespace or a glob would change the invocation and a name
# that looks like an option would be read as one. The trailing -- stops apt-get
# reading a package name as a flag.
attempt_install() {
  sudo timeout "$UPDATE_TIMEOUT" apt-get update \
    && sudo timeout "$INSTALL_TIMEOUT" apt-get install -y -- "${missing[@]}"
}

# Try installing from the lists the image already carries, before fetching any.
#
# The failure this addresses is throughput, not reachability. Measured on
# 2026-08-19: a run that SUCCEEDED fetched at 237 kB/s and 56 kB/s and needed
# roughly seventy seconds of update, so attempt one blew the ninety-second bound
# and attempt two squeaked through. With two attempts that is a coin flip, and it
# landed both ways within half an hour on two pull requests whose own code was
# fine. Nothing about the mirror was down; an earlier attempt at this rewrote the
# sources to a different host and changed nothing, because the host was never the
# problem.
#
# So skip the fetch entirely where it is not needed. The runner image ships
# package lists, and a package already present in them installs in seconds with
# no index download at all. This lowers the EXPECTED time to seconds and raises
# the worst case by the probe's own bound, from 310s to 355s; the header
# arithmetic carries both numbers and both still fit the job's 480s. The update
# path below is unchanged for the case where the lists really are too old to
# satisfy the request.
readonly PROBE_TIMEOUT=45
attempt_install_without_update() {
  sudo timeout "$PROBE_TIMEOUT" apt-get install -y -- "${missing[@]}"
}

# Announce the path taken. The previous version of this logic had no marker, so a
# log could not answer whether it had run, and confirming that took three reads
# of three different job logs. A step that changes behaviour says so.
if attempt_install_without_update; then
  echo "ci-apt-install: installed from the image's existing lists: ${missing[*]}"
  exit 0
fi
echo "ci-apt-install: existing lists could not satisfy ${missing[*]}; refreshing" >&2

for attempt in $(seq 1 "$ATTEMPTS"); do
  if attempt_install; then
    exit 0
  fi
  if [ "$attempt" -eq "$ATTEMPTS" ]; then
    echo "ci-apt-install: ${ATTEMPTS} attempts failed for: ${missing[*]}" >&2
    exit 1
  fi
  echo "ci-apt-install: attempt ${attempt} of ${ATTEMPTS} failed; retrying in ${BACKOFF}s" >&2
  sleep "$BACKOFF"
done

#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Concurrent-writer evidence integrity gate.
#
# Pipelock ships detectors for damaged evidence, but nothing exercised them
# against a corpus produced by more than one writer at a time. Two data-loss
# defects lived behind that gap: a record and its newline written separately
# could interleave with another writer and merge two records onto one physical
# line, and raw escrow sidecars named from a colliding sequence were written
# with a truncating call so one writer silently destroyed another's payload.
# Both were detectable by `pipelock evidence doctor` the whole time.
#
# This gate produces the adversarial state and points the SHIPPED doctor at it,
# so the check can never drift from what an operator runs. It builds the real
# binary rather than calling internals.
set -euo pipefail

readonly WRITERS=6
readonly ENTRIES_PER_WRITER=40
# Over the recorder's 4096-byte write buffer, so a record and its newline
# cannot coalesce into a single flush by accident. Below the buffer the defect
# is invisible, which is why it survived to production undetected.
readonly PAYLOAD_BYTES=6000

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

bin="$workdir/pipelock"
echo "building the shipped binary"
go build -o "$bin" ./cmd/pipelock

evidence_dir="$workdir/evidence"
mkdir -p "$evidence_dir"

echo "generating a concurrent-writer corpus (${WRITERS} writers, ${ENTRIES_PER_WRITER} entries each, ${PAYLOAD_BYTES}-byte payloads)"
go run ./scripts/gen-concurrent-evidence \
  --dir "$evidence_dir" \
  --writers "$WRITERS" \
  --entries "$ENTRIES_PER_WRITER" \
  --payload-bytes "$PAYLOAD_BYTES"

written=$(find "$evidence_dir" -name '*.jsonl' | wc -l)
if [ "$written" -eq 0 ]; then
  echo "FAIL: the generator produced no evidence files, so the gate proved nothing" >&2
  exit 1
fi
echo "corpus written: $written evidence file(s)"

echo "running the shipped structural doctor"
report="$workdir/doctor.txt"
"$bin" evidence doctor "$evidence_dir" >"$report" 2>&1 || true
cat "$report"

# Concurrent writers still share one chain namespace, so the doctor reports a
# forked sequence. That defect is open and tracked separately; tolerating it
# here is what lets this gate run today instead of waiting for it. Everything
# else must be absent, because everything else is a defect that has been fixed
# and must never come back.
readonly KNOWN_OPEN='duplicate_recorder_seq|conflicting_recorder_prev_hash'

unexpected=$(grep -oE '^  [a-z_]+:' "$report" | tr -d ' :' | grep -vE "^(${KNOWN_OPEN})$" || true)
if [ -n "$unexpected" ]; then
  cat >&2 <<MSG

FAIL: the shipped evidence doctor found damage that is NOT the known open
sequence fork. This gate exists to catch exactly this. Unexpected finding kinds:

$unexpected

  malformed_jsonl   a record and its newline reached the file separately, so
                    another writer appended between them and two records now
                    share one physical line. Both records are unreadable and
                    cannot be recovered.
  raw escrow        two writers derived the same sidecar name and one encrypted
                    payload silently overwrote the other.

Do not silence this by lowering the writer count or the payload size. The payload
is deliberately larger than the recorder write buffer, because below that size a
record and its newline coalesce into one flush and the defect cannot appear.
MSG
  exit 1
fi

echo
echo "PASS: no unexpected structural damage under concurrent writers"
echo "note: the known sequence fork is tolerated here on purpose. When that is"
echo "      fixed, delete it from KNOWN_OPEN in this script so it cannot return."

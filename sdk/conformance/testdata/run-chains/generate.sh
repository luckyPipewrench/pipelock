#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the run-chain conformance fixtures from a real pipelock binary.
#
# Usage: generate.sh /path/to/pipelock [OUTPUT_DIR]
#
# Three proxy runs share one flight-recorder directory:
#   run A  starts first and writes an unlinked chain;
#   run B  restarts after A and publishes a signed link continuing A's tail;
#   run C  starts from a copy of the directory as it was after A only, so it
#          also links A. Its chain and link are used for the double-successor
#          variant, where two runs both claim to continue A.
#
# The script then derives the byte-edited variants from those runs. The two
# variants that need a freshly signed link are written by the Go generator:
#   PIPELOCK_RUN_CHAIN_FIXTURES=1 go test ./sdk/conformance/ -run TestGenerateRunChainFixtures
# That test also rewrites every variant's expect.json from the Go reference
# (internal/receipt VerifyBase), so expectations are never hand-written.
set -euo pipefail

bin=${1:?usage: generate.sh /path/to/pipelock [OUTPUT_DIR]}
out=${2:-$(cd "$(dirname "$0")" && pwd)}
bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")

work=$(mktemp -d "${TMPDIR:-/tmp}/pipelock-run-chains.XXXXXX")
proxy_pid=""
cleanup() {
	if [ -n "$proxy_pid" ]; then kill "$proxy_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

export HOME="$work/home" XDG_CONFIG_HOME="$work/home/.config" PIPELOCK_HOME="$work/home/.pipelock"
mkdir -p "$HOME"
cfg="$work/pipelock.yaml"
"$bin" init --no-auditor --skip-canary --output "$cfg" >"$work/init.log" 2>&1
rec="$work/recorder"
key="$work/keys/flight-recorder-signing.key"
test -f "$key.pub"

free_port() {
	python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

# one_run starts the proxy, sends two requests that policy blocks (a
# loopback destination), and stops it with SIGTERM so the run seals.
one_run() {
	local port
	port=$(free_port)
	"$bin" run --config "$cfg" --listen "127.0.0.1:$port" >"$work/run-$1.log" 2>&1 &
	proxy_pid=$!
	for _ in $(seq 1 200); do
		if curl -s -o /dev/null "http://127.0.0.1:$port/health"; then break; fi
		sleep 0.1
	done
	curl -s -o /dev/null "http://127.0.0.1:$port/fetch?url=http://127.0.0.1:9/one" || true
	curl -s -o /dev/null "http://127.0.0.1:$port/fetch?url=http://127.0.0.1:9/two" || true
	kill -TERM "$proxy_pid"
	wait "$proxy_pid" || true
	proxy_pid=""
}

sessions() { find "$1" -maxdepth 1 -name 'evidence-*.jsonl' -printf '%f\n' | sed -E 's/^evidence-(.*)-[0-9]+\.jsonl$/\1/' | sort -u; }

one_run A
cp -a "$rec" "$work/after-a"
sess_a=$(sessions "$rec")
one_run B
sess_b=$(sessions "$rec" | grep -vx "$sess_a")
cp -a "$rec" "$work/after-b"
rm -rf "$rec"
cp -a "$work/after-a" "$rec"
one_run C
sess_c=$(sessions "$rec" | grep -vx "$sess_a")
cp -a "$rec" "$work/after-c"

# Run D restarts after A with a rotated signing key, following the documented
# rotation ceremony: generate the successor key, endorse it with the retiring
# key while stopped, install it, restart.
rm -rf "$rec"
cp -a "$work/after-a" "$rec"
"$bin" signing key generate --purpose receipt-signing --out "$work/next.key" >"$work/keygen.log" 2>&1
"$bin" signing receipt-rotation endorse --chain "$rec" --session "$sess_a" \
	--prior-key-file "$key" --new-key-file "$work/next.key" --root-key "$key.pub" \
	--out "$work/rotation-endorsement.json" >"$work/endorse.log" 2>&1
cp "$key" "$work/retired.key"
cp "$work/next.key" "$key"
one_run D
sess_d=$(sessions "$rec" | grep -vx "$sess_a")
cp -a "$rec" "$work/after-d"
cp "$work/retired.key" "$key"
test -f "$work/after-b/chain-link-$sess_a.json"
test -f "$work/after-c/chain-link-$sess_a.json"
test -f "$work/after-d/chain-link-$sess_a.json"

# variant NAME SESSION... copies the named chains' shards into OUTPUT/NAME.
variant() {
	local name=$1 src=$2
	shift 2
	rm -rf "${out:?}/$name"
	mkdir -p "$out/$name"
	for s in "$@"; do cp "$src"/evidence-"$s"-*.jsonl "$out/$name/"; done
}

# tamper FILE edits the signed target of the second action receipt, leaving
# the line valid JSON so extraction succeeds and only the signature fails.
tamper() {
	python3 - "$1" <<'EOF'
import json, sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
seen = 0
for i, line in enumerate(lines):
    e = json.loads(line)
    if e.get("type") != "action_receipt":
        continue
    seen += 1
    if seen == 2:
        rec = e["detail"]["action_record"]
        rec["target"] = rec["target"] + "-tampered"
        lines[i] = json.dumps(e, separators=(",", ":"))
        break
else:
    sys.exit("no second action receipt to tamper")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
EOF
}

variant valid "$work/after-b" "$sess_a" "$sess_b"
cp "$work/after-b/chain-link-$sess_a.json" "$out/valid/"

variant tampered-predecessor "$work/after-b" "$sess_a" "$sess_b"
cp "$work/after-b/chain-link-$sess_a.json" "$out/tampered-predecessor/"
tamper "$(ls "$out"/tampered-predecessor/evidence-"$sess_a"-*.jsonl)"

variant tampered-successor "$work/after-b" "$sess_a" "$sess_b"
cp "$work/after-b/chain-link-$sess_a.json" "$out/tampered-successor/"
tamper "$(ls "$out"/tampered-successor/evidence-"$sess_b"-*.jsonl)"

# The link's tail sequence is edited without re-signing it.
variant link-edited "$work/after-b" "$sess_a" "$sess_b"
python3 - "$work/after-b/chain-link-$sess_a.json" "$out/link-edited/chain-link-$sess_a.json" <<'EOF'
import json, sys
link = json.load(open(sys.argv[1], encoding="utf-8"))
link["predecessor_tail_seq"] -= 1
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(link, separators=(",", ":")) + "\n")
EOF

variant link-deleted "$work/after-b" "$sess_a" "$sess_b"

# Two runs claim A. Only one file can carry A's link name, so C's link sits
# under a second name, which Go also reports as a name mismatch.
variant double-successor "$work/after-b" "$sess_a" "$sess_b"
cp "$work/after-c"/evidence-"$sess_c"-*.jsonl "$out/double-successor/"
cp "$work/after-b/chain-link-$sess_a.json" "$out/double-successor/"
cp "$work/after-c/chain-link-$sess_a.json" "$out/double-successor/chain-link-$sess_c.json"

# A restart that changed signing keys. Whether the link is trusted depends on
# what the verifier is given: the first key only, both keys, or the first key
# plus the rotation endorsement.
variant key-rotated "$work/after-d" "$sess_a" "$sess_d"
cp "$work/after-d/chain-link-$sess_a.json" "$out/key-rotated/"
cp "$work/rotation-endorsement.json" "$out/key-rotated/rotation-endorsement.json"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["new_signer_key"])' \
	"$work/rotation-endorsement.json" >"$out/rotated-signer-key.hex"

cp "$key.pub" "$out/signer-key.hex"
# Throwaway key from this generation only, kept so the Go generator can sign
# the re-signed link variants. It signs nothing outside these fixtures.
cp "$key" "$out/signing-key.test-only"
echo "generated run-chain fixtures in $out (A=$sess_a B=$sess_b C=$sess_c)"

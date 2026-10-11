# Receipt Verify Example

Runnable walkthrough for Pipelock **signed action receipts**: a deterministic
SSRF block writes a flight-recorder receipt, `pipelock verify-receipt` accepts
it, and a tampered copy fails verification.

Fully offline: runtime-generated signing key + metadata-IP `/fetch` block.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Block | `/fetch` to `169.254.169.254` returns HTTP 403 |
| Receipt on disk | `evidence-proxy.run.<id>-0.jsonl` contains a fetch `block` receipt |
| Verify pass | `pipelock verify-receipt --key` exits 0 |
| Tamper fails | Changing a captured receipt's signed `action_record.verdict` makes chain verification exit 1 |

## Prerequisites

- `pipelock` on `PATH`, or set `PIPELOCK_BIN`
- Bash 3.2+, `curl`, Python 3

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify

From the repository root:

```bash
./examples/receipt-verify/verify.sh
```

Or from this directory: `./verify.sh` (with `PIPELOCK_BIN` set if needed).

The script's fifth step changes `detail.action_record.verdict` in a captured
`action_receipt` record, then runs `verify-receipt` with the generated public
key. It reports a recorder hash mismatch and exits 1. The next step changes the standalone receipt and requires a signature failure. Receipt-chain verification authenticates the signed `action_record`, including the action, policy hash, verdict, target, and chain linkage. It also checks the outer recorder hashes when present. Hash linkage alone doesn't authenticate unsigned outer fields. An entry's `type` selects the receipt chain; unknown types fail closed.

## Manual Try

```bash
WORK="$(mktemp -d)"
"$PIPELOCK_BIN" signing key generate --purpose receipt-signing --out "$WORK/signing.key"
"$PIPELOCK_BIN" signing pubkey --key-file "$WORK/signing.key" --out "$WORK/signing.key.pub"
# Point flight_recorder.dir at $WORK/evidence and signing_key_path at $WORK/signing.key, then:
"$PIPELOCK_BIN" run --config /path/to/rewritten-pipelock.yaml
curl -sS -G --data-urlencode "url=http://169.254.169.254/latest/meta-data/" \
  "http://127.0.0.1:8888/fetch"
# Stop the proxy with Ctrl-C in its terminal so it writes the transcript root and trailing checkpoint.
EVIDENCE_FILE="$(find "$WORK/evidence" -maxdepth 1 -type f -name 'evidence-proxy.run.*-0.jsonl' -print -quit)"
"$PIPELOCK_BIN" verify-receipt "$EVIDENCE_FILE" --whole-recorder \
  --key "$WORK/signing.key.pub"
```

If `pipelock` is already on your `PATH`, you can use `pipelock` instead of `"$PIPELOCK_BIN"`.

## Config Notes

Block-path receipts do not require `require_receipts: true` — that flag fail-closes
allow-path traffic when emission fails. Keys are generated at runtime under a
temp dir and never committed.

See the [receipt verification guide](../../docs/guides/receipt-verification.md) and [flight recorder guide](../../docs/guides/flight-recorder.md).

## Contributing

Improvements welcome: chain-break case, or `pipelock-verifier` dual-check.
Open a PR against `main`.

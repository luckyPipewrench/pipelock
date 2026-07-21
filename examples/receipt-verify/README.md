# Receipt Verify Example

Runnable walkthrough for Pipelock **signed action receipts**: a deterministic
SSRF block writes a flight-recorder receipt, `pipelock verify-receipt` accepts
it, and a tampered copy fails verification.

Fully offline: runtime-generated signing key + metadata-IP `/fetch` block.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Block | `/fetch` to `169.254.169.254` returns HTTP 403 |
| Receipt on disk | `evidence-proxy-0.jsonl` contains a fetch `block` receipt |
| Verify pass | `pipelock verify-receipt --key` exits 0 |
| Tamper fails | Flipping one signature byte makes verify exit non-zero |

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

## Manual Try

```bash
WORK="$(mktemp -d)"
"$PIPELOCK_BIN" signing key generate --purpose receipt-signing --out "$WORK/signing.key"
"$PIPELOCK_BIN" signing pubkey --key-file "$WORK/signing.key" --out "$WORK/signing.key.pub"
# Point flight_recorder.dir / signing_key_path at $WORK, then:
"$PIPELOCK_BIN" run --config /path/to/rewritten-pipelock.yaml
curl -sS -G --data-urlencode "url=http://169.254.169.254/latest/meta-data/" \
  "http://127.0.0.1:8888/fetch"
"$PIPELOCK_BIN" verify-receipt "$WORK/evidence/evidence-proxy-0.jsonl" \
  --key "$WORK/signing.key.pub"
```

If `pipelock` is already on your `PATH`, you can use `pipelock` instead of `"$PIPELOCK_BIN"`.

## Config Notes

Block-path receipts do not require `require_receipts: true` — that flag fail-closes
allow-path traffic when emission fails. Keys are generated at runtime under a
temp dir and never committed.

See `../../docs/guides/receipt-verification.md` and
`../../docs/guides/flight-recorder.md`.

## Contributing

Improvements welcome: chain-break case, or `pipelock-verifier` dual-check.
Open a PR against `main`.

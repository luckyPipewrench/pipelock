<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Receipt verification

Pipelock's flight recorder generates Ed25519-signed action receipts -- one per
proxied request. Each receipt links to the previous one via a SHA-256 hash
chain, forming a tamper-evident log of every security decision. This guide
covers how to verify receipts, check chain integrity, and use the
cross-implementation conformance suite.

## When to verify

- **After an incident:** Verify the evidence log to confirm it has not been
  tampered with. A broken hash chain or invalid signature means evidence was
  modified after the fact.
- **During audit:** Provide the verified chain to auditors as signed proof of
  what pipelock enforced during a session.
- **In CI/CD:** Run `pipelock verify-receipt` against evidence files produced
  by integration tests to confirm the flight recorder is functioning.
- **Cross-implementation:** Use the conformance suite's golden files to verify
  that a third-party receipt verifier (e.g. Python, TypeScript) agrees with
  the reference Go implementation.

## Verifying a single receipt

```bash
pipelock verify-receipt receipt.json
```

Output on success:

```
OK: receipt.json
  Action ID:   019...
  Action Type: fetch
  Verdict:     allowed
  Target:      https://docs.python.org/3/
  Transport:   fetch
  Timestamp:   2026-04-10T14:30:00Z
  Signer:      70b991eb...
  Chain seq:   42
  Chain prev:  sha256:a1b2c3d4...
```

Pin a specific signer key to reject receipts from unknown signers:

```bash
pipelock verify-receipt receipt.json --key 70b991eb77816fc4ef0ae6a54d8a4119ddc5a16c9711c332c39e743079f6c63e
```

Exit code 0 means valid, exit code 1 means invalid or malformed.

## Verifying a receipt chain

Pass a flight recorder JSONL file to verify the entire hash chain:

```bash
pipelock verify-receipt evidence-proxy-0.jsonl
```

Output on success:

```
CHAIN VALID: evidence-proxy-0.jsonl
  Receipts:  142
  Final seq: 141
  Root hash:  sha256:e5f6a7b8...
  Start:     2026-04-10T14:00:00Z
  End:       2026-04-10T15:30:00Z
```

Chain verification checks:

- Every receipt's Ed25519 signature is valid against the signer key.
- All receipts share the same signer key (or match the `--key` argument).
- `chain_seq` increments by exactly 1 from 0 to N-1.
- The first receipt has `chain_prev_hash: "genesis"`.
- Each subsequent receipt's `chain_prev_hash` equals the SHA-256 hash of
  the previous receipt's canonical JSON.

If any check fails, the output reports which sequence number broke the chain.

## Computing a transcript root

The transcript root is the hash of the final receipt in the chain, serving as
a tamper-evident summary of the entire session:

```bash
pipelock transcript-root evidence-proxy-0.jsonl --key 70b991eb...
```

```
Transcript Root: evidence-proxy-0.jsonl
  Session:       proxy
  Root hash:     sha256:e5f6a7b8...
  Receipt count: 142
  Final seq:     141
  Start:         2026-04-10T14:00:00Z
  End:           2026-04-10T15:30:00Z
```

The `--key` flag is required for transcript roots: the root is only
meaningful if every receipt in the chain was verified against a trusted key.

## How the chain works

Each receipt contains:

- **action_record**: The security decision (action ID, verdict, target,
  transport, policy hash, chain sequence, chain previous hash).
- **signature**: `ed25519:` prefix + hex-encoded Ed25519 signature over
  `SHA-256(canonical JSON of action_record)`.
- **signer_key**: Hex-encoded Ed25519 public key of the signer.

The chain links receipts via `chain_prev_hash`:

```
Receipt 0:  chain_seq=0, chain_prev_hash="genesis"
Receipt 1:  chain_seq=1, chain_prev_hash=sha256(receipt_0)
Receipt 2:  chain_seq=2, chain_prev_hash=sha256(receipt_1)
...
```

Inserting, removing, or modifying any receipt breaks the chain at that point.

## Cross-implementation conformance suite

The `sdk/conformance/` directory contains golden test vectors for any
receipt verifier implementation:

| File | Purpose |
|------|---------|
| `testdata/test-key.json` | Test keypair seed and public key hex |
| `testdata/valid-single.json` | Single valid receipt, seq 0, genesis prev |
| `testdata/valid-chain.jsonl` | Five-receipt chain (one JSON per line) |
| `testdata/invalid-signature.json` | Valid structure with tampered signature |
| `testdata/broken-chain.jsonl` | Five receipts with a prev_hash break at seq 3 |

The signing key is deterministic (seeded from a known phrase) so the golden
files can be regenerated bit-identical:

```bash
go test ./sdk/conformance/ -run TestGenerateGoldenFiles -update
```

### Writing a verifier in another language

1. Parse `test-key.json` to get the test public key.
2. Verify `valid-single.json`: signature must pass, action record must
   parse correctly.
3. Verify `valid-chain.jsonl`: all 5 signatures must pass, chain must be
   unbroken (seq 0-4, genesis first, prev_hash links valid).
4. Reject `invalid-signature.json`: signature verification must fail.
5. Reject `broken-chain.jsonl`: chain verification must fail at seq 3.

A reference Python verifier is available at
[pipelock-verify-python](https://github.com/luckyPipewrench/pipelock-verify-python).

## See also

- [Flight recorder guide](flight-recorder.md) for configuring evidence logging
- [Mediation envelope guide](mediation-envelope.md) for receipt ID correlation
- [Configuration reference](../configuration.md#flight-recorder-v21) for all recorder fields

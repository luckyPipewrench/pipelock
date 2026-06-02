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

When verifying a file-based evidence capture, `transcript-root` derives the
`SessionID` from the first entry in the file rather than the `--session`
flag (which still controls the session ID for directory-based chain scans).
An empty evidence file — zero receipts — fails with a non-zero exit code
rather than silently printing a valid-looking root, so scripts can trust
an exit-0 status to mean "receipts were present and the chain verified."

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

## Resume and rotation integrity

When pipelock restarts or rotates the evidence file, the receipt emitter
resumes the chain from the last persisted receipt. v2.2.0 hardens the
resume path in three ways:

- **Tail signature verification:** the resume code verifies the Ed25519
  signature of the tail receipt before trusting its `chain_seq` and
  chain hash. A tampered or partially-corrupted evidence file fails
  fast rather than letting the next emitted receipt silently continue
  from attacker-controlled state.
- **Atomic resume:** the recorder computes the resumed sequence number,
  previous hash, and first-sequence-in-span into local temporaries and
  only mutates its internal state after all filesystem reads succeed.
  A transient read error no longer leaves a half-initialised chain
  that restarts from genesis.
- **uint64 sequence parsing:** file ordering during resume uses
  `strconv.ParseUint` so evidence filenames with sequence numbers
  greater than `math.MaxInt` (or 32-bit builds) order correctly.

These hardenings are transparent to verifiers — the wire format is
unchanged. They protect the emitter side from bugs and tampering that
would have produced broken or forgeable chains at restart.

## Standalone `pipelock-verifier` CLI

As of v2.5.0, Pipelock ships a standalone `pipelock-verifier` binary under
`cmd/pipelock-verifier/`. It verifies legacy ActionReceipt v1 receipts and
chains, EvidenceReceipt v2 envelopes and chains, and Audit Packets without
running the proxy — auditors and SIEMs can drop it next to the agent platform
without inheriting any of Pipelock's runtime surface.

```bash
# Verify an individual receipt
pipelock-verifier receipt receipt.json

# Verify a full chain
pipelock-verifier chain evidence-proxy-0.jsonl

# Verify an EvidenceReceipt v2 shadow chain with provenance
pipelock-verifier chain evidence-proxy-0.jsonl \
  --key receipt-signing.pub \
  --expect-payload-kind shadow_delta \
  --expect-contract sha256:...

# Verify an Audit Packet directory or packet.json file
pipelock-verifier audit-packet ./audit-packet
```

For EvidenceReceipt v2, `--key` pins the trusted Ed25519 receipt-signing public
key. Without `--key`, the verifier can check structure, hash linkage, sequence
monotonicity, and signer-id consistency, but it reports signatures as not
checked because v2 receipts do not embed public keys.

The standalone binary reads the same Audit Packet v0 schema and receipt signing
conventions as the in-tree `pipelock verify-receipt` subcommand, plus the
EvidenceReceipt v2 schema used by learn-and-lock. It returns exit 0 for valid
evidence, exit 1 for invalid evidence, exit 2 for runtime errors, and exit 64
for CLI usage errors. Use this binary in post-incident review and nightly audit
jobs.

## Language-portable verifier packages

Pipelock v2.5.0 publishes first-party verifier libraries for three runtimes,
all of which validate the same canonical conformance vectors used by the
Go reference verifier. Pick whichever fits your downstream audit pipeline:

| Runtime | Path | Use case |
|---|---|---|
| Go (in-tree reference) | `sdk/audit-packet/` and `cmd/pipelock-verifier/` | Server-side audit pipelines, CI workflows, EvidenceReceipt v2 receipt/chain verification |
| TypeScript | [`sdk/verifiers/ts/`](../../sdk/verifiers/ts/) | Node-based audit / SIEM, browser-side evidence inspection |
| Rust | [`sdk/verifiers/rust/`](../../sdk/verifiers/rust/) | Embedded use, audit-platform sidecars, no-runtime environments |
| Python (companion) | [`pipelock-verify-python`](https://github.com/luckyPipewrench/pipelock-verify-python) | Python-based audit pipelines and Jupyter analysis. v1 chains today; EvidenceReceipt v2 envelopes after the prepared 0.2.0 release. |

The TypeScript and Rust verifiers ship with their own test suites that
exercise the canonical vectors from the Go schema package, so a schema
change that breaks any verifier fails the release before the tag. The
verifier-CI workflow runs these tests on every PR.

## Audit Packet v0 schema

The canonical packet schema lives at [`sdk/audit-packet/`](../../sdk/audit-packet/).
It defines the evidence bundle around a receipt chain: run identity, observed
policy hashes, verdict totals, verifier trust state, posture claims, and
artifact paths. Downstream verifiers in any language read the same schema, so
a verifier you write against the schema today keeps working as long as the
schema major version (`v0`) stays stable.

The schema covers:

- **Run identity.** Provider, repository, workflow, ref, SHA, agent identity,
  and run timestamps.
- **Policy evidence.** Sorted policy hashes observed in receipts plus optional
  config snapshot digest.
- **Receipt summary.** Eight verdict buckets (`allow`, `block`, `warn`, `ask`,
  `strip`, `forward`, `redirect`, `other`), transport counts, blocked-layer
  counts, domains touched, and optional inline receipt summaries.
- **Verifier trust.** `valid` evidence must be tied to a pinned signer key;
  `self_consistent_only` proves hash-chain consistency but not signer
  provenance.
- **Posture claims.** Runtime status for raw sockets, Docker socket exposure,
  DNS/UDP, browser proxying, WebSocket frame scanning, and explicit
  unsupported paths.
- **Artifact containment.** Packet artifact paths are relative, non-empty, and
  cannot escape the packet directory.

The Go bindings under `sdk/audit-packet/` are the language reference;
they ship the canonical conformance vectors that every other verifier
implementation tests against.

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
First-party TypeScript and Rust verifiers ship in-tree under
`sdk/verifiers/ts/` and `sdk/verifiers/rust/`; the standalone
`pipelock-verifier` Go CLI ships under `cmd/pipelock-verifier/`. The Go,
TypeScript, and Rust implementations validate the same canonical conformance
vectors; the Python companion continues to cover the v1 chain surface noted
above.

## See also

- [Flight recorder guide](flight-recorder.md) for configuring evidence logging
- [Mediation envelope guide](mediation-envelope.md) for receipt ID correlation
- [Receipt transport coverage](receipt-transports.md) for the per-transport emission matrix and error-path receipt coverage
- [Configuration reference](../configuration.md#flight-recorder-v21) for all recorder fields

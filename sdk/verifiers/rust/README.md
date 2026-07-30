# Pipelock Rust Verifier

`pipelock-verifier-rs` is the Rust reference verifier for Pipelock Audit Packet
v0, ActionReceipt v1, and the EvidenceReceipt v2 spanned proxy-decision
conformance fixture.

## Install

From crates.io (published as
[`pipelock-verifier-rs`](https://crates.io/crates/pipelock-verifier-rs)):

```bash
# --locked uses the crate's pinned Cargo.lock for a reproducible build
# (recommended for a security verifier).
cargo install --locked pipelock-verifier-rs
pipelock-verifier-rs receipt receipt.json --key <hex>
```

The Audit Packet v0 schema is embedded in the binary at compile time, so
verification works fully offline with no network access.

To build from source instead:

```bash
cargo build --release   # binary at target/release/pipelock-verifier-rs
```

## Usage

It provides these commands:

```text
pipelock-verifier-rs audit-packet PATH [--json] [--key HEX_OR_FILE] [--offline] [--allow-self-consistent-only] [--no-trust-required] [--expect-sha256 HEX]
pipelock-verifier-rs chain PATH [--json] [--key HEX_OR_FILE] [--rotation-endorsement FILE]... [--dir] [--session-id ID]
pipelock-verifier-rs receipt PATH [--json] [--key HEX_OR_FILE]
```

Exit codes match the Go and TypeScript verifiers:

- `0` valid
- `1` invalid
- `2` runtime error
- `64` usage error

The verifier embeds the Audit Packet v0 schema at compile time, validates structural invariants, verifies Ed25519 receipt signatures, replays receipt chains with the `genesis` root, and cross-checks packet totals, receipt count, root hash, final sequence, and verdict consistency. The `receipt` command also verifies EvidenceReceipt v2 `proxy_decision_with_spans` receipts with a pinned `--key`, including the JCS preimage and strict source-span payload shape.

For an ActionReceipt v1 chain that rotated signing keys, pin the original root
and pass one `--rotation-endorsement` for each rotation boundary:

```bash
pipelock-verifier-rs chain evidence.jsonl \
  --key receipt-root.pub \
  --session-id proxy \
  --rotation-endorsement rotation-2026-07-30.json
```

Each endorsement is verified under the retiring key and matched to the exact
prior sequence, tail hash, recorder session, and successor key. Missing,
altered, duplicate, replayed, cross-session, and unused endorsements fail
closed.

Signer keys may be raw 32-byte hex, the versioned `pipelock-ed25519-public-v1` text format, or a file containing either form.
Trusted Audit Packet verification requires an external `--key` or an
out-of-band `--expect-sha256` packet digest. A packet's embedded signer key
cannot establish its own provenance. The explicitly weaker
`--allow-self-consistent-only` and `--no-trust-required` modes retain their
documented opt-in behavior. `--offline` skips receipt-chain verification while
still validating the schema and packet-level trust fields.

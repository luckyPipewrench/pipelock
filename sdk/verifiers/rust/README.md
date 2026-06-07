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
pipelock-verifier-rs chain PATH [--json] [--key HEX_OR_FILE] [--dir] [--session-id ID]
pipelock-verifier-rs receipt PATH [--json] [--key HEX_OR_FILE]
```

Exit codes match the Go and TypeScript verifiers:

- `0` valid
- `1` invalid
- `2` runtime error
- `64` usage error

The verifier embeds the Audit Packet v0 schema at compile time, validates structural invariants, verifies Ed25519 receipt signatures, replays receipt chains with the `genesis` root, and cross-checks packet totals, receipt count, root hash, final sequence, and verdict consistency. The `receipt` command also verifies EvidenceReceipt v2 `proxy_decision_with_spans` receipts with a pinned `--key`, including the JCS preimage and strict source-span payload shape.

Signer keys may be raw 32-byte hex, the versioned `pipelock-ed25519-public-v1` text format, or a file containing either form.

# Pipelock Rust Verifier

`pipelock-verifier-rs` is the Rust reference verifier for Pipelock Audit Packet v0.

It provides three commands:

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

The verifier embeds the Audit Packet v0 schema at compile time, validates structural invariants, verifies Ed25519 receipt signatures, replays receipt chains with the `genesis` root, and cross-checks packet totals, receipt count, root hash, final sequence, and verdict consistency.

Signer keys may be raw 32-byte hex, the versioned `pipelock-ed25519-public-v1` text format, or a file containing either form.

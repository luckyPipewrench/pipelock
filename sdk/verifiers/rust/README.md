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
pipelock-verifier-rs audit-packet PATH [--json] [--key HEX_OR_FILE]... [--offline] [--allow-self-consistent-only] [--no-trust-required] [--expect-sha256 HEX]
pipelock-verifier-rs chain PATH [--json] [--key HEX_OR_FILE]... [--rotation-endorsement FILE]... [--dir] [--session-id ID]
pipelock-verifier-rs group EVIDENCE_DIR --group-id ID --key HEX_OR_FILE... [--json]
pipelock-verifier-rs receipt PATH [--json] [--key HEX_OR_FILE]
```

`group` verifies one signed multi-shard receipt group, including each shard's
receipt chains and native AEL stream, the signed close, and any predecessor
transition. It also walks every other session in the directory as a whole v1
chain against the pinned keys, and checks an unclosed predecessor's checkpoint
signatures and v1 and v2 chains. It requires externally pinned `--key` values. A missing signed
close reports `GROUP_INCOMPLETE` and exits nonzero; only a fully checked group
reports `GROUP_VALID` with exit code zero.

Exit codes match the Go and TypeScript verifiers:

- `0` valid
- `1` invalid
- `2` runtime error
- `64` usage error

The verifier embeds the Audit Packet v0 schema at compile time, validates structural invariants, verifies Ed25519 receipt signatures, replays receipt chains with the `genesis` root, and cross-checks packet totals, receipt count, root hash, final sequence, and verdict consistency. The `receipt` command also verifies EvidenceReceipt v2 `proxy_decision_with_spans` receipts with a pinned `--key`, including the JCS preimage and strict source-span payload shape.

Every Pipelock process run writes its own receipt chain, named `<base>.run.<id>`, and a restart can leave a signed `chain-link-<predecessor>.json` file naming the exact tail it continues. With `--dir` and no `--session-id`, `pipelock-verifier-rs chain DIR --dir --key KEY` verifies every run chain of the `proxy` base, then checks each link file: its signature, that it names the predecessor's exact last receipt, that no predecessor has two successors, and that a signing-key change across a restart is covered by `--key` or a `--rotation-endorsement` signed by the retiring key. The report lists each run, then a `RESTART CONTINUITY` summary with linked and unlinked runs. An unlinked run is not a failure, because a first run, concurrent runs, and runs by older binaries are all unlinked, but it's also what a deleted link file looks like, so a passing result doesn't prove no run's evidence is missing. With `--session-id S`, run S is verified and S's whole base is still checked, so the result fails when any run in that base has a finding, and the finding names that run. A directory with no run chains keeps single-session verification. A file belongs to a session only when its parsed name matches exactly, so session `s` doesn't read `evidence-s-evil-0.jsonl`, and every entry in it must carry that session's `session_id`: a file named for one run that holds another run's entries is refused. Inside the directory, a symlinked evidence or link file is refused; a file you name on the command line is read as given, symlink or not. The directory you pass can't be a symlink or go through one, even when a later `..` in the path cancels it lexically, because that path opens a different directory from the one its text names. A current run writes an ActionReceipt v1 chain and an EvidenceReceipt v2 chain into the same files; when a file or session holds both, it's valid only when both verify, and a failure names the chain it came from. A file or shard holding only v2 receipts is verified as a v2 chain. The recorder's own entry hash chain is checked in every mode and reported as `outer_chain_broken`. That chain is unkeyed, so it catches an edit made without recomputing the hashes and nothing more; the receipt signatures are what authenticate the content. Read alone, a shard after a session's first fails that check, because its first entry doesn't start the chain. Two runs whose signed action records carry the same `run_nonce` are reported as `duplicate_run_nonce`, because one process run writes one chain. These checks match the Go reference `pipelock verify-receipt --chain DIR`. Every failing run prints a one-line `verification failed:` reason on stderr, in JSON mode too.

When a run's last shard was torn by a crash, its `chain-link-<predecessor>.json` slot can hold a signed recovery seal (`kind: recovery_seal`, version 1) instead of an ordinary link. The verifier checks the seal's signature, that it names the damaged shard's exact bytes, size and complete-prefix tail, and that it names the successor run's opening receipt. A valid seal is reported as `attested_discontinuity`: the successor counts as linked across an attested gap, and that finding alone keeps the result failing. When the torn suffix can't be parsed as a record, the predecessor is also reported as `corrupt_chain`; when the only damage is a complete final record missing its newline, `attested_discontinuity` is the finding. A seal moved to another shard, run or slot, or a shard changed after sealing, is rejected and the successor stays unlinked. A seal records what Pipelock observed, not that the damage was accidental. See `docs/specs/evidence-recovery-seal-v1.md`.

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
`--key` repeats to pin a set of trusted keys, as it does for the Go reference. `audit-packet` verifies both receipt chains its evidence file holds, so a forged EvidenceReceipt v2 fails the packet even though the packet's counts and root describe the ActionReceipt v1 chain.

Trusted Audit Packet verification requires an external `--key` or an
out-of-band `--expect-sha256` packet digest. A packet's embedded signer key
cannot establish its own provenance. The explicitly weaker
`--allow-self-consistent-only` and `--no-trust-required` modes retain their
documented opt-in behavior. `--offline` skips receipt-chain verification while
still validating the schema and packet-level trust fields.

When full verification fails, the report never repeats the packet's own trust claim: a packet that claimed `verdict: valid` or `self_consistent_only` is reported as `verdict: invalid` with `trusted: false` and `valid: false`. A successful report is unchanged.

### Schema-only Audit Packet checks

`audit-packet --offline` checks the packet schema without authenticating its
signer or verdict. The report uses `verdict: schema_checked_trust_unverified`,
`trusted: false`, and `valid: false`; the CLI exits nonzero. JSON and CI
consumers must require full chain verification before accepting a trusted
verdict.

## Fixture-only secret-egress receipts

The `receipt` command also understands the candidate EvidenceReceipt v2 kind
`secret_egress_decision_v1`, exercised by the shared signed corpus under
`sdk/conformance/testdata/secret-egress-v1/`. It requires the matching critical
feature, policy hash, registry commitment and strict typed decision fields.
Ordinary JCS formatting semantics are preserved. Structural/signature success
does not establish registry membership, policy compliance, producer coverage or
durable append; no production transport emits this kind yet.

For this kind, raw readers enforce exact envelope fields, canonical unsigned
integer tokens, unescaped ASCII canonical UTC RFC3339Nano timestamps, and the
16 KiB raw decision
bound. Insignificant whitespace and object key order remain permitted. Library
callers handling untrusted JSON should use `run_receipt` or
`util::parse_json_text` before verification; an independently constructed
`serde_json::Value` cannot retain duplicate keys or original numeric spelling.

# Pipelock TypeScript Verifier

Reference TypeScript verifier for Pipelock Audit Packet v0, action receipts,
receipt chains, and the EvidenceReceipt v2 spanned proxy-decision conformance
fixture.

## Install

From npm (published as [`@pipelock/verifier-ts`](https://www.npmjs.com/package/@pipelock/verifier-ts)):

```bash
# Global CLI:
npm install -g @pipelock/verifier-ts
pipelock-verifier-ts receipt receipt.json --key <hex>

# Or as a project dependency (CLI available via npx):
npm install @pipelock/verifier-ts
npx pipelock-verifier-ts receipt receipt.json --key <hex>
```

The Audit Packet v0 schema is bundled in the package, so verification works
fully offline with no network access.

### Build from source

```bash
npm install
npm run build
```

The package exposes `pipelock-verifier-ts` after build.

## Usage

```bash
pipelock-verifier-ts audit-packet PATH [--json] [--key HEX_OR_FILE]... [--offline]
pipelock-verifier-ts chain PATH [--json] [--key HEX_OR_FILE]... [--rotation-endorsement FILE]... [--dir] [--session-id ID]
pipelock-verifier-ts receipt PATH [--json] [--key HEX_OR_FILE]
```

Exit codes match the Go verifier:

| Code | Meaning         |
| ---- | --------------- |
| 0    | valid           |
| 1    | invalid         |
| 2    | runtime error   |
| 64   | CLI usage error |

`audit-packet` validates `packet.json` against `sdk/audit-packet/v0.json`, applies the structural v0 checks, and re-verifies the referenced receipt chain unless `--offline` is set. `chain` accepts either an `evidence.jsonl` file or a recorder session directory with `--dir`. `receipt` verifies one receipt JSON file. For EvidenceReceipt v2, `receipt` requires a pinned `--key`, verifies the JCS preimage, and enforces strict validation for supported v2 payload kinds, including source-span rules for `proxy_decision_with_spans`.

Every Pipelock process run writes its own receipt chain, named `<base>.run.<id>`, and a restart can leave a signed `chain-link-<predecessor>.json` file naming the exact tail it continues. With `--dir` and no `--session-id`, `pipelock-verifier-ts chain DIR --dir --key KEY` verifies every run chain of the `proxy` base, then checks each link file: its signature, that it names the predecessor's exact last receipt, that no predecessor has two successors, and that a signing-key change across a restart is covered by `--key` or a `--rotation-endorsement` signed by the retiring key. The report lists each run, then a `RESTART CONTINUITY` summary with linked and unlinked runs. An unlinked run is not a failure, because a first run, concurrent runs, and runs by older binaries are all unlinked, but it's also what a deleted link file looks like, so a passing result doesn't prove no run's evidence is missing. With `--session-id S`, run S is verified and S's whole base is still checked, so the result fails when any run in that base has a finding, and the finding names that run. A directory with no run chains keeps single-session verification. A file belongs to a session only when its parsed name matches exactly, so session `s` doesn't read `evidence-s-evil-0.jsonl`, and every entry in it must carry that session's `session_id`: a file named for one run that holds another run's entries is refused. Inside the directory, a symlinked evidence or link file is refused; a file you name on the command line is read as given, symlink or not. The directory you pass can't be a symlink or go through one, even when a later `..` in the path cancels it lexically, because that path opens a different directory from the one its text names. A current run writes an ActionReceipt v1 chain and an EvidenceReceipt v2 chain into the same files; when a file or session holds both, it's valid only when both verify, and a failure names the chain it came from. A file or shard holding only v2 receipts is verified as a v2 chain. The recorder's own entry hash chain is checked in every mode and reported as `outer_chain_broken`. That chain is unkeyed, so it catches an edit made without recomputing the hashes and nothing more; the receipt signatures are what authenticate the content. Read alone, a shard after a session's first fails that check, because its first entry doesn't start the chain. Two runs whose signed action records carry the same `run_nonce` are reported as `duplicate_run_nonce`, because one process run writes one chain. These checks match the Go reference `pipelock verify-receipt --chain DIR`. Every failing run prints a one-line `verification failed:` reason on stderr, in JSON mode too.

When a run's last shard was torn by a crash, its `chain-link-<predecessor>.json` slot can hold a signed recovery seal (`kind: recovery_seal`, version 1) instead of an ordinary link. The verifier checks the seal's signature, that it names the damaged shard's exact bytes, size and complete-prefix tail, and that it names the successor run's opening receipt. A valid seal is reported as `attested_discontinuity`: the successor counts as linked across an attested gap, the damage stays a `corrupt_chain` finding, and the result still fails. A seal moved to another shard, run or slot, or a shard changed after sealing, is rejected and the successor stays unlinked. A seal records what Pipelock observed, not that the damage was accidental. See `docs/specs/evidence-recovery-seal-v1.md`.

For an ActionReceipt v1 chain that rotated signing keys, pin the original root
and pass one `--rotation-endorsement` for each rotation boundary:

```bash
pipelock-verifier-ts chain evidence.jsonl \
  --key receipt-root.pub \
  --session-id proxy \
  --rotation-endorsement rotation-2026-07-30.json
```

Each endorsement is verified under the retiring key and matched to the exact
prior sequence, tail hash, recorder session, and successor key. Missing,
altered, duplicate, replayed, cross-session, and unused endorsements fail
closed.

`--key` repeats to pin a set of trusted keys, as it does for the Go reference. `audit-packet` verifies both receipt chains its evidence file holds, so a forged EvidenceReceipt v2 fails the packet even though the packet's counts and root describe the ActionReceipt v1 chain.

Trusted Audit Packet verification requires an external `--key` or an
out-of-band `--expect-sha256` packet digest. A packet's embedded signer key
cannot establish its own provenance. The explicitly weaker
`--allow-self-consistent-only` and `--no-trust-required` modes retain their
documented opt-in behavior. `--offline` is schema-only and deliberately skips
receipt-chain verification.

When full verification fails, the report never repeats the packet's own trust claim: a packet that claimed `verdict: valid` or `self_consistent_only` is reported as `verdict: invalid` with `trusted: false` and `valid: false`. A successful report is unchanged.

## Development

```bash
npm run typecheck
npm run build
npm test
```

The ActionReceipt v1 canonical encoder intentionally mirrors Go `encoding/json` for the receipt structs: declaration-order fields, Go `omitempty`, sorted map keys, compact output, and Go's default HTML escaping. This byte-level behavior is part of the v1 verifier contract. EvidenceReceipt v2 signatures use their declared JCS profile instead.

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

Use `runReceipt` or recorder extraction for untrusted serialized input. These
paths check the new-kind source profile before typed verification, including
integer-token spelling. `normalizeEvidenceReceipt` and `verifyEvidenceReceipt`
accept already-decoded objects: JavaScript represents parsed `1`, `1.0` and
`1e0` as the same number, so those APIs cannot certify the discarded spelling.
They still reject an unsupported version value such as `1.5`.

The source profile permits JCS-equivalent whitespace, property order and escaped
property names. It is not a byte-for-byte comparison with Go's emitted JSON;
Go's separate `VerifyV2BytesWithKey` API supplies that stronger check. The
new-kind integer, timestamp and signature-string restrictions still apply.

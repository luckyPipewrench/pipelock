# Pipelock Audit Packet v0

The Audit Packet is the evidence bundle Pipelock writes after a Pipelock-mediated agent run.
It pairs a verifier verdict from the signed receipt chain with the enforcement posture that
produced it, so a relying party (CISO, auditor, downstream platform) can decide whether the
run is trustworthy without re-running the agent.

This directory holds the locked v0 spec.

| File          | What it is                                                              |
| ------------- | ----------------------------------------------------------------------- |
| `v0.json`     | JSON Schema (draft 2020-12). The canonical contract.                    |
| `example.json`| Fully populated minimal packet that conforms to `v0.json`.              |
| `audit_packet.go` | Go bindings (struct tags match `v0.json` field names).              |
| `CHANGELOG.md`| Schema-version history. Independent of pipelock binary versions.        |

The threat model that governs how to read a packet, including what a verified verdict does and does not prove, lives in [`docs/security/audit-packet-threat-model.md`](../../docs/security/audit-packet-threat-model.md).

## Where packets come from

The first packet producer is the
[`pipelock-agent-egress-action`](https://github.com/luckyPipewrench/pipelock-agent-egress-action)
GitHub Action. It runs an agent script under a Linux netns + iptables + setpriv boundary,
emits signed receipts via Pipelock's flight recorder, runs the receipt verifier after exit,
and writes the four artifact files below into the Audit Packet directory:

| File             | What                                                                  |
| ---------------- | --------------------------------------------------------------------- |
| `packet.json`    | The structured packet that conforms to this schema.                   |
| `summary.md`     | Human-readable summary of `packet.json` for PR reviewers.             |
| `evidence.jsonl` | Byte-for-byte receipt chain (one `action_receipt` per line).          |
| `verifier.txt`   | Raw stdout/stderr from `pipelock verify-receipt`.                     |

`packet.json` is the entry point. `evidence.jsonl` is the underlying signed input.

## What the schema enforces

The schema is the contract between producers (the action, future producers) and consumers
(verifiers, SIEM exporters, compliance evidence pipelines). It locks down:

- **Top-level shape.** Required: `schema_version`, `generated_at`, `run`, `policy`, `summary`,
  `verifier`, `posture`, `artifacts`. Optional: `packet_id`, `receipts`, `scanner_config_snapshot`.
- **Verdict bucket set.** Eight buckets keyed by pipelock's seven `config.Action*` constants
  (`allow`, `block`, `warn`, `ask`, `strip`, `forward`, `redirect`) plus `other` for unrecognized
  verdicts. Producers MUST emit all eight keys, even when zero, so consumers can sum without
  nil-checks.
- **Verifier verdict enum.** `valid`, `invalid`, `error`, `not_run`, `self_consistent_only`.
  `self_consistent_only` is required: it captures the realistic case where a chain hashes
  correctly but no signer key was pinned — the chain proves internal consistency, not Pipelock
  provenance. Consumers that conflate this with `valid` defeat the whole point of pinning.
- **Posture status enums.** `raw_socket_status`, `docker_socket_status`, `dns_udp_status`,
  `browser_proxy_status`, and `websocket_frame_scanning` each have a closed enum.
  Producers MUST emit all five plus `unsupported_paths`; the first four use `unknown` for
  "not probed" and `websocket_frame_scanning` uses `off`. `unsupported_paths` is a
  required array of egress vectors the producer explicitly does not enforce; emit an
  empty array when none are known. Consumers reading `unknown` treat it as no claim,
  not as a denial.
- **Verifier trust semantics.** `verifier.trusted` is required. `verdict=valid` requires
  `trusted=true` and a signer key; all other verifier verdicts require `trusted=false`.
- **`additionalProperties: false`** at the top level and on most nested objects. Schema-version
  bumps add fields; v0 packets must NOT silently smuggle unknown fields.

## Rationale

`v0.json` was reconciled from two earlier drafts:

1. A schema sketch favoring 3-bucket totals and nested `run` / `policy` / `summary`.
2. The shape the action repo's `audit-packet.sh` actually emits (8-bucket totals, flat top
   level, `verifier.trusted` boolean, additional posture runtime fields).

The merged spec keeps the impl's 8-bucket totals (each maps 1:1 to a `config.Action*` constant
— summarizing `strip` and `redirect` into `block` would lose forensic granularity), the draft's
nested `run` / `policy` blocks (so a CISO can ctrl-F `policy_hash` and find it in one section),
and the impl's `self_consistent_only` verdict (it already happens; consumers need to model it).

Posture-claim fields from the draft (`raw_socket_status`, `docker_socket_status`, etc.) and
`unsupported_paths` are required because the packet's job is to document _what was enforced_,
not just _what the receipts said_. A clean receipt chain under a posture that admits
unsupported paths is weaker evidence than the same chain under stricter posture, and the
schema needs to make that visible to relying parties.

## Validating a packet

The Go binding lives in this directory:

```go
import auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"

var p auditpacket.Packet
if err := json.Unmarshal(data, &p); err != nil {
    return err
}
if err := p.Validate(); err != nil {
    return err
}
```

`Packet.Validate()` enforces structural invariants the JSON Schema also enforces: required
semantic fields, enum values, non-negative counts, verifier trust semantics, summary total
consistency, sorted unique domains, and artifact path containment. For full schema-level
validation, including JSON key presence and `additionalProperties: false`, run any JSON
Schema 2020-12 validator against `v0.json`; we do not ship a validator dependency in
pipelock to keep the direct-dependency count minimal.

## Versioning

Schema versions are independent from pipelock binary releases. The schema_version constant
(`pipelock.audit_packet.v0`) MUST NOT change across pipelock minor or patch releases. A v1
schema would be a new file at `sdk/audit-packet/v1.json`.

See [CHANGELOG.md](CHANGELOG.md) for what each schema version locks down.

## Out of scope for v0

- **Multi-agent rollups.** v0 packets describe a single agent run. Cross-run aggregation
  is a Pro-tier feature and lives in a future `audit_packet_rollup_v0.json` schema.
- **Framework mappings (OWASP, NIST, EU AI Act).** Pro-tier producers MAY add a top-level
  `framework_mappings` field; v0 ignores it (because of `additionalProperties: false`, that
  field is rejected, so Pro outputs MUST emit a different `schema_version` such as
  `pipelock.audit_packet.v0_pro`).
- **Inline transparency-log proof.** v0 includes `verifier.root_hash` so relying parties can
  anchor the chain externally, but the packet itself does not embed transparency-log inclusion
  proofs. v1 candidate.

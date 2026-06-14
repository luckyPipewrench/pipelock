# Receipt schema versioning policy

This document states the versioning rules for Pipelock's two receipt formats and the
forward-compatibility guarantee verifiers must honor.

## Current schema versions

| Format | Version field | Current value | Verifier entry point |
|--------|---------------|---------------|----------------------|
| ActionReceipt | `receipt.ReceiptVersion` (`internal/receipt/receipt.go:17`) | `1` | `receipt.VerifyWithKey` (`internal/receipt/receipt.go:66`) |
| AARP assurance envelope | `aarp.Profile` (`internal/aarp/doc.go:50`) | `"aarp/v0.1"` | `aarp.Verify` (`internal/aarp/verify.go:67`) |

### ActionReceipt v1

The flat JSON envelope:

```json
{
  "version": 1,
  "action_record": { "version": 1, ... },
  "signature": "ed25519:<128 hex chars>",
  "signer_key": "<64 hex chars>"
}
```

The outer `version` is `receipt.ReceiptVersion = 1`. The nested `action_record.version`
is `receipt.ActionRecordVersion = 1`. Both constants live in `internal/receipt/`.

The verifier (`receipt.VerifyWithKey`) rejects any receipt whose outer `version` differs
from `ReceiptVersion` with the error "unsupported receipt version N (expected 1)".
Likewise `ActionRecord.Validate` rejects records whose inner `version` differs from
`ActionRecordVersion`.

### AARP v0.1 assurance envelope

Every AARP assurance envelope carries `"profile": "aarp/v0.1"` in both the top-level
envelope object and each signature's protected header. The verifier (`aarp.Verify`) rejects
envelopes whose top-level `profile` is not `aarp.Profile` ("aarp/v0.1") with a schema-fatal
error. A per-signature `protected.profile` mismatch is reported per-signature as
`unknown_suite`, not envelope-fatal (AARP-CORPUS-CONTRACT.md §"Envelope-fatal vs
per-signature").

## Forward-compatibility guarantee

**Verifiers must keep accepting frozen v1 receipts across every release.** A future Pipelock
release that introduces a new version number must continue to parse and verify all correctly
signed v1 receipts and v0.1 envelopes. This guarantee is enforced mechanically:

- Frozen v1 fixtures live in `sdk/conformance/testdata/frozen/v1/`.
- `TestFrozenV1ReceiptFixtures` in `sdk/conformance/frozen_v1_test.go` loads each fixture
  and asserts the current verifier accepts it on every CI run.
- The test also checks each fixture's SHA-256 against a pinned value (drift guard). If a
  frozen file is mutated the test fails immediately with a "frozen fixture drift" message.

## What changes bump the version

### ActionReceipt

A new outer `version` integer (e.g. `2`) is warranted only when the wire format changes in
a way that makes a v1 verifier fail to parse the new receipt correctly. Examples that
require a bump:

- Removing `action_record` or `signature` fields from the envelope.
- Changing the signing input (currently `SHA-256(canonical JSON of action_record)`).
- Changing the signature wire format (currently `"ed25519:<hex>"`).

Adding NEW optional fields to `action_record` that a v1 verifier ignores does NOT require a
bump (JSON unknown-field tolerance is the mechanism — `receipt.Unmarshal` uses `json.Unmarshal`
which ignores unknown fields by design). Removing or renaming existing required fields
requires a bump.

### AARP assurance envelope

The profile string advances (e.g. `"aarp/v1.0"`) only when the signing input, canonical
payload shape, or the core verified-claim vocabulary changes incompatibly. The profile must
match identically; AARP envelopes have no "compatible subset" tolerance.

## Deprecation

When a new version is introduced:

1. The old version remains verifiable (forward-compat guarantee above).
2. The old version is marked deprecated in this file with the Pipelock release version that
   introduced the replacement.
3. The frozen fixtures for the deprecated version remain in
   `sdk/conformance/testdata/frozen/<version>/` permanently. They are never deleted.
4. A deprecation notice is added to the emitter so operators know when they are emitting
   a deprecated format.
5. Removal of OLD-version support requires a major release and a migration guide.

## Forward compatibility and selective disclosure

AARP envelopes carry `"ext"` (non-critical extensions) which are excluded from the signed
payload and ignored safely by verifiers that do not recognize them. This is intentional:
non-critical extensions allow producers to attach advisory metadata (e.g. redaction
markers, selective-disclosure hints) without breaking cross-version verification. Critical
extensions are listed in `crit_ext`; an unknown entry in `crit_ext` causes the envelope to
be rejected (fail-closed). New critical extension names are a protocol change and require
community coordination before deployment.

ActionReceipt v1 has no extension mechanism; new optional fields are added directly and
ignored by prior verifiers via JSON unknown-field tolerance.

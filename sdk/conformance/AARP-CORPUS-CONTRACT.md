# AARP v0.1 Four-Language Verifier Contract

This document is the **normative contract** every AARP reference verifier (Go,
TypeScript, Rust, Python) MUST satisfy. The Go implementation in
`internal/aarp/` is the reference; the other three port FROM it. The shared
hostile corpus lives in `sdk/conformance/testdata/aarp-corpus/`. The
cross-language gate (`aarp-corpus-gate.sh`) runs all four verifiers over that
corpus and fails on **any** disagreement.

The bug class this corpus exists to kill: **a claim one verifier inflates that
another rejects.** Cross-language divergence IS the bug.

## What a verifier does

Given an AARP assurance **envelope** (or a JSONL **chain** of envelopes) and a
pinned **trust file**, the verifier appraises the envelope and reports — grouped
by axis — exactly which claims it could cryptographically confirm, plus the fixed
`does_not_assert` list. It never emits "trusted" or "safe". Per-signature
problems (unknown suite, untrusted key, bad signature) are reported per
signature, **never** as an envelope rejection, so one bad parallel signature can
neither mask nor poison a good one.

## CLI interface (exact)

```
<verifier> aarp <PATH> --trust <TRUST_JSON> [--chain] [--json]
```

- `<PATH>`: a single envelope (`*.aarp.json`) or, with `--chain`, a JSONL stream
  (`*.aarp.jsonl`, one envelope per line).
- `--trust <TRUST_JSON>`: the pinned trust file (see below). Optional; absent
  means empty trust (every signature is `unknown_key`).
- `--json`: print the **comparable output** (below) on stdout.
- `--chain`: verify Rung-1 chain linkage instead of single-envelope appraisal.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | The envelope was **appraised** (single) / the stream is **linked** (chain). |
| 1 | The envelope is **fatal**: schema violation, ENVELOPE profile mismatch, ENVELOPE-level unknown critical extension, unsafe number, duplicate key, trailing tokens, unknown field, bad grammar, empty signature set, OR a chain that is not linked. |
| 2 | I/O or trust-file error. |
| 64 | Usage error. |

"Fatal" is distinct from "appraised with unverified claims": a forged signature is **appraised** (exit 0) and reports `assertion_signed=false`; an ENVELOPE profile mismatch is **fatal** (exit 1) and produces no appraisal.

**Envelope-fatal vs per-signature.** Fatal conditions are properties of the envelope the verifier cannot safely interpret at all: the ENVELOPE `profile`, the ENVELOPE-level `crit_ext`, schema/grammar/number-safety, and an empty signature set. Anything wrong with one PARALLEL SIGNATURE is reported per signature and never rejects the envelope, so a bad signature can neither mask nor poison a good one. In particular a signature whose `protected.profile` or `protected.canon` does not match, or whose `protected.crit` names an unknown critical extension, is reported `unknown_suite` on THAT signature (it never verifies, no fallback); it is NOT envelope-fatal.

## Trust file format

```json
{
  "trusted_keys": { "<key_id>": "<ed25519 public key, 64 lowercase hex>" },
  "trust_entries": {
    "<key_id>": { "mediator_id": "...", "role": "...", "trust_domain": "..." }
  }
}
```

- A signature whose `key_id` is absent from `trusted_keys` is `unknown_key` and
  never verifies.
- A `key_id` present in `trusted_keys` but absent from `trust_entries` can verify
  a signature but cannot confirm `mediator_key_pinned`.
- A trust entry confirms `mediator_key_pinned` only when its `mediator_id`
  equals the assertion's `mediator_id`, and (when set) its `role` equals the
  verifying signature's `signer_role` and its `trust_domain` equals the
  assertion's `trust_domain`. Role/domain mismatch → not pinned (no escalation).

## Comparable output (the cross-language equality surface)

With `--json`, an **appraised** envelope prints the **JCS-canonical bytes** of
this object (RFC 8785: NFC-normalized strings, object keys sorted by Unicode code
point, compact, Go-`json`-style HTML escaping of `<` `>` `&` U+2028 U+2029,
integer-only numbers), followed by a single `\n`:

```jsonc
{
  "assertion_signed": <bool>,
  "axes": { "<axis>": ["<sorted claim names>"] },   // only non-empty axes
  "claimed_unverified": ["<sorted, deduped producer claims not confirmed>"],
  "does_not_assert": ["<sorted fixed list>"],
  "profile": "aarp/v0.1",
  "signatures": [                                    // ENVELOPE ORDER (not sorted)
    { "alg": "...", "key_id": "...", "signer_role": "...", "status": "..." }
  ],
  "verified_claims": ["<sorted, deduped confirmed claim names>"]
}
```

A **chain** that links prints:

```json
{"chain_linked": true, "length": <N>}
```

EXCLUDED from the comparable surface (legitimately differ across languages):
`warnings` prose, per-signature `reason` prose, and `assurance_claimed` (a
verbatim echo of the input). A verifier MAY print these in non-`--json` mode.

For a **fatal** envelope, `--json` prints `{"envelope_fatal": true, ...}` and the
process exits non-zero. The gate compares only the non-zero exit for fatal
fixtures (every language must reject), not the body.

### Canonicalization keys

All array fields except `signatures` are sorted ascending by Unicode code point
and de-duplicated. `signatures` preserves envelope order (every verifier walks
signatures in array order; a reorder is itself a meaningful difference). After
building the object, the verifier runs it through that language's RFC 8785 JCS
canonicalizer (the same one used to recompute the payload digest), which sorts
all object keys. The result is therefore deterministic and identical across
languages — `internal/aarp.ComparableAppraisal` is the reference implementation.

## Status enum (per signature)

`verified` `failed` `unknown_key` `unimplemented` `unknown_suite` `malformed`.
Only `verified` counts toward a confirmed claim. There is **no fallback**: an
unknown or unimplemented suite, an untrusted key, or a bad signature all leave
the signature unverified.

## Verified-claim & axis vocabulary

| Claim | Axis | Confirmed when |
|-------|------|----------------|
| `assertion_signature_valid` | integrity | ≥1 parallel signature verified under a trusted key over the canonical payload |
| `mediator_key_pinned` | identity | a verifying signature's key id is bound by a trust entry to the asserted mediator (role/domain-scoped) |
| `chain_link_present` | integrity | the envelope carries a well-formed Rung-1 chain link |

Producer claim → required verified claims (all must be present to be confirmed;
otherwise the producer claim is reported in `claimed_unverified`):

- `mediated` → `mediator_key_pinned`
- `complete-mediation` / `complete_mediation` → (never verifiable; always unverified)
- `transparency_inclusion` → (never verifiable in v0.1)
- any unknown claim → reported claim-only (unverified)

`does_not_assert` is the fixed list: `absence_of_bypass`, `action_safety`,
`complete_mediation`, `efficacy`, `policy_correctness`.

## Canonicalization & number-safety rules (must match Go exactly)

- **JCS RFC 8785** for the signed payload and the comparable output: NFC strings,
  object keys sorted by code point, compact, HTML-escape `< > &` and U+2028/U+2029,
  reject floats.
- **I-JSON number safety**: a raw JSON number is allowed ONLY if it is an integer
  with no fractional part, no exponent, not `-0`, within `[-(2^53-1), 2^53-1]`.
  Anything else anywhere in the envelope is FATAL. Identity/digest/counter/
  timestamp/amount values are typed strings with strict grammars.
- **Strict parse**: reject duplicate object keys at any depth, trailing tokens
  after the value, and unknown fields in AARP-controlled objects.
- **Surrogate escapes**: match Go `encoding/json` (and Python `json`) exactly,
  not just "replace any surrogate". Three rules:
  1. *Non-greedy pairing.* A high-surrogate escape pairs ONLY with an
     immediately following low-surrogate escape. If the next token is not a
     low-surrogate escape, the high alone decodes to U+FFFD and the following
     escape is reprocessed independently — so a high,high,low run
     (`\uD800\uDBFF\uDC00`) yields U+FFFD followed by the astral pair built from
     the 2nd and 3rd escapes, NOT three U+FFFD. A greedy decoder that consumes
     the second escape unconditionally is a cross-language differential.
  2. *Lone surrogates → U+FFFD at decode.* An unpaired high or low surrogate
     becomes U+FFFD in the decoded string (so even raw string comparisons such
     as `mediator_id` trust pinning match Go), and the envelope remains
     appraisable unless another rule makes it fatal.
  3. *Valid pairs preserved.* A valid surrogate pair is a legitimate astral
     code point (e.g. an emoji) and MUST be preserved intact. A canonicalizer
     that walks UTF-16 code units must not mangle a valid pair to two U+FFFD.
- **Typed-string grammars**: 64-char lowercase hex digests; RFC3339Nano
  timestamps; unsigned decimal counters (no leading zero except "0").

## Signing input (for signature verification)

Each signature's message is `JCS({context, payload_sha256, protected})` where:

- `context` = `"pipelock-aarp-v0.1/assurance-assertion"`
- `payload_sha256` = lowercase-hex SHA-256 of the JCS-canonical **payload**
  (`{profile, subject, assertion, crit_ext, chain?}` — NOT signatures, NOT ext)
- `protected` = that signature's protected header object

`crit_ext` is ALWAYS present in the signed payload: an absent or nil envelope crit_ext MUST serialize as `"crit_ext":[]` (empty array, never omitted, never null) so the canonical bytes match across implementations. A verifier that omits it when empty computes a different digest and fails every signature.

The wire form is `"<alg>:<standard-base64 signature>"`. Ed25519 verifies the
canonical bytes directly. (ML-DSA-65 is a recognized but unimplemented slot:
always `unimplemented`, never verified.)

## SVID attestation (PR-B — added in the stacked follow-up)

The SVID X.509 proof-of-possession binding, its corpus fixtures, and the three
Codex-finding fixtures (trust-domain confusion, issued-at-after-leaf-expiry,
valid baseline) are specified and gated in the stacked attestation PR. This
contract section will be extended there; the envelope contract above is frozen.

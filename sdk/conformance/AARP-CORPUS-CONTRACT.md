# AARP v0.1 Four-Language Verifier Contract

This document is the **normative contract** every AARP reference verifier (Go,
TypeScript, Rust, Python) MUST satisfy. The Go implementation in
`internal/aarp/` is the reference; the other three port FROM it. The shared
hostile corpus lives in `sdk/conformance/testdata/aarp-corpus/`. The
cross-language gate (`aarp-corpus-gate.sh`) runs all four verifiers over that
corpus and fails on **any** disagreement. All four reference verifiers implement
`--svid`, so the gate covers the SVID `svid/` arm by default (set
`AARP_GATE_INCLUDE_SVID=0` to skip it) alongside the Go reference conformance test.

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
  "assurance": { "axes_with_verified_claims": ["<sorted axes holding ≥1 verified claim>"] },
  "axes": { "<axis>": ["<sorted claim names>"] },   // only non-empty axes
  "claimed_unverified": ["<sorted, deduped producer claims not confirmed>"],
  "does_not_assert": ["<sorted list: fixed general set + any paired negatives>"],
  "overclaim_risks": ["<sorted, deduped over-read warning codes>"],
  "profile": "aarp/v0.1",
  "signatures": [                                    // ENVELOPE ORDER (not sorted)
    { "alg": "...", "key_id": "...", "signer_role": "...", "status": "..." }
  ],
  "verified_claims": ["<sorted, deduped confirmed claim names>"]
}
```

`assurance` carries only the axis-set descriptor (which axes hold verified
claims), never a grade or score. The redundant axis count is intentionally
omitted so the comparable surface stays free of raw JSON numbers; readers derive
it as the array length. `overclaim_risks` lists active "you might be about to
over-read X" warnings (codes below). The default human (`--json`-off) view leads
with `does_not_assert` + `overclaim_risks` BEFORE the verified claims.

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

Verified-claim names are deliberately literal — each names the exact mechanical
fact confirmed, never a property a relying party might over-read:

| Claim | Axis | Confirmed when |
|-------|------|----------------|
| `receipt_signature_valid` | integrity | ≥1 parallel signature verified under a trusted key over the canonical payload |
| `mediator_key_pinned` | identity | a verifying signature's key id is bound by a trust entry to the asserted mediator (role/domain-scoped) |
| `receipt_timestamp_monotonic_chain_present` | integrity | the envelope carries a well-formed Rung-1 chain link (a monotonic position, NOT a verified contiguous stream and NOT freshness) |

Producer claim → required verified-claim set (every member must be present to be
confirmed; otherwise the producer claim is reported in `claimed_unverified`). The
producer's INPUT claim vocabulary is stable and distinct from the renamed verifier
OUTPUT:

- `mediated` → `mediator_key_pinned`
- `complete-mediation` / `complete_mediation` → (never verifiable; always unverified)
- `transparency_inclusion` → (never verifiable in v0.1)
- any unknown claim → reported claim-only (unverified)

`does_not_assert` fixed general list (sorted in output): `absence_of_bypass`,
`action_safety`, `all_tools_discovered`, `complete_mediation`,
`delegated_actions_mediated`, `efficacy`, `hosted_saas_actions_mediated`,
`intent_correctness`, `key_non_compromise`, `local_side_effects_mediated`,
`policy_correctness`, `semantic_equivalence_after_modify`. When an SVID claim is
present, the paired negatives `does_not_assert_network_non_bypass_from_identity`
and `does_not_assert_deployment_enforcement_from_identity` are also added.

`overclaim_risks` codes: `signature_valid_is_not_transparency_inclusion` (a valid
signature is integrity, not transparency-log inclusion),
`svid_identity_is_not_deployment_non_bypass` (a bound signing-workload identity is
not a deployment/non-bypass proof), and
`chain_link_present_is_not_verified_contiguous_chain` (a single chain link is not
a verified contiguous stream).

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

## SVID attestation

The SVID layer appraises an X.509-SVID workload-identity **proof-of-possession
binding** on top of the envelope appraisal. It is additive: it never changes the
envelope contract above, never makes an envelope fatal, and never removes a core
claim. A verifier that does not implement it MUST still produce the byte-identical
envelope appraisal; a verifier that does implement it adds at most three claims.

### CLI

```text
<verifier> aarp <PATH> --trust <TRUST_JSON> --svid <SVID_JSON> [--json]
```

`--svid` names a per-fixture sidecar. `--trust` carries the envelope-signing trust
as elsewhere and stays optional, but it is what lets the SVID claims attach: an
SVID binding only attaches to a **signed** assertion, so without trust that
verifies a signature every signature is `unknown_key`, the assertion is unsigned,
and no claim — including the three SVID claims — attaches. Without `--svid` the
appraisal is exactly the envelope appraisal. SVID is single-envelope only (never
combined with `--chain`).

### `--svid` sidecar format

```jsonc
{
  "evidence": {                         // producer-supplied; the X.509-SVID PoP
    "type": "x509",                     // only "x509" counts; "jwt" is claim-only
    "spiffe_id": "spiffe://example.org/workload/agent-a",
    "leaf_der_b64": "<standard-base64 DER of the leaf SVID>",
    "chain_der_b64": ["..."],           // optional intermediates, leaf->root
    "nonce": "<base64url, no padding, >= 16 bytes decoded>",
    "issued_at": "<RFC3339Nano>",
    "binding": {
      "alg": "ecdsa-p256-sha256" | "ed25519",
      "context": "pipelock-aarp-v0.1/svid-receipt-binding",
      "payload_sha256": "<lowercase-hex SHA-256 of canonical binding payload>",
      "signature_b64": "<standard-base64 leaf-key signature over the binding>"
    }
  },
  "verify": {                           // verifier-pinned context; never producer-controlled
    "trust_domain": "example.org",
    "action_time": "<RFC3339Nano>",     // the SVID is validated AT this time, offline
    "allowed_spiffe_ids": ["..."],      // optional; empty permits any id in the domain
    "bundle": [                         // pinned trust-bundle history, chronological
      { "not_before": "<RFC3339Nano>", "not_after": "<RFC3339Nano|omitted=open>",
        "authorities_der_b64": ["<standard-base64 DER of a CA cert>"] }
    ]
  }
}
```

A malformed **pinned bundle** (bad DER, inverted window, empty domain) is an
operator-configuration error (exit 2), not a fixture verdict — the bundle is
trusted input. Everything an attacker controls lives in `evidence`, which the
verifier appraises fail-closed.

### SVID validation algorithm (must match the Go reference exactly)

In order, fail-closed at the first failure (a failure adds NO claim and leaves the
envelope appraisal untouched):

1. `evidence.type` MUST be `"x509"` (a JWT-SVID is bearer-only in v0.1).
2. `issued_at` MUST be a valid RFC3339Nano timestamp.
3. `nonce` MUST be valid base64url (no padding) decoding to **>= 16 bytes**.
4. `binding.context` MUST equal `pipelock-aarp-v0.1/svid-receipt-binding`.
5. The leaf (+ any intermediates) MUST validate **offline at `action_time`**
   (not "now") against the pinned bundle generation authoritative at
   `action_time`. No generation covers `action_time` → reject (stale/forked
   bundle). The leaf MUST carry exactly one well-formed SPIFFE URI SAN, and its
   trust domain MUST equal `verify.trust_domain`.
6. `evidence.spiffe_id` MUST equal the leaf's validated URI SAN (no substitution),
   and MUST be permitted by `allowed_spiffe_ids` when that set is non-empty.
7. The signed `assertion.trust_domain` MUST be present and MUST equal
   `verify.trust_domain` (trust-domain confusion: a valid SVID from one domain
   cannot back an assertion declaring another).
8. `issued_at` MUST fall within the leaf's `[NotBefore, NotAfter]` window
   (post-expiry key use is rejected even when the chain validates at action time).
9. The proof-of-possession signature MUST verify under the **leaf** public key over
   the canonical binding payload. ECDSA: `alg` MUST be `ecdsa-p256-sha256`, the
   leaf key MUST be curve **P-256** (an explicit curve check — ECDSA ASN.1
   verification is curve-agnostic, so a P-384/P-521 leaf under a P-256 alg id MUST
   be rejected), and the signature is over `SHA-256(canonical)` as ASN.1. Ed25519:
   `alg` MUST be `ed25519` and the signature is over the canonical bytes directly.

### Canonical binding payload

The message the leaf key signs is the JCS-canonical (RFC 8785, NFC) bytes of:

```jsonc
{
  "action_record_sha256":       "<subject.action_record_sha256>",
  "assurance_assertion_sha256": "<SHA-256 of the JCS-canonical signed payload>",
  "context":                    "pipelock-aarp-v0.1/svid-receipt-binding",
  "issued_at":                  "<evidence.issued_at>",
  "mediator_id":                "<assertion.mediator_id>",
  "nonce":                      "<evidence.nonce>",
  "profile":                    "aarp/v0.1",
  "receipt_envelope_sha256":    "<subject.receipt_envelope_sha256>",
  "receipt_signer_key":         "<subject.receipt_signer_key>",
  "spiffe_id":                  "<evidence.spiffe_id>"
}
```

Binding to the action-record, receipt-envelope, and assurance-assertion digests is
what defeats replay across actions; the nonce defeats replay within an action.

### Verified-claim & axis additions

When ALL of the above pass, exactly these three claims are added (only on a signed
assertion):

| Claim | Axis | Confirmed when |
|-------|------|----------------|
| `signing_workload_svid_chain_validated` | identity | the X.509-SVID leaf chain validated against the pinned bundle and the SPIFFE ID is permitted |
| `signing_workload_svid_bound` | identity | the SVID leaf key signed the receipt/assertion binding (proof of possession) — an identity binding, NOT a deployment attestation |
| `signing_workload_svid_valid_at_action_time` | freshness | the SVID validated point-in-time at the action time |

Producer claim → required verified claims: the stable INPUT claim
`workload_identity_verified` → the renamed OUTPUT claim
`signing_workload_svid_chain_validated` (likewise `x509_svid_bound` →
`signing_workload_svid_bound`, `svid_valid_at_action_time` →
`signing_workload_svid_valid_at_action_time`). A producer that claims it without a
verifying binding has it reported in `claimed_unverified` (no inflation). When the
binding verifies, the paired negatives
`does_not_assert_network_non_bypass_from_identity` and
`does_not_assert_deployment_enforcement_from_identity` are added to
`does_not_assert`, and `overclaim_risks` gains
`svid_identity_is_not_deployment_non_bypass`.

### Corpus scope

The SVID corpus uses a **single-CA, leaf-directly-under-root** chain (no
intermediates) so the four languages' X.509 path validation stays byte-identical;
multi-intermediate chains are a documented out-of-scope extension. The hostile
matrix (`svid/`) covers: valid ECDSA-P256 and Ed25519 baselines, replay across
actions, expiry / not-yet-valid at action time, wrong leaf key, stale bundle,
forked bundle root, trust-domain confusion, SPIFFE-ID substitution, P-384 curve
confusion, short nonce, unsigned assertion, JWT-treated-as-verified, issued-at
after leaf expiry, a forged binding signature, a malformed SPIFFE-ID path
(dot-segment) that a loose parser would accept, a signing CA expired at action
time while the pinned generation still covers it, and an `issued_at` one
nanosecond past a whole-second leaf expiry (sub-second precision), an issuer-DN
mismatch under the pinned CA key, and a binding signature with non-base64 junk
that lenient decoders must not discard. The three
regression-anchor fixtures are the valid baseline (`s01`), trust-domain confusion
(`s09`), and issued-at-after-leaf-expiry (`s15`). Every malicious fixture appraises
WITHOUT the three claims. All four reference verifiers implement `--svid`, so the
shell gate covers `svid/` by default (`AARP_GATE_INCLUDE_SVID=0` skips it) and
catches cross-language inflation alongside the Go reference conformance test.

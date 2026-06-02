// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package aarp implements the Agent Action Receipt Profile (AARP) v0.1
// assurance envelope: a separate, independently-signed appraisal artifact that
// sits alongside a shipped pipelock receipt and reports exactly what a verifier
// could cryptographically confirm versus what the producer merely claimed.
//
// AARP is not a new receipt format. The shipped v1 ActionReceipt
// (internal/receipt) and the v2 EvidenceReceipt (internal/contract/receipt)
// stay byte-for-byte frozen; AARP appraises them as immutable inputs referenced
// by digest. It never rewrites a receipt and never emits a "trusted" or "safe"
// verdict.
//
// # What this package provides
//
//   - A protected signature suite bound into every signed byte sequence, with
//     fail-closed rejection of unknown suites and unknown critical extensions
//     and no fallback verification (suite.go).
//   - JCS number-safety: identity, digest, timestamp, counter, and amount
//     fields are typed strings with explicit grammars; raw JSON numbers outside
//     the I-JSON safe-integer range are rejected (numbers.go).
//   - A parallel multi-signature envelope: N protected signatures over the same
//     canonical assertion payload bytes, never chained over one another. Ed25519
//     ships today; the post-quantum slot is typed-but-stubbed (envelope.go,
//     sign.go, verify.go).
//   - An issuer-agnostic Rung-1 timestamp-chain primitive (sequence number +
//     prior hash) so backdating within an issuer's stream is detectable without
//     depending on any particular issuer deployment (chain.go).
//   - A claim-set appraisal result grouped by axis with an explicit
//     does_not_assert list (appraise.go).
//
// # What it composes with (does not reinvent)
//
//   - internal/contract.Canonicalize / ParseJSONStrict for RFC 8785 JCS,
//     NFC normalization, float rejection, and duplicate-key rejection.
//   - internal/svid for offline X.509-SVID validation (consumed by the
//     attestation binding built on top of this core).
//
// Every signing input in this package is the JCS canonicalization of a single
// object that carries the domain-separation context as a signed field, so the
// context is inside the signed bytes (JCS sorts object keys, so it is signed but
// not necessarily first in canonical order). String concatenation is never used
// to form a signing input.
package aarp

// Profile is the AARP profile identifier carried by every envelope and every
// protected signature header. A mismatch is fatal: the verifier never appraises
// an envelope whose profile it does not implement.
const Profile = "aarp/v0.1"

// CanonID names the canonicalization the signed bytes were produced with. It is
// part of the protected suite so a verifier can never be tricked into matching
// bytes produced under a different canonicalization.
const CanonID = "jcs-rfc8785-nfc"

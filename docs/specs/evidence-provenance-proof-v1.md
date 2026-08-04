# Evidence provenance proof v1 (experimental, fixture-only)

Status: experimental and fixture-only. This document specifies no registered receipt payload, production emitter, verifier command, or capability claim.

## Scope and terms

A source is named input bytes. A view is UTF-8 bytes produced from exactly one source by an ordered typed recipe. A match is a half-open byte interval `[byte_start, byte_end)` in that view. All offsets are unsigned UTF-8 **byte** offsets. Rune/character conversion is forbidden.

Implementations MUST reject invalid UTF-8 source or view bytes; starts or ends in UTF-8 continuation bytes; zero-length, out-of-bounds, or arithmetic-overflowing intervals; unsorted, duplicate, or overlapping intervals. Adjacent intervals are valid. Because the wire shape carries `byte_start` and `byte_end`, a verifier rejects `byte_end <= byte_start` and never derives an end from an unrepresented length field.

## Typed recipe language

`transform_profile_digest` is a `sha256:<lowercase hex>` digest of the profile document. A verifier MUST possess the exact digest-matched profile before reconstructing a view. The canonical evidence-provenance v1 profile document is `sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v1.json`; its exact committed bytes have digest `sha256:8bc27d5d89e4e5ba3e0d1e68a25a3f0170f9a5ea2f19edf81a9a90bf82e23b3e`.

That profile document—not a Pipelock implementation—is the normative source of truth for the ordered vocabulary, operation parameter shapes, Unicode/control-character and malformed-input policy, decoding and padding selection, canonical encodings, UTF-8 checks, and byte/decode-pass limits. It declares a 2 MiB input limit, a 1 MiB post-operation output limit, and at most four percent-decode passes. The Go implementation deliberately does not load a conformance document at runtime; its digest test parses the document and fails if those implementation constants or the operation order diverge. This keeps receipt validation hermetic while preventing a second source of truth. It is a distinct document from `pipelock-transform-v1.json`, which remains the source-span transform profile.

Recipes are ordered arrays of typed operations. Operations are never labels or concatenated strings; the following is a convenience summary, while the profile document is authoritative:

- `identity`
- `url_component { component: url|hostname|path|query_key|query_value, selector, occurrence }`; query key/value requires a selector and zero-based occurrence, including repeated keys.
- `percent_decode { passes: 1..4 }`
- `dlp_normalize { profile: "pipelock-dlp-v1" }`
- `lowercase`, `invisible_strip`, `leetspeak`, `vowel_fold`
- `hex_decode`, `base32_decode { decode_padding }`, and `base64_decode { decode_padding }`.

Each operation consumes the preceding output; no operation may silently retain undecodable input. Unsupported parameters, malformed encodings, absent URL components, and limit failures are errors. `selector` and `profile` values MUST NOT contain Unicode control characters; implementations MUST reject them. Hex inputs MUST be canonical lowercase hex: re-encoding decoded bytes using lowercase hexadecimal MUST produce exactly the input. Base32 and base64 inputs MUST be canonical for their selected padding mode: re-encoding decoded bytes using the selected RFC 4648 encoding MUST produce exactly the input. Valid UTF-8 is required before the first operation and after every operation. The profile, not the producer or implementation, determines vocabulary, decoding ambiguity, limits, and policy.

## Commitments

Commitments are `hmac-sha256:<hex>`, using an undisclosed verifier-held key of at least 32 bytes. The key MUST NOT be serialized. Publishing an unkeyed digest of undisclosed view or match bytes is prohibited: it would create an offline oracle for low-entropy guesses.

Every preimage uses this frame: `u64be(byte_length) || bytes`, with one frame for the ASCII domain and one for every field. Canonical typed recipe bytes begin with a framed ASCII `pipelock/evidence-provenance/recipe/v1` domain, framed transform-profile digest, and framed fixed-width `u64be(operation_count)`. Each operation is then its own frame containing frames for, in order: fixed-vocabulary operation enum byte, fixed-vocabulary component enum byte (zero when absent), selector bytes, fixed-width `u32be(occurrence)`, fixed-width `u8(passes)`, profile bytes, and fixed-width boolean `decode_padding` byte. Unknown enum values and unsupported operation parameters are errors. The view commitment domain is `pipelock/evidence-provenance/view/v1`; it frames source ordinal, source ID, profile digest, canonical typed recipe bytes, and every byte of the complete view. The match commitment domain is `pipelock/evidence-provenance/match/v1`; it frames source ID, profile digest, canonical recipe bytes, complete-view commitment, match ordinal, byte start, byte end, and match class. Ordinals and offsets are fixed eight-byte unsigned big-endian fields inside length frames. Thus source/match order, recipes, coordinates, and bytes outside a match all alter a commitment.

The experimental typed shape is `EvidenceProvenanceProof`, with `version` exactly `pipelock-evidence-provenance-proof/v1`, ordered `ProvenanceSource` values, and ordered `ProvenanceMatch` values. It commits explicit source and match ordinals as described above; implementations MUST reject duplicate source IDs and duplicate ordinals. `producer.binary_digest` and `producer.ruleset_digest` are independently optional: absent is represented by an omitted field, while a present field MUST be canonical `sha256:<lowercase hex>`. A present producer digest is attested-but-unchecked; independently checked remains verifier-local reporting state and is never a producer-controlled field.

## Verification stages

1. **Structural:** UTF-8, recipe, interval, ordering, and commitment encoding checks pass or fail.
2. **Reconstructed:** only with source bytes and the exact transform profile, reconstruct the view and validate intervals.
3. **Commitment checked:** only with the undisclosed HMAC key, recompute complete-view and match commitments.
4. **Producer independently checked:** only after independently acquiring and hashing a binary/ruleset can producer digests be reported as checked.

Without source bytes/profile/key, report the unavailable stage explicitly, never success. Producer-supplied binary and ruleset digests are **attested-but-unchecked** until stage 4; they do not identify the binary that ran.

## Conformance corpus

`sdk/conformance/testdata/transform-profile/evidence-provenance-v1.json` is byte-exact via base64 values, including hostile invalid UTF-8. Its profile digest is regenerated whenever the separately pinned evidence-provenance profile changes. Meta-tests require a vector for each operation and each declared error. Corpus keys are harmless test-only HMAC keys and do not change the no-offline-oracle rule for emitted receipts.

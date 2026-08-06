# Evidence provenance proof v1 (experimental, fixture-only)

Status: experimental and fixture-only. This document specifies no registered receipt payload, production emitter, verifier command, or capability claim.

## Profile lifecycle and the freeze boundary

While this profile is experimental, `v1` names a schema-major profile FAMILY and the exact revision in force is its digest, not its filename. Revising the vocabulary therefore changes the digest in place, and that is deliberate: no production emitter, published verifier, or released artifact consumes this profile, so no issued proof is invalidated by doing so. Implementations pin one exact digest and reject every other value, which means an unknown digest fails closed rather than degrading to a weaker interpretation.

That permission ends at a hard boundary. On the FIRST of either a production emission or a published verifier that implements this profile, the profile bytes and digest become immutable permanently. After that point a vocabulary change MUST be published as a new profile, every frozen profile MUST be retained by digest for the full receipt-retention period, and dispatch MUST be exact allowlisted digest matching.

Dispatch must never be ordered fallback. Trying one profile and then another on failure lets an attacker choose the weaker interpretation of the same bytes, which converts a verification control into a downgrade oracle. An unknown digest is a rejection, not a prompt to try again.

The reason to state this now rather than at the freeze is cost. Today the migration is a digest change. After one real receipt exists it requires archival profile support, mixed-version verification tests, downgrade controls, and a documented retention period, and it must be designed under the pressure of already having something to preserve.

## Scope and terms

A source is named input bytes. A view is UTF-8 bytes produced from exactly one source by an ordered typed recipe. A match is a half-open byte interval `[byte_start, byte_end)` in that view. All offsets are unsigned UTF-8 **byte** offsets. Rune/character conversion is forbidden.

Implementations MUST reject invalid UTF-8 source or view bytes; starts or ends in UTF-8 continuation bytes; zero-length, out-of-bounds, or arithmetic-overflowing intervals; unsorted, duplicate, or overlapping intervals. Adjacent intervals are valid. Because the wire shape carries `byte_start` and `byte_end`, a verifier rejects `byte_end <= byte_start` and never derives an end from an unrepresented length field.

## Typed recipe language

`transform_profile_digest` is a `sha256:<lowercase hex>` digest of the profile document. A verifier MUST possess the exact digest-matched profile before reconstructing a view. The canonical evidence-provenance v1 profile document is `sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v1.json`; its exact committed bytes have digest `sha256:3de14968449593cae58da869cfc97855cb098e491494390a12ba742cb0b70f94`.

That profile document—not a Pipelock implementation—is the normative source of truth for the ordered vocabulary, operation parameter shapes, Unicode/control-character and malformed-input policy, decoding and padding selection, canonical encodings, UTF-8 checks, and execution limits. It declares a 32-operation maximum, a 16 MiB cumulative processing budget charged before every operation and repeated internal decode pass, a 2 MiB input limit, a 1 MiB post-operation output limit, and at most four percent-decode passes. Implementations MUST reject an oversized recipe before execution or commitment reconstruction. The Go implementation deliberately does not load a conformance document at runtime; its digest test parses the document and fails if those implementation constants or the operation order diverge. This keeps receipt validation hermetic while preventing a second source of truth. It is a distinct document from `pipelock-transform-v1.json`, which remains the source-span transform profile.

Recipes are ordered arrays of typed operations. Operations are never labels or concatenated strings; the following is a convenience summary, while the profile document is authoritative:

- `identity`
- `url_component { component: url|hostname|path|query_key|query_value|raw_query, selector, occurrence }`; query key/value requires a selector and zero-based occurrence, including repeated keys.
- `percent_decode { passes: 1..4 }`
- `dlp_normalize { profile: "pipelock-dlp-v1" }`
- `lowercase`, `invisible_strip`, `leetspeak`, `vowel_fold`
- `hex_decode`, `base32_decode { decode_padding }`, and `base64_decode { decode_padding }`.
- `query_unescape`, `invisible_space`, and `matching_normalize { profile: "pipelock-matching-v1" }`.
- `hex_decode_liberal`, `base32_decode_liberal { decode_padding }`, and `base64_decode_liberal { alphabet, decode_padding }` reproduce scanner-accepted decodings without weakening the canonical decoders.
- `encoded_token_normalize { alphabet }`, `text_segment { occurrence }`, `html_entity_decode`, and `whitespace_compact`.
- `url_noise_strip`, `ordered_query_concat`, `query_subsequence { indices }`, and `hostname_dot_remove`.
- `encoded_run { occurrence, minimum_length }` and `canary_canonicalize`.

Each operation consumes the preceding output; no operation may silently retain undecodable input. Unsupported parameters, malformed encodings, absent URL components, and limit failures are errors. `selector` and `profile` values MUST NOT contain Unicode control characters; implementations MUST reject them. `hex_decode` inputs MUST be canonical lowercase hex: re-encoding decoded bytes using lowercase hexadecimal MUST produce exactly the input. `base32_decode` and `base64_decode` inputs MUST be canonical for their selected padding mode: re-encoding decoded bytes using the selected RFC 4648 encoding MUST produce exactly the input. The `*_liberal` operations deliberately omit canonical re-encoding checks so they reproduce scanner-accepted decodings; they still reject malformed input and require valid UTF-8 output. Valid UTF-8 is required before the first operation and after every operation. The profile, not the producer or implementation, determines vocabulary, decoding ambiguity, limits, and policy.

## Commitments

Commitments are `hmac-sha256:<hex>`, using an undisclosed verifier-held key of at least 32 bytes. The key MUST NOT be serialized. Publishing an unkeyed digest of undisclosed view or match bytes is prohibited: it would create an offline oracle for low-entropy guesses.

Every preimage uses this frame: `u64be(byte_length) || bytes`, with one frame for the ASCII domain and one for every field. Canonical typed recipe bytes begin with a framed ASCII `pipelock/evidence-provenance/recipe/v1` domain, framed transform-profile digest, and framed fixed-width `u64be(operation_count)`. Each operation is then its own frame containing frames for, in order: fixed-vocabulary operation enum byte, fixed-vocabulary component enum byte (zero when absent), selector bytes, fixed-width `u32be(occurrence)`, fixed-width `u8(passes)`, profile bytes, and fixed-width boolean `decode_padding` byte. Historical operation kinds 1 through 11 end there. Appended kinds 12 and above then frame alphabet bytes, raw uint8 index bytes, and fixed-width `u32be(minimum_length)`. This conditional tail preserves every historical operation preimage while making the new parameters unambiguous. Unknown enum values and unsupported operation parameters are errors. The view commitment domain is `pipelock/evidence-provenance/view/v1`; it frames source ordinal, source ID, profile digest, canonical typed recipe bytes, and every byte of the complete view. The match commitment domain is `pipelock/evidence-provenance/match/v1`; it frames source ID, profile digest, canonical recipe bytes, complete-view commitment, match ordinal, byte start, byte end, and match class. Ordinals and offsets are fixed eight-byte unsigned big-endian fields inside length frames. Thus source/match order, recipes, coordinates, and bytes outside a match all alter a commitment.

The experimental typed shape is `EvidenceProvenanceProof`, with `version` exactly `pipelock-evidence-provenance-proof/v1`, ordered `ProvenanceSource` values, and ordered `ProvenanceMatch` values. It commits explicit source and match ordinals as described above; implementations MUST reject duplicate source IDs and duplicate ordinals. `producer.binary_digest` and `producer.ruleset_digest` are independently optional: absent is represented by an omitted field, while a present field MUST be canonical `sha256:<lowercase hex>`. A present producer digest is attested-but-unchecked; independently checked remains verifier-local reporting state and is never a producer-controlled field.

## Verification stages

1. **Structural:** UTF-8, recipe, interval, ordering, and commitment encoding checks pass or fail.
2. **Reconstructed:** only with source bytes and the exact transform profile, reconstruct the view and validate intervals.
3. **Commitment checked:** only with the undisclosed HMAC key, recompute complete-view and match commitments.
4. **Producer independently checked:** only after independently acquiring and hashing a binary/ruleset can producer digests be reported as checked.

Without source bytes/profile/key, report the unavailable stage explicitly, never success. Producer-supplied binary and ruleset digests are **attested-but-unchecked** until stage 4; they do not identify the binary that ran.

Fixture verification also has availability limits. The outer fixture is at most 16 MiB with JSON nesting at most 64 levels and at most 32 signed entries. Each decoded signed payload is at most 1 MiB. The verification envelope and each proof carry at most 32 sources; each decoded source is at most 2 MiB and all supplied sources total at most 16 MiB. A source has at most 1,024 matches, and a supplied binary or ruleset is at most 2 MiB. Across all signed entries, a fixture has at most 128 source references and 4,096 matches, and all recipe executions share a 64 MiB cumulative processing budget. Implementations charge the per-recipe profile budget before this fixture-wide budget at every operation and repeated internal decode pass. A reconstructed view MUST be cached by source ID and canonical recipe and reused for location and commitment checking. Exceeding a fixture-envelope or fixture-wide limit is a `proof_structure` rejection, except a supplied artifact that exceeds its limit fails at `artifacts`; exhausting one recipe's profile budget remains a `view_reproduction` failure. These are verifier-side resource limits, not producer-controlled claims.

## Conformance corpus

`sdk/conformance/testdata/transform-profile/evidence-provenance-v1.json` is byte-exact via base64 values, including hostile invalid UTF-8. Its profile digest is regenerated whenever the separately pinned evidence-provenance profile changes. Meta-tests require a vector for each operation and each declared error. Corpus keys are harmless test-only HMAC keys and do not change the no-offline-oracle rule for emitted receipts.

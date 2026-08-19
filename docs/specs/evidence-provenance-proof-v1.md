# Evidence provenance proof v1 (experimental, fixture-only)

Status: experimental and fixture-only. This document specifies no registered receipt payload, production emitter, or capability claim. The shipped `pipelock-verifier provenance` command verifies experimental evidence-provenance fixtures.

## Transform-profile registry and immutability

The proof wire version remains `pipelock-evidence-provenance-proof/v1`. It has not changed. A transform profile selects replay semantics and is identified by its exact document digest, not by an operation name or a best-effort profile version.

The registry contains these immutable profiles:

- v1: `sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v1.json`, digest `sha256:3de14968449593cae58da869cfc97855cb098e491494390a12ba742cb0b70f94`.
- v2: `sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v2.json`, digest `sha256:01e022d444562a25591cd379e894f5f6cde9eda9527fb92af2330373a25e7af7`.

Every normative profile document and its digest are frozen at publication, including experimental profiles. A semantic correction MUST create a new document and digest. It MUST NOT rewrite a prior profile in place. Verifiers retain every registered profile for the receipt-retention period.

Before executing any operation, a verifier MUST resolve `transform_profile_digest` by exact allowlisted match. An unknown, malformed, or unsupported digest is a rejection. It MUST NOT fall back to v1, select the newest profile, or try another profile after a failure. Ordered fallback would let an attacker choose a weaker interpretation of the same bytes.

V2 adds `ascii_alphanumeric_strip`; v1 recipes MUST reject it. The digest remains the semantic selector, so no verifier may reinterpret a v1 recipe under v2 semantics.

`encoded_token_normalize` and `url_noise_strip` differ between the profiles. v1 retains its original allow-list behavior: token normalization removes only its listed delimiters and rejects other separators, while URL noise stripping removes dot, slash, ASCII space/TAB/LF/CR, plus, comma, semicolon, and vertical bar. For hex, v2 consumes `0x`, `0X`, `\\x`, or `\\X` only when the prefix is immediately followed by two ASCII hex bytes, rejects the token when a remaining ASCII letter falls outside `[A-Fa-f]` and is not `x` or `X`, rejects a retained result longer than 4096 bytes, then keeps token data bytes by alphabet: hex `[0-9A-Fa-f]`; Base32 `[A-Z2-7=]`; standard Base64 `[A-Za-z0-9+/=]`; and URL-safe Base64 `[A-Za-z0-9_-=]`. v2 `url_noise_strip` keeps ASCII `[A-Za-z0-9_-=]`. The profile documents remain normative for the complete operation behavior.

## Scope and terms

A source is named input bytes. A view is UTF-8 bytes produced from exactly one source by an ordered typed recipe. A match is a half-open byte interval `[byte_start, byte_end)` in that view. All offsets are unsigned UTF-8 **byte** offsets. Rune/character conversion is forbidden.

Implementations MUST reject invalid UTF-8 source or view bytes; starts or ends in UTF-8 continuation bytes; zero-length, out-of-bounds, or arithmetic-overflowing intervals; unsorted, duplicate, or overlapping intervals. Adjacent intervals are valid. Because the wire shape carries `byte_start` and `byte_end`, a verifier rejects `byte_end <= byte_start` and never derives an end from an unrepresented length field.

## Typed recipe language

`transform_profile_digest` is a `sha256:<lowercase hex>` digest of the profile document. A verifier MUST possess the exact digest-matched registry profile before reconstructing a view. The v1 and v2 documents and digests are listed above.

That profile document, rather than a Pipelock implementation, is the normative source of truth for the ordered vocabulary, operation parameter shapes, Unicode/control-character and malformed-input policy, decoding and padding selection, canonical encodings, UTF-8 checks, and execution limits. It declares a 32-operation maximum, a 16 MiB cumulative processing budget charged before every operation and repeated internal decode pass, a 2 MiB input limit, a 1 MiB post-operation output limit, and at most four percent-decode passes. Implementations MUST reject an oversized recipe before execution or commitment reconstruction. The Go implementation deliberately does not load a conformance document at runtime; its digest test parses the document and fails if those implementation constants or the operation order diverge. This keeps receipt validation hermetic while preventing a second source of truth. It is a distinct document from `pipelock-transform-v1.json`, which remains the source-span transform profile.

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
- V2 only: `ascii_alphanumeric_strip`, which keeps ASCII `[A-Za-z0-9]` and removes every other rune.

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

`sdk/conformance/testdata/transform-profile/evidence-provenance-v1.json` and `evidence-provenance-v2.json` are byte-exact via base64 values, including hostile invalid UTF-8. Each corpus pins its own profile digest. The 63 historical vectors remain under v1; both corpora also exercise the separator cases whose outputs differ by profile. Meta-tests require a vector for each operation and each declared error. Corpus keys are harmless test-only HMAC keys and do not change the no-offline-oracle rule for emitted receipts.

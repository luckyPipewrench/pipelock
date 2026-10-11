# Evidence provenance transform profile v5

This experimental, fixture-only profile carries bytes through internal decoder
steps and validates UTF-8 on the complete operation output. Selection requires
its exact document digest:

`sha256:1ba7ea1a9a18622e259531bab86e4e2671fbfabe8259fde38223b0d80ca6d441`

The [normative document](../../sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v5.json)
and [independent corpus](../../sdk/conformance/testdata/transform-profile/evidence-provenance-v5.json)
are consumed by Go, TypeScript, Python, and Rust. The proof wire version and
operation vocabulary are unchanged from v4.

The replay contract is satisfied when:

1. All four interpreters resolve the exact v5 digest and reject unknown profiles.
2. All four pass every shared v1–v5 vector, including invalid operation outputs.
3. V1–v4 documents, digests, and published vectors remain byte-identical.

`percent_decode` performs exactly the requested passes on bytes. A malformed
escape in any pass is an error; plus remains plus. V4's partial query decoding
is retained: complete escapes decode, malformed escapes remain verbatim, and
plus becomes space. Every internal pass is charged before processing.

`ordered_query_concat` concatenates decoded value bytes before the UTF-8 check.
`query_subsequence` decodes the first 20 non-empty values as bytes, then selects
and concatenates its indices before the check. An unselected value need not be
UTF-8. `url_component` query selection checks escape syntax in every key/value
but requires UTF-8 only in the returned component. A byte-order mark is data and
remains in both source and decoded output.

| Decoder operation | Boundary audit and v5 behavior |
|---|---|
| `percent_decode` | Carries bytes between passes; rejects invalid final UTF-8. |
| `query_unescape` | V4 already carries bytes between passes; v5 retains it. |
| `ordered_query_concat`, `query_subsequence` | Carries bytes through per-value decoding and concatenation; validates the selected result. |
| `url_component` query selection | Decodes to bytes, selects a component, then validates its output. |
| `hex_decode`, `base32_decode`, `base64_decode` and their liberal variants | Single-pass decoding; checks UTF-8 at the operation boundary and preserves byte-order marks. |
| `html_entity_decode` | Every pass emits Unicode scalars; zero, surrogate, and out-of-range numeric references become U+FFFD under HTML5. |
| `json_unicode_escape` | Single pass emits Unicode scalars; surrogate pairs combine and unpaired surrogates become U+FFFD. |

The 32-operation, 2 MiB input, 1 MiB output, and 16 MiB cumulative processing
limits remain unchanged. Invalid UTF-8 cannot cross an operation boundary, even
when a later operation could complete it. Run `bash sdk/conformance/replay-corpus-gate.sh`
to test every profile in all four languages with dependencies already installed.

This adds no production emitter and changes no signed default. Profiles v1–v4
keep their documents, digests, vectors, and historical replay behavior. Verifiers
must never retry a failed recipe under another profile.

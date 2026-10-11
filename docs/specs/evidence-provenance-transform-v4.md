# Evidence provenance transform profile v4

This additive, fixture-only profile extends the existing typed replay interpreter.
Selection requires its exact digest:

`sha256:925a91d9137c52ba70a7e71450929e5b11a00c0f979ee5fa3bc1e227789ffd37`

The normative document is
[`evidence-provenance-transform-v4.json`](../../sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v4.json).
The shared [v4 corpus](../../sdk/conformance/testdata/transform-profile/evidence-provenance-v4.json)
is exercised by Go, TypeScript, Python, and Rust.

V4 changes `query_unescape` to preserve malformed percent escapes while decoding
complete escapes in the same input. Its existing 500-round limit remains.
`ordered_query_concat` and `query_subsequence` use this profile-specific behavior.
Strict `percent_decode` and URL component selection retain their rejection rules.

The operation vocabulary and commitment codes are unchanged from v3.

Every profile still rejects invalid UTF-8 before execution and after each
operation. Existing operation-count, input, output, and cumulative processing
limits apply. V1, v2, and v3 documents, digests, vocabularies, and replay semantics
remain unchanged. There is no fallback from an unknown digest and no automatic upgrade of an existing recipe.

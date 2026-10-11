# Evidence provenance transform profile v4

This additive, fixture-only profile extends the existing typed replay interpreter.
Selection requires its exact digest:

`sha256:bc90648392a6417a157091f8ad4d2dd9f02a356d81003e32f95571e64c8bc7af`

The normative document is
[`evidence-provenance-transform-v4.json`](../../sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v4.json).
The shared [v4 corpus](../../sdk/conformance/testdata/transform-profile/evidence-provenance-v4.json)
is exercised by Go, TypeScript, Python, and Rust.

V4 changes `query_unescape` to preserve malformed percent escapes while decoding
complete escapes in the same input. Its existing 500-round limit remains.
`ordered_query_concat` and `query_subsequence` use this profile-specific behavior.
Strict `percent_decode` and URL component selection retain their rejection rules.

The new `decode_recovery` operation selects a printable candidate from the same
bounded alignments evaluated by the scanner. It accepts `alphabet` (`hex`,
`standard`, or `url`) and optional `occurrence` (default zero, at most three).
Hex candidates include both prefix notation and an interpretation preserving
every hex digit. Each retained token is limited to 4096 bytes. The normative
document defines candidate order, the eight-byte printable-run requirement,
incomplete tails, and padding. Operation commitment code 31 is
appended; existing operation codes retain their values.

Every profile still rejects invalid UTF-8 before execution and after each
operation. Existing operation-count, input, output, and cumulative processing
limits apply. V1, v2, and v3 documents, digests, vocabularies, and replay semantics
remain unchanged. Older profiles reject the new operation. There is no fallback
from an unknown digest and no automatic upgrade of an existing recipe.

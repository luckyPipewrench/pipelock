# Evidence provenance transform profile v4

This additive, fixture-only profile extends the existing typed replay interpreter.
Selection requires its exact digest:

`sha256:f9566968c9a50297d67b48fd207329e685e3c61a176befd22aa8aad1d0f6877c`

The normative document is
[`evidence-provenance-transform-v4.json`](../../sdk/conformance/testdata/transform-profile/evidence-provenance-transform-v4.json).
The shared [v4 corpus](../../sdk/conformance/testdata/transform-profile/evidence-provenance-v4.json)
is exercised by Go, TypeScript, Python, and Rust.

V4 changes `query_unescape` to preserve malformed percent escapes while decoding
complete escapes in the same input. Its existing 500-round limit remains.
`ordered_query_concat` and `query_subsequence` use this profile-specific behavior.
Strict `percent_decode` and URL component selection retain their rejection rules.

The new `decode_recovery` operation filters one selected encoding alphabet and
reads a bounded byte alignment. It accepts `alphabet` (`hex`, `standard`, or
`url`) and optional `occurrence` (default zero, at most one for hex or three for
base64). Its retained token limit is 4096 bytes. The normative document defines
prefix handling, incomplete tails, and padding. Operation commitment code 31 is
appended; existing operation codes retain their values.

Every profile still rejects invalid UTF-8 before execution and after each
operation. Existing operation-count, input, output, and cumulative processing
limits apply. V1, v2, and v3 documents, digests, vocabularies, and replay semantics
remain unchanged. Older profiles reject the new operation. There is no fallback
from an unknown digest and no automatic upgrade of an existing recipe.

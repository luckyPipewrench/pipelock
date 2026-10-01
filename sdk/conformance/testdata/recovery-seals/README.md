# Recovery seal conformance fixture

`valid/` contains the evidence directory and signed recovery seal emitted by the real Go recorder and receipt-emitter recovery path. The predecessor shard ends with trailing NUL bytes, and the successor run begins with a signed genesis `session_open`. Go, TypeScript, and Rust tests read these same files so the three verifiers agree on the signature, shard binding, successor binding, and discontinuity result.

`seal.json` is a copy of the predecessor claim file for convenient schema inspection. `signer.pub` contains the public key used by this fixture. The deterministic seed is public test data only; it must never sign production evidence.

`rotated/` contains a second real-writer fixture whose damaged predecessor changed signing keys before recovery. Its `signer.pub` lists both keys, one per line. All three verifiers require both keys to verify that prefix; evidence doctor inspects its signatures and placement without deciding operator trust.

Regenerate the fixture from the writer path with `go test ./sdk/conformance -run TestGenerateRecoverySealFixture -update`.

Regenerate the rotated fixture with `go test ./sdk/conformance -run TestGenerateRotatedRecoverySealFixture -update`.

The test skips generation unless `-update` is present. Review fixture changes together with the recovery-seal schema and all three verifier test results.

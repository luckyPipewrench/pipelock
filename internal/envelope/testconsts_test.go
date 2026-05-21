// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

// Test-shared string constants. Extracted to satisfy goconst across the
// envelope test suite and keep fixture data consistent.
const (
	testReceiptID1     = "01961f3a-7b2c-7000-8000-000000000001"
	testReceiptID2     = "01961f3a-7b2c-7000-8000-000000000002"
	testActionWrite    = "write"
	testActionRead     = "read"
	testVerdictAllow   = "allow"
	testSideEffectExt  = "external_write"
	testActorAgent     = "agent"
	testActorAgentTest = "agent:test"
	testActorAlpha     = "alpha"
	testKeyIDTest      = "test"
	testKeyIDTrusted   = "trusted-key"
	testConfigHashSHA  = "sha256:test"
	testTrustDomain    = "example.test"
	testHeaderSigInput = "Signature-Input"
	testHeaderSig      = "Signature"
	testTrustBadDomain = "bad/domain"
	testInvalidSigB64  = "pipelock1=:AQI=:"

	// globalHex is the shared 32-byte hex sentinel used as ConfigHash in
	// emitter tests. Moved to file scope so it can be referenced from
	// multiple test functions.
	globalHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
)

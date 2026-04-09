// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package conformance hosts golden receipt files and cross-implementation
// tests for the pipelock action receipt format.
//
// The files in testdata/ are the byte-for-byte contract that any receipt
// verifier (Go, Python, or otherwise) MUST agree on. Go verifies them via
// the tests in this package. The reference Python verifier lives at
// https://github.com/luckyPipewrench/pipelock-verify-python and consumes
// the same files.
//
// Golden files:
//
//   - testdata/test-key.json        Test keypair seed + public key hex.
//   - testdata/valid-single.json    Single valid receipt, seq 0, genesis prev.
//   - testdata/valid-chain.jsonl    Five-receipt chain (one JSON per line).
//   - testdata/invalid-signature.json  Valid structure, tampered signature.
//   - testdata/broken-chain.jsonl   Five receipts, individually signed but
//     with a prev_hash break at seq 3.
//
// The signing key is deterministic (seeded from a known phrase) so the
// golden files can be regenerated bit-identical with:
//
//	go test ./sdk/conformance/ -run TestGenerateGoldenFiles -update
//
// The key is a TEST key. Never use it for production signing.
package conformance

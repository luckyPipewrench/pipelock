// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/svidsidecar"
)

// loadSVIDFile reads a --svid sidecar into the producer evidence and the
// verifier's pinned SVID options. The sidecar schema and its parsing live in
// internal/svidsidecar, shared with the AARP conformance corpus so the bytes the
// corpus generator writes are exactly the bytes this CLI parses.
//
// A structural problem in the operator-pinned trust material (bad bundle DER,
// unparseable window, empty domain) is a configuration error, never a fixture
// verdict: the bundle is trusted input. Attacks live in the evidence/binding,
// which aarp.VerifySVIDBinding appraises fail-closed (no claim inflation).
func loadSVIDFile(path string) (*aarp.SVIDEvidence, aarp.SVIDVerifyOptions, error) {
	return svidsidecar.Load(path)
}

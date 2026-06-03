// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/svid"
)

// svidFile is the per-fixture SVID input the four reference verifiers read with
// --svid. It is deliberately separate from both the envelope (producer-signed)
// and the Ed25519 trust file (envelope-signing trust): an SVID binding carries
// its own producer evidence AND its own verifier-pinned context, and the context
// (trust domain, bundle history, action time) varies per fixture — a
// trust-domain-confusion or stale-bundle attack cannot share one global trust
// file with a valid baseline.
//
//   - evidence: the producer-supplied X.509-SVID proof-of-possession. Its JSON
//     shape is exactly aarp.SVIDEvidence (decoded straight into it).
//   - verify:   the verifier's pinned SVID trust context — never anything the
//     producer controls. The bundle authorities are operator-pinned CA DER; the
//     action time is the point-in-time the SVID is validated at (offline).
type svidFile struct {
	Evidence aarp.SVIDEvidence `json:"evidence"`
	Verify   svidVerifyFile    `json:"verify"`
}

// svidVerifyFile is the verifier-pinned SVID trust context for one fixture.
type svidVerifyFile struct {
	// TrustDomain is the SPIFFE trust domain the SVID must validate against.
	TrustDomain string `json:"trust_domain"`
	// ActionTime is the RFC3339Nano point-in-time the SVID is validated at
	// (offline, not "now").
	ActionTime string `json:"action_time"`
	// AllowedSPIFFEIDs, when non-empty, is the exact set of permitted SPIFFE IDs.
	AllowedSPIFFEIDs []string `json:"allowed_spiffe_ids,omitempty"`
	// Bundle is the pinned trust-bundle history (one or more generations), in
	// chronological order.
	Bundle []svidBundleGenFile `json:"bundle"`
}

// svidBundleGenFile is one pinned trust-bundle generation: a window and the CA
// authorities authoritative during it.
type svidBundleGenFile struct {
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after,omitempty"`
	AuthoritiesDERB64 []string `json:"authorities_der_b64"`
}

// loadSVIDFile reads a --svid sidecar into the producer evidence and the
// verifier's pinned SVID options. A structural problem in the operator-pinned
// trust material (bad bundle DER, unparseable window, empty domain) is a
// configuration error (exit 2), never a fixture verdict: the bundle is trusted
// input, so a malformed bundle is operator misconfiguration, not an attack the
// appraisal should silently absorb. Attacks live in the evidence/binding, which
// aarp.VerifySVIDBinding appraises fail-closed (no claim inflation).
func loadSVIDFile(path string) (*aarp.SVIDEvidence, aarp.SVIDVerifyOptions, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("read svid file: %w", err)
	}
	var sf svidFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sf); err != nil {
		return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("parse svid file: %w", err)
	}
	// Reject trailing tokens after the JSON value: Decode reads only the first
	// value, so a second value (or junk) would otherwise pass silently. A clean
	// file decodes exactly one object and then hits EOF.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("parse svid file: unexpected trailing data after JSON value")
	}

	gens := make([]svid.Generation, 0, len(sf.Verify.Bundle))
	for i, b := range sf.Verify.Bundle {
		notBefore, err := time.Parse(time.RFC3339Nano, b.NotBefore)
		if err != nil {
			return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].not_before: %w", i, err)
		}
		var notAfter time.Time
		if b.NotAfter != "" {
			notAfter, err = time.Parse(time.RFC3339Nano, b.NotAfter)
			if err != nil {
				return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].not_after: %w", i, err)
			}
		}
		authorities := make([]*x509.Certificate, 0, len(b.AuthoritiesDERB64))
		for j, derB64 := range b.AuthoritiesDERB64 {
			der, err := base64.StdEncoding.DecodeString(derB64)
			if err != nil {
				return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].authorities_der_b64[%d]: %w", i, j, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].authorities_der_b64[%d]: parse certificate: %w", i, j, err)
			}
			authorities = append(authorities, cert)
		}
		gen, err := svid.NewGeneration(notBefore, notAfter, authorities)
		if err != nil {
			return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d]: %w", i, err)
		}
		gens = append(gens, gen)
	}

	history, err := svid.NewTrustBundleHistory(sf.Verify.TrustDomain, gens...)
	if err != nil {
		return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("build trust bundle history: %w", err)
	}
	actionTime, err := time.Parse(time.RFC3339Nano, sf.Verify.ActionTime)
	if err != nil {
		return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("verify.action_time: %w", err)
	}

	opts := aarp.SVIDVerifyOptions{
		TrustDomain:      sf.Verify.TrustDomain,
		History:          history,
		ActionTime:       actionTime,
		AllowedSPIFFEIDs: sf.Verify.AllowedSPIFFEIDs,
	}
	return &sf.Evidence, opts, nil
}

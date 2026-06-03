// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package svidsidecar defines the on-disk --svid sidecar schema shared by the
// pipelock-verifier CLI and the AARP conformance corpus, plus the parser that
// turns a sidecar's verifier-pinned `verify` block into aarp.SVIDVerifyOptions.
//
// A sidecar carries two independent halves with very different trust:
//
//   - Evidence: the producer-supplied X.509-SVID proof-of-possession (decoded
//     straight into aarp.SVIDEvidence). It is attacker-controlled and appraised
//     fail-closed by aarp.VerifySVIDBinding — a failure withholds the
//     workload-identity claims, it never rejects the envelope.
//   - Verify: the verifier's pinned SVID trust context (trust domain, bundle
//     history, action time, allowed ids). It is never producer-controlled, so a
//     structural problem here (bad bundle DER, unparseable window, empty domain)
//     is operator misconfiguration, surfaced as an error for the caller to map
//     to a configuration exit code — never a fixture verdict.
//
// The schema lives in one place so the CLI loader and the conformance corpus
// generator/Go-arm cannot drift: the bytes the generator writes are exactly the
// bytes the CLI (and the TS/Rust/Python reference verifiers) parse.
package svidsidecar

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

// Sidecar is the on-disk --svid input. Its JSON shape is the cross-language
// contract every reference verifier reads: evidence decodes straight into
// aarp.SVIDEvidence; verify carries the verifier-pinned context.
type Sidecar struct {
	Evidence aarp.SVIDEvidence `json:"evidence"`
	Verify   VerifyBlock       `json:"verify"`
}

// VerifyBlock is the verifier-pinned SVID trust context for one fixture.
type VerifyBlock struct {
	// TrustDomain is the SPIFFE trust domain the SVID must validate against.
	TrustDomain string `json:"trust_domain"`
	// ActionTime is the RFC3339Nano point-in-time the SVID is validated at
	// (offline, not "now").
	ActionTime string `json:"action_time"`
	// AllowedSPIFFEIDs, when non-empty, is the exact set of permitted SPIFFE IDs.
	AllowedSPIFFEIDs []string `json:"allowed_spiffe_ids,omitempty"`
	// Bundle is the pinned trust-bundle history (one or more generations), in
	// chronological order.
	Bundle []BundleGen `json:"bundle"`
}

// BundleGen is one pinned trust-bundle generation: a window and the CA
// authorities authoritative during it.
type BundleGen struct {
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after,omitempty"`
	AuthoritiesDERB64 []string `json:"authorities_der_b64"`
}

// Parse strictly decodes a sidecar from its on-disk bytes. Unknown fields and
// trailing tokens are rejected so the sidecar is held to the same strict-parse
// discipline as the producer-signed envelope: a clean file decodes exactly one
// object and then hits EOF.
func Parse(data []byte) (*Sidecar, error) {
	var sc Sidecar
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("parse svid file: %w", err)
	}
	// Decode reads only the first value, so a second value (or junk) would
	// otherwise pass silently. A clean file hits EOF on the next Decode.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse svid file: unexpected trailing data after JSON value")
	}
	return &sc, nil
}

// Options builds the verifier-pinned aarp.SVIDVerifyOptions from the sidecar's
// verify block: the bundle history, action time, and allowed-id set. A
// structural problem in this operator-pinned trust material is a configuration
// error, never a fixture verdict — the bundle is trusted input. Attacks live in
// the evidence/binding, which aarp.VerifySVIDBinding appraises fail-closed.
func (s *Sidecar) Options() (aarp.SVIDVerifyOptions, error) {
	gens := make([]svid.Generation, 0, len(s.Verify.Bundle))
	for i, b := range s.Verify.Bundle {
		notBefore, err := time.Parse(time.RFC3339Nano, b.NotBefore)
		if err != nil {
			return aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].not_before: %w", i, err)
		}
		var notAfter time.Time
		if b.NotAfter != "" {
			notAfter, err = time.Parse(time.RFC3339Nano, b.NotAfter)
			if err != nil {
				return aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].not_after: %w", i, err)
			}
		}
		authorities := make([]*x509.Certificate, 0, len(b.AuthoritiesDERB64))
		for j, derB64 := range b.AuthoritiesDERB64 {
			der, err := base64.StdEncoding.DecodeString(derB64)
			if err != nil {
				return aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].authorities_der_b64[%d]: %w", i, j, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d].authorities_der_b64[%d]: parse certificate: %w", i, j, err)
			}
			authorities = append(authorities, cert)
		}
		gen, err := svid.NewGeneration(notBefore, notAfter, authorities)
		if err != nil {
			return aarp.SVIDVerifyOptions{}, fmt.Errorf("bundle[%d]: %w", i, err)
		}
		gens = append(gens, gen)
	}

	history, err := svid.NewTrustBundleHistory(s.Verify.TrustDomain, gens...)
	if err != nil {
		return aarp.SVIDVerifyOptions{}, fmt.Errorf("build trust bundle history: %w", err)
	}
	actionTime, err := time.Parse(time.RFC3339Nano, s.Verify.ActionTime)
	if err != nil {
		return aarp.SVIDVerifyOptions{}, fmt.Errorf("verify.action_time: %w", err)
	}

	return aarp.SVIDVerifyOptions{
		TrustDomain:      s.Verify.TrustDomain,
		History:          history,
		ActionTime:       actionTime,
		AllowedSPIFFEIDs: s.Verify.AllowedSPIFFEIDs,
	}, nil
}

// Load reads, strictly parses, and resolves a sidecar file into the producer
// evidence and the verifier-pinned options. It is the CLI's one-call entry; the
// conformance corpus uses Parse + Options directly on in-memory sidecars.
func Load(path string) (*aarp.SVIDEvidence, aarp.SVIDVerifyOptions, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, aarp.SVIDVerifyOptions{}, fmt.Errorf("read svid file: %w", err)
	}
	sc, err := Parse(data)
	if err != nil {
		return nil, aarp.SVIDVerifyOptions{}, err
	}
	opts, err := sc.Options()
	if err != nil {
		return nil, aarp.SVIDVerifyOptions{}, err
	}
	return &sc.Evidence, opts, nil
}

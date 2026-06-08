// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// testCertDER builds a self-signed Ed25519 certificate DER. With isCA it is a
// valid trust authority; without it (a leaf) NewGeneration rejects it, which
// exercises loadSVIDFile's generation-error branch. The validity window is
// wall-clock-relative (loadSVIDFile does not check cert time; only NewGeneration's
// CA-flag/key-usage checks matter here), so this is not a time-bomb.
func testCertDER(t *testing.T, isCA bool) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svid-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.BasicConstraintsValid = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

// baseSVIDSidecar returns a well-formed sidecar map (parseable by loadSVIDFile)
// with caDERb64 as the pinned authority. The evidence is dummy: loadSVIDFile only
// parses it into aarp.SVIDEvidence and never verifies the binding.
func baseSVIDSidecar(caDERb64 string) map[string]any {
	return map[string]any{
		"evidence": map[string]any{
			"type":         "x509",
			"spiffe_id":    "spiffe://example.org/workload/agent-a",
			"leaf_der_b64": base64.StdEncoding.EncodeToString([]byte("dummy-leaf-der")),
			"nonce":        base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
			"issued_at":    "2026-04-15T12:00:00.000000000Z",
			"binding": map[string]any{
				"alg":           "ed25519",
				"context":       "pipelock-aarp-v0.1/svid-receipt-binding",
				"signature_b64": base64.StdEncoding.EncodeToString([]byte("dummy-sig")),
			},
		},
		"verify": map[string]any{
			"trust_domain": "example.org",
			"action_time":  "2026-04-15T12:00:00.000000000Z",
			"bundle": []any{
				map[string]any{
					"not_before":          "2025-01-01T00:00:00Z",
					"authorities_der_b64": []any{caDERb64},
				},
			},
		},
	}
}

func writeSVIDSidecar(t *testing.T, dir string, sc any) string {
	t.Helper()
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("marshal sidecar: %v", err)
	}
	path := filepath.Join(dir, "sidecar.svid.json")
	writeFileT(t, path, b)
	return path
}

func TestLoadSVIDFile_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caDER := base64.StdEncoding.EncodeToString(testCertDER(t, true))
	path := writeSVIDSidecar(t, dir, baseSVIDSidecar(caDER))

	ev, opts, err := loadSVIDFile(path)
	if err != nil {
		t.Fatalf("loadSVIDFile: %v", err)
	}
	if ev == nil || ev.Type != "x509" {
		t.Fatalf("evidence not parsed: %+v", ev)
	}
	if opts.History == nil {
		t.Fatal("trust bundle history is nil")
	}
	if opts.TrustDomain != "example.org" {
		t.Fatalf("trust domain = %q, want example.org", opts.TrustDomain)
	}
	if opts.ActionTime.IsZero() {
		t.Fatal("action time not parsed")
	}
}

func TestLoadSVIDFile_Errors(t *testing.T) {
	t.Parallel()
	caDER := base64.StdEncoding.EncodeToString(testCertDER(t, true))
	leafDER := base64.StdEncoding.EncodeToString(testCertDER(t, false))

	// withVerify returns the base sidecar with the verify block replaced.
	withVerify := func(v map[string]any) map[string]any {
		sc := baseSVIDSidecar(caDER)
		sc["verify"] = v
		return sc
	}
	bundle := func(notBefore, notAfter string, auths ...string) []any {
		gen := map[string]any{"not_before": notBefore, "authorities_der_b64": toAnySlice(auths)}
		if notAfter != "" {
			gen["not_after"] = notAfter
		}
		return []any{gen}
	}

	tests := []struct {
		name string
		// raw, when non-empty, is written verbatim (for non-JSON-object cases).
		raw     string
		sidecar map[string]any
	}{
		{name: "malformed json", raw: "{not json"},
		{
			name: "unknown top-level field",
			sidecar: func() map[string]any {
				sc := baseSVIDSidecar(caDER)
				sc["extra"] = "x"
				return sc
			}(),
		},
		{
			name:    "bad not_before",
			sidecar: withVerify(map[string]any{"trust_domain": "example.org", "action_time": "2026-04-15T12:00:00Z", "bundle": bundle("not-a-time", "", caDER)}),
		},
		{
			name:    "bad not_after",
			sidecar: withVerify(map[string]any{"trust_domain": "example.org", "action_time": "2026-04-15T12:00:00Z", "bundle": bundle("2025-01-01T00:00:00Z", "not-a-time", caDER)}),
		},
		{
			name:    "bad authority base64",
			sidecar: withVerify(map[string]any{"trust_domain": "example.org", "action_time": "2026-04-15T12:00:00Z", "bundle": bundle("2025-01-01T00:00:00Z", "", "!!!not-base64!!!")}),
		},
		{
			name:    "unparseable authority cert",
			sidecar: withVerify(map[string]any{"trust_domain": "example.org", "action_time": "2026-04-15T12:00:00Z", "bundle": bundle("2025-01-01T00:00:00Z", "", base64.StdEncoding.EncodeToString([]byte("garbage")))}),
		},
		{
			name:    "non-CA authority rejected by generation",
			sidecar: withVerify(map[string]any{"trust_domain": "example.org", "action_time": "2026-04-15T12:00:00Z", "bundle": bundle("2025-01-01T00:00:00Z", "", leafDER)}),
		},
		{
			name:    "invalid trust domain",
			sidecar: withVerify(map[string]any{"trust_domain": "", "action_time": "2026-04-15T12:00:00Z", "bundle": bundle("2025-01-01T00:00:00Z", "", caDER)}),
		},
		{
			name:    "bad action_time",
			sidecar: withVerify(map[string]any{"trust_domain": "example.org", "action_time": "not-a-time", "bundle": bundle("2025-01-01T00:00:00Z", "", caDER)}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			var path string
			if tc.raw != "" {
				path = filepath.Join(dir, "sidecar.svid.json")
				writeFileT(t, path, []byte(tc.raw))
			} else {
				path = writeSVIDSidecar(t, dir, tc.sidecar)
			}
			if _, _, err := loadSVIDFile(path); err == nil {
				t.Fatalf("loadSVIDFile(%s) = nil error, want error", tc.name)
			}
		})
	}
}

func TestLoadSVIDFile_TrailingData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caDER := base64.StdEncoding.EncodeToString(testCertDER(t, true))
	b, err := json.Marshal(baseSVIDSidecar(caDER))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "sidecar.svid.json")
	writeFileT(t, path, append(b, []byte("\n{\"trailing\":true}")...))
	if _, _, err := loadSVIDFile(path); err == nil {
		t.Fatal("loadSVIDFile accepted trailing data after the JSON value")
	}
}

func TestLoadSVIDFile_MissingFile(t *testing.T) {
	t.Parallel()
	if _, _, err := loadSVIDFile(filepath.Join(t.TempDir(), "nope.svid.json")); err == nil {
		t.Fatal("loadSVIDFile(missing) = nil error, want error")
	}
}

// TestRunAARP_SVIDAppraises drives the full --svid path: the sidecar loads, the
// envelope appraises, and the (dummy, non-verifying) binding withholds the
// workload-identity claims without failing the envelope (exit 0).
func TestRunAARP_SVIDAppraises(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envPath, trustPath := aarpEnvFixtures(t, dir)
	caDER := base64.StdEncoding.EncodeToString(testCertDER(t, true))
	svidPath := writeSVIDSidecar(t, dir, baseSVIDSidecar(caDER))

	var out, errBuf bytes.Buffer
	err := runAARP(&out, &errBuf, envPath, aarpOptions{trustPath: trustPath, svidPath: svidPath, jsonOutput: true})
	if err != nil {
		t.Fatalf("runAARP --svid: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"assertion_signed":true`)) {
		t.Fatalf("expected an appraisal, got: %s", out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("signing_workload_svid_bound")) {
		t.Fatalf("dummy binding must not inflate workload identity: %s", out.String())
	}
}

func TestRunAARP_SVIDLoadError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envPath, trustPath := aarpEnvFixtures(t, dir)
	badSVID := filepath.Join(dir, "bad.svid.json")
	writeFileT(t, badSVID, []byte("{not json"))

	var out, errBuf bytes.Buffer
	err := runAARP(&out, &errBuf, envPath, aarpOptions{trustPath: trustPath, svidPath: badSVID, jsonOutput: true})
	assertExitCode(t, err, cliutil.ExitConfig)
}

// toAnySlice converts a []string to []any for JSON map construction.
func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

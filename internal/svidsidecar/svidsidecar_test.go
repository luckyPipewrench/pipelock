// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package svidsidecar_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/svidsidecar"
)

const (
	testTrustDomain = "example.org"
	testActionTime  = "2026-04-15T12:00:00.000000000Z"
	testNotBefore   = "2025-01-01T00:00:00Z"
)

// caDERB64 builds a self-signed Ed25519 CA certificate DER, base64-std encoded.
// With isCA=false the cert is a leaf, which NewGeneration rejects (not a CA) —
// the Options authority-validation branch. The window is wall-clock-relative so
// this is not a time-bomb (Options does not check cert validity time).
func caDERB64(t *testing.T, isCA bool) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svidsidecar-test"},
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
	return base64.StdEncoding.EncodeToString(der)
}

// validSidecarJSON returns a well-formed sidecar with caB64 as the single pinned
// authority. The evidence is opaque here: this package only parses it into
// aarp.SVIDEvidence and never verifies the binding (that is aarp's job).
func validSidecarJSON(caB64 string) string {
	return `{
  "evidence": {
    "type": "x509",
    "spiffe_id": "spiffe://example.org/workload/agent-a",
    "leaf_der_b64": "ZHVtbXktbGVhZi1kZXI=",
    "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "issued_at": "` + testActionTime + `",
    "binding": {
      "alg": "ed25519",
      "context": "pipelock-aarp-v0.1/svid-receipt-binding",
      "payload_sha256": "",
      "signature_b64": "ZHVtbXktc2ln"
    }
  },
  "verify": {
    "trust_domain": "` + testTrustDomain + `",
    "action_time": "` + testActionTime + `",
    "bundle": [
      { "not_before": "` + testNotBefore + `", "authorities_der_b64": ["` + caB64 + `"] }
    ]
  }
}`
}

func TestParse(t *testing.T) {
	t.Parallel()
	ca := caDERB64(t, true)
	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		sc, err := svidsidecar.Parse([]byte(validSidecarJSON(ca)))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if sc.Evidence.Type != "x509" {
			t.Errorf("evidence.type = %q, want x509", sc.Evidence.Type)
		}
		if sc.Verify.TrustDomain != testTrustDomain {
			t.Errorf("verify.trust_domain = %q, want %q", sc.Verify.TrustDomain, testTrustDomain)
		}
		if len(sc.Verify.Bundle) != 1 {
			t.Fatalf("bundle len = %d, want 1", len(sc.Verify.Bundle))
		}
	})

	for _, tc := range []struct {
		name string
		data string
	}{
		{"unknown field", `{"evidence":{},"verify":{},"extra":1}`},
		{"unknown nested field", `{"evidence":{"bogus":1},"verify":{}}`},
		{"malformed json", `{"evidence":`},
		{"trailing data", validSidecarJSON(ca) + `{"second":true}`},
		{"trailing junk", validSidecarJSON(ca) + ` not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := svidsidecar.Parse([]byte(tc.data)); err == nil {
				t.Fatalf("Parse(%s) = nil error, want error", tc.name)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()
	ca := caDERB64(t, true)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		sc, err := svidsidecar.Parse([]byte(validSidecarJSON(ca)))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		opts, err := sc.Options()
		if err != nil {
			t.Fatalf("Options: %v", err)
		}
		if opts.TrustDomain != testTrustDomain {
			t.Errorf("opts.TrustDomain = %q, want %q", opts.TrustDomain, testTrustDomain)
		}
		if opts.History == nil {
			t.Error("opts.History is nil")
		}
		if opts.ActionTime.IsZero() {
			t.Error("opts.ActionTime is zero")
		}
	})

	leaf := caDERB64(t, false) // not a CA -> NewGeneration rejects it
	for _, tc := range []struct {
		name  string
		block svidsidecar.VerifyBlock
	}{
		{
			name: "bad not_before",
			block: svidsidecar.VerifyBlock{TrustDomain: testTrustDomain, ActionTime: testActionTime, Bundle: []svidsidecar.BundleGen{
				{NotBefore: "not-a-time", AuthoritiesDERB64: []string{ca}},
			}},
		},
		{
			name: "bad not_after",
			block: svidsidecar.VerifyBlock{TrustDomain: testTrustDomain, ActionTime: testActionTime, Bundle: []svidsidecar.BundleGen{
				{NotBefore: testNotBefore, NotAfter: "not-a-time", AuthoritiesDERB64: []string{ca}},
			}},
		},
		{
			name: "bad authority base64",
			block: svidsidecar.VerifyBlock{TrustDomain: testTrustDomain, ActionTime: testActionTime, Bundle: []svidsidecar.BundleGen{
				{NotBefore: testNotBefore, AuthoritiesDERB64: []string{"!!!not-base64!!!"}},
			}},
		},
		{
			name: "bad authority DER",
			block: svidsidecar.VerifyBlock{TrustDomain: testTrustDomain, ActionTime: testActionTime, Bundle: []svidsidecar.BundleGen{
				{NotBefore: testNotBefore, AuthoritiesDERB64: []string{base64.StdEncoding.EncodeToString([]byte("not-a-cert"))}},
			}},
		},
		{
			name: "authority not a CA",
			block: svidsidecar.VerifyBlock{TrustDomain: testTrustDomain, ActionTime: testActionTime, Bundle: []svidsidecar.BundleGen{
				{NotBefore: testNotBefore, AuthoritiesDERB64: []string{leaf}},
			}},
		},
		{
			name: "bad trust domain",
			block: svidsidecar.VerifyBlock{TrustDomain: "127.0.0.1", ActionTime: testActionTime, Bundle: []svidsidecar.BundleGen{
				{NotBefore: testNotBefore, AuthoritiesDERB64: []string{ca}},
			}},
		},
		{
			name: "bad action_time",
			block: svidsidecar.VerifyBlock{TrustDomain: testTrustDomain, ActionTime: "not-a-time", Bundle: []svidsidecar.BundleGen{
				{NotBefore: testNotBefore, AuthoritiesDERB64: []string{ca}},
			}},
		},
		{
			name:  "empty bundle",
			block: svidsidecar.VerifyBlock{TrustDomain: testTrustDomain, ActionTime: testActionTime, Bundle: nil},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sc := &svidsidecar.Sidecar{Verify: tc.block}
			if _, err := sc.Options(); err == nil {
				t.Fatalf("Options(%s) = nil error, want error", tc.name)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	ca := caDERB64(t, true)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "sidecar.svid.json")
		if err := os.WriteFile(path, []byte(validSidecarJSON(ca)), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		ev, opts, err := svidsidecar.Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if ev == nil || ev.Type != "x509" {
			t.Errorf("evidence = %+v, want type x509", ev)
		}
		if opts.History == nil {
			t.Error("opts.History is nil")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		if _, _, err := svidsidecar.Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Fatal("Load(missing) = nil error, want error")
		}
	})

	t.Run("malformed json file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "malformed.svid.json")
		if err := os.WriteFile(path, []byte(`{"evidence":`), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := svidsidecar.Load(path); err == nil {
			t.Fatal("Load(malformed) = nil error, want error")
		}
	})

	t.Run("bad verify block", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.svid.json")
		bad := `{"evidence":{"type":"x509"},"verify":{"trust_domain":"example.org","action_time":"nope","bundle":[]}}`
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := svidsidecar.Load(path); err == nil {
			t.Fatal("Load(bad verify) = nil error, want error")
		}
	})
}

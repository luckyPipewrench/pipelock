// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package coveragecertverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/coveragecert"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func writeCoverageCertVerifyFixture(t *testing.T) (certFile, pubHex string) {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert, err := coveragecert.Sign(coveragecert.Body{
		Schema:        coveragecert.Schema,
		KeyPurpose:    coveragecert.KeyPurpose,
		Agent:         "agent-a",
		WindowStart:   start,
		WindowEnd:     start.Add(time.Hour),
		TotalReceipts: 2,
		Sessions: []coveragecert.SessionCoverage{{
			ID:                 "session-a",
			ReceiptCount:       2,
			ChainIntact:        true,
			Anchored:           "local",
			CompletenessStatus: "LIMITED",
			CompletenessReason: "bounded_closed",
		}},
		SessionsCovered:    1,
		ChainsIntact:       1,
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           coveragecert.DefaultBoundary(),
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}, priv)
	if err != nil {
		t.Fatalf("coveragecert.Sign: %v", err)
	}
	data, err := coveragecert.Marshal(cert)
	if err != nil {
		t.Fatalf("coveragecert.Marshal: %v", err)
	}
	certFile = filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return certFile, hex.EncodeToString(pub)
}

func TestRunTrustedSignerVerifies(t *testing.T) {
	certFile, pubHex := writeCoverageCertVerifyFixture(t)
	var out bytes.Buffer

	if err := Run(Options{
		CertFile:       certFile,
		TrustedSigners: []string{"inline=" + pubHex},
		Out:            &out,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), "Signature: valid") {
		t.Fatalf("Run output = %q, want bounded verification lines", out.String())
	}
}

func TestRunUntrustedSignerFailsClosed(t *testing.T) {
	certFile, _ := writeCoverageCertVerifyFixture(t)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var out bytes.Buffer

	err = Run(Options{
		CertFile:       certFile,
		TrustedSigners: []string{"inline=" + hex.EncodeToString(otherPub)},
		Out:            &out,
	})
	if err == nil || !strings.Contains(err.Error(), "not in the trusted-signer set") {
		t.Fatalf("Run err = %v, want fail-closed untrusted-signer error", err)
	}
	// The diagnostic line is still emitted before the fail-closed return.
	if !strings.Contains(out.String(), "NOT TRUSTED") {
		t.Fatalf("Run output = %q, want NOT TRUSTED diagnostic line", out.String())
	}
}

func TestRunFailsClosed(t *testing.T) {
	certFile, pubHex := writeCoverageCertVerifyFixture(t)
	data, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(data), `"agent": "agent-a"`, `"agent": "agent-b"`, 1)
	if tampered == string(data) {
		t.Fatal("fixture did not contain agent field")
	}
	tamperedFile := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(tamperedFile, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err = Run(Options{CertFile: tamperedFile, TrustedSigners: []string{"inline=" + pubHex}})
	if err == nil || !strings.Contains(err.Error(), "signature is INVALID") {
		t.Fatalf("Run tampered error = %v, want invalid signature", err)
	}

	err = Run(Options{CertFile: filepath.Join(t.TempDir(), "missing.json")})
	if err == nil || !strings.Contains(err.Error(), "--cert") {
		t.Fatalf("Run missing file error = %v, want --cert", err)
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package certgen

import (
	"testing"
	"time"
)

func TestGenerateCA_ZeroValidity(t *testing.T) {
	t.Parallel()

	_, _, _, err := GenerateCA(testOrg, 0)
	if err == nil {
		t.Fatal("expected error for zero validity, got nil")
	}
}

func TestGenerateCA_NegativeValidity(t *testing.T) {
	t.Parallel()

	_, _, _, err := GenerateCA(testOrg, -time.Hour)
	if err == nil {
		t.Fatal("expected error for negative validity, got nil")
	}
}

func TestGenerateCA_PEMOutput(t *testing.T) {
	t.Parallel()

	_, _, pemBytes, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatalf("GenerateCA error: %v", err)
	}
	// PEM output should start with the certificate header.
	const pemHeader = "-----BEGIN CERTIFICATE-----"
	if len(pemBytes) < len(pemHeader) {
		t.Fatalf("PEM bytes too short: got %d, need at least %d", len(pemBytes), len(pemHeader))
	}
	if string(pemBytes[:len(pemHeader)]) != pemHeader {
		t.Errorf("PEM output should start with %q", pemHeader)
	}
}

func TestGenerateCA_MaxPathLenZero(t *testing.T) {
	t.Parallel()

	cert, _, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatalf("GenerateCA error: %v", err)
	}
	// CA should have MaxPathLen=0 (can only sign leaf certs).
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}
	if !cert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be true")
	}
}

func TestGenerateLeaf_ZeroTTL(t *testing.T) {
	t.Parallel()

	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatalf("GenerateCA error: %v", err)
	}
	_, err = GenerateLeaf(ca, caKey, testHost, 0)
	if err == nil {
		t.Fatal("expected error for zero TTL, got nil")
	}
}

func TestGenerateLeaf_NegativeTTL(t *testing.T) {
	t.Parallel()

	ca, caKey, _, err := GenerateCA(testOrg, testValidityDay)
	if err != nil {
		t.Fatalf("GenerateCA error: %v", err)
	}
	_, err = GenerateLeaf(ca, caKey, testHost, -time.Hour)
	if err == nil {
		t.Fatal("expected error for negative TTL, got nil")
	}
}

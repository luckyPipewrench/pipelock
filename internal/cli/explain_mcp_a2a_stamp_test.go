// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	// explainStampSeedIndex selects the key (seed = sha256 of the index as a
	// little-endian uint64) whose signature over explainSignedAgentCardRPC's
	// card contains explainStampRun: a credential-shaped run that is only a
	// coincidence of the base64url alphabet.
	explainStampSeedIndex = 245205
	explainStampRun       = "JCHhf" + "_dD89X92nLzqDlMKU9" + "YnfrLpuluGyZtz4d51-8m"
	explainStampPattern   = "Hugging Face Token"
)

func explainStampKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	var le [8]byte
	binary.LittleEndian.PutUint64(le[:], explainStampSeedIndex)
	seed := sha256.Sum256(le[:])
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("ed25519 public key has unexpected type")
	}
	return pub, priv
}

func TestBuildMCPExplainReport_A2AVerifiedSignatureStampIsNotCredentialScanned(t *testing.T) {
	pub, priv := explainStampKey(t)
	line := explainSignedAgentCardRPC(t, priv, nil)
	if !strings.Contains(string(line), explainStampRun) {
		t.Fatalf("fixture no longer carries the credential-shaped signature run %q", explainStampRun)
	}
	cfg := explainA2ASignatureConfig(t, pub)
	a2aContext := mcpExplainA2AContext{Method: "GetExtendedAgentCard", Origin: explainA2ACardURL}

	t.Run("verified stamp is allowed", func(t *testing.T) {
		report, err := buildMCPExplainReportWithA2AContext(cfg, "(test)", "vendor", line, a2aContext)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if !report.Allowed || report.Error != "" || len(report.Patterns) != 0 {
			t.Fatalf("verified stamp = %+v, want allowed with no credential finding", report)
		}
	})

	t.Run("same card without a trusted key is blocked for the stamp", func(t *testing.T) {
		untrusted := explainA2ASignatureConfig(t, pub)
		untrusted.A2AScanning.TrustedAgentCardKeys = nil
		untrusted.A2AScanning.RequireSignedAgentCards = false
		report, err := buildMCPExplainReportWithA2AContext(untrusted, "(test)", "vendor", line, a2aContext)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if report.Allowed || !slices.Contains(report.Patterns, explainStampPattern) {
			t.Fatalf("no trusted key = %+v, want a %s block", report, explainStampPattern)
		}
	})

	t.Run("forged signature carrying a token is blocked", func(t *testing.T) {
		forged := "hf" + "_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" + "-" + strings.Repeat("A", 46)
		raw, err := base64.RawURLEncoding.DecodeString(forged)
		if err != nil || len(raw) != ed25519.SignatureSize {
			t.Fatalf("forged fixture does not decode to a signature: %v", err)
		}
		report, err := buildMCPExplainReportWithA2AContext(cfg, "(test)", "vendor", explainSignedAgentCardRPC(t, priv, raw), a2aContext)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if report.Allowed || report.Action != config.ActionBlock || !slices.Contains(report.Patterns, explainStampPattern) {
			t.Fatalf("forged signature = %+v, want a %s block", report, explainStampPattern)
		}
	})
}

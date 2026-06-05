// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

// fixedStamp is a deterministic generated_at for assembly tests. Relative to
// time.Now is unnecessary here: generated_at is a display stamp, not validated
// against the clock.
func fixedStamp() time.Time {
	return time.Date(2026, time.June, 5, 12, 0, 0, 0, time.UTC)
}

func TestAssemblePacket_AllScenarios(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	outDir := t.TempDir()

	for _, s := range DefaultScenarios() {
		s := s
		t.Run(s.ID, func(t *testing.T) {
			cs, err := eng.Capture(s)
			if err != nil {
				t.Fatalf("Capture: %v", err)
			}
			res, err := AssemblePacket(cs, outDir, fixedStamp())
			if err != nil {
				t.Fatalf("AssemblePacket: %v", err)
			}

			// All four artifact files exist.
			for _, name := range []string{artifactPacketName, artifactEvidenceName, artifactVerifierName, artifactSummaryName} {
				if _, err := os.Stat(filepath.Join(res.PacketDir, name)); err != nil {
					t.Errorf("missing artifact %s: %v", name, err)
				}
			}

			// Packet validates against the v0 schema.
			if err := res.Packet.Validate(); err != nil {
				t.Errorf("packet schema invalid: %v", err)
			}

			// Totals reconcile with the chain (the verifier cross-check).
			if res.Packet.Summary.ReceiptCount != cs.ReceiptCount {
				t.Errorf("summary receipt_count=%d, chain=%d", res.Packet.Summary.ReceiptCount, cs.ReceiptCount)
			}

			// Re-extract the written evidence.jsonl and verify the chain against
			// the published signer key — exactly what the shipped verifier does.
			evidencePath := filepath.Join(res.PacketDir, artifactEvidenceName)
			receipts, err := receipt.ExtractReceipts(evidencePath)
			if err != nil {
				t.Fatalf("re-extract: %v", err)
			}
			chain := receipt.VerifyChain(receipts, res.Packet.Verifier.SignerKey)
			if !chain.Valid {
				t.Fatalf("written evidence chain invalid: %s", chain.Error)
			}
			if chain.RootHash != res.Packet.Verifier.RootHash {
				t.Errorf("root hash drift: chain=%s packet=%s", chain.RootHash, res.Packet.Verifier.RootHash)
			}
		})
	}
}

func TestValidatePacketEnvelopePublicSafe_Rejections(t *testing.T) {
	t.Parallel()

	base := func() *auditpacket.Packet {
		return &auditpacket.Packet{
			Run:      auditpacket.Run{Provider: auditpacket.ProviderLocal, AgentIdentity: labAgentIdentity},
			Verifier: auditpacket.Verifier{SignerKey: "deadbeef"},
		}
	}

	tests := []struct {
		name   string
		mutate func(*auditpacket.Packet)
	}{
		{"non-local provider", func(p *auditpacket.Packet) { p.Run.Provider = auditpacket.ProviderGitHubActions }},
		{"foreign agent identity", func(p *auditpacket.Packet) { p.Run.AgentIdentity = "real-ci-agent" }},
		{"repository leak", func(p *auditpacket.Packet) { p.Run.Repository = "acme/private" }},
		{"config path leak", func(p *auditpacket.Packet) { p.Policy.ConfigPath = "/home/operator/.config/pipelock.yaml" }},
		{"host ip leak", func(p *auditpacket.Packet) { p.Posture.HostIP = "10.0.0.5" }},
		{"proxy url leak", func(p *auditpacket.Packet) { p.Posture.ProxyURL = "http://10.0.0.5:8888" }},
		{"script basename leak", func(p *auditpacket.Packet) { p.Posture.ScriptBasename = "deploy-prod.sh" }},
		{"missing signer key", func(p *auditpacket.Packet) { p.Verifier.SignerKey = "" }},
		{"unsafe touched domain", func(p *auditpacket.Packet) { p.Summary.DomainsTouched = []string{"api.realvendor.io"} }},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := base()
			tc.mutate(p)
			err := ValidatePacketEnvelopePublicSafe(p)
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !errors.Is(err, errEnvelope) {
				t.Fatalf("expected errEnvelope, got %v", err)
			}
		})
	}
}

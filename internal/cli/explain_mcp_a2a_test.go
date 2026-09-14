// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jcs"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	explainA2AOrigin  = "https://agent.example.com"
	explainA2ACardURL = explainA2AOrigin + "/.well-known/agent-card.json"
	explainA2AKeyID   = "vendor-agent-v1"
)

func buildMCPExplainReport(cfg *config.Config, serverName string, line []byte) (mcpExplainReport, error) {
	return buildMCPExplainReportWithA2AContext(cfg, "(test)", serverName, line, mcpExplainA2AContext{})
}

// explainSignedAgentCardRPC uses the same JCS + compact JWS fixture shape as
// the A2A signature integration tests. Keeping the response in its JSON-RPC
// producer envelope proves explain reaches the runtime response dispatcher,
// rather than testing the card scanner in isolation.
func explainSignedAgentCardRPC(t *testing.T, priv ed25519.PrivateKey, signature []byte) []byte {
	t.Helper()
	card := map[string]any{
		"name":        "Vendor Agent",
		"description": "does things",
		"version":     "1.0.0",
		"skills": []any{
			map[string]any{"id": "s1", "name": "search"},
		},
	}
	preimage, err := jcs.Marshal(card)
	if err != nil {
		t.Fatalf("marshal Agent Card preimage: %v", err)
	}
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": explainA2AKeyID})
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	if signature == nil {
		signature = ed25519.Sign(priv, []byte(protected+"."+base64.RawURLEncoding.EncodeToString(preimage)))
	}
	card["signatures"] = []any{map[string]any{
		"protected": protected,
		"signature": base64.RawURLEncoding.EncodeToString(signature),
	}}
	body, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal signed Agent Card: %v", err)
	}
	return []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(body) + `}`)
}

func explainA2ASignatureConfig(t *testing.T, pub ed25519.PublicKey) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.A2AScanning = config.A2AScanning{
		Enabled:                 true,
		Action:                  config.ActionBlock,
		ScanAgentCards:          false,
		DetectCardDrift:         false,
		RequireSignedAgentCards: true,
		TrustedAgentCardKeys: []config.A2ATrustedCardKey{{
			KeyID:          explainA2AKeyID,
			PublicKey:      signing.EncodePublicKey(pub),
			AllowedOrigins: []string{explainA2AOrigin},
		}},
	}
	return cfg
}

func TestBuildMCPExplainReport_A2ASignedAgentCardMatchesRuntimePolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	cfg := explainA2ASignatureConfig(t, pub)
	context := mcpExplainA2AContext{Method: "GetExtendedAgentCard", Origin: explainA2ACardURL}

	t.Run("valid signature is allowed", func(t *testing.T) {
		report, err := buildMCPExplainReportWithA2AContext(cfg, "(test)", "vendor", explainSignedAgentCardRPC(t, priv, nil), context)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if !report.Allowed || report.Error != "" {
			t.Fatalf("valid signed Agent Card = %+v, want allowed", report)
		}
		if len(report.Scanned) != 0 {
			t.Fatalf("signature-only policy claimed generic scans: %v", report.Scanned)
		}
		if !strings.Contains(strings.Join(report.Notes, " "), "A2A response policy used") {
			t.Fatalf("report must identify its A2A request context: %+v", report.Notes)
		}
	})

	t.Run("invalid signature is blocked", func(t *testing.T) {
		report, err := buildMCPExplainReportWithA2AContext(cfg, "(test)", "vendor", explainSignedAgentCardRPC(t, priv, make([]byte, ed25519.SignatureSize)), context)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if report.Allowed || report.Error != "" || report.Action != config.ActionBlock {
			t.Fatalf("invalid signed Agent Card = %+v, want blocked", report)
		}
		if report.Scanner != explainA2AScanner || report.Remediation != nil {
			t.Fatalf("A2A signature finding must not offer generic response suppression: %+v", report)
		}
		if !strings.Contains(strings.Join(report.Notes, " "), "response_scanning suppress entries are not consulted") {
			t.Fatalf("A2A signature finding lacks suppression boundary: %+v", report.Notes)
		}
	})

	t.Run("origin mismatch is blocked without generic remediation", func(t *testing.T) {
		mismatched := mcpExplainA2AContext{Method: "GetExtendedAgentCard", Origin: "https://other.vendor.example/.well-known/agent-card.json"}
		report, err := buildMCPExplainReportWithA2AContext(cfg, "(test)", "vendor", explainSignedAgentCardRPC(t, priv, nil), mismatched)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if report.Allowed || report.Scanner != explainA2AScanner || report.Remediation != nil {
			t.Fatalf("origin mismatch = %+v, want blocked A2A finding without response remediation", report)
		}
	})

	t.Run("A2A injection has no response-scanning suppression", func(t *testing.T) {
		injectionContext := mcpExplainA2AContext{Method: "SendMessage", Origin: explainA2ACardURL}
		report, err := buildMCPExplainReportWithA2AContext(cfg, "(test)", "vendor", []byte(mcpJailbreak), injectionContext)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if report.Allowed || len(report.Patterns) == 0 || report.Remediation != nil {
			t.Fatalf("A2A injection = %+v, want named block without response remediation", report)
		}
	})

	t.Run("warn action describes A2A forwarding", func(t *testing.T) {
		warnCfg := explainA2ASignatureConfig(t, pub)
		warnCfg.A2AScanning.Action = config.ActionWarn
		report, err := buildMCPExplainReportWithA2AContext(warnCfg, "(test)", "vendor", explainSignedAgentCardRPC(t, priv, make([]byte, ed25519.SignatureSize)), context)
		if err != nil {
			t.Fatalf("build report: %v", err)
		}
		if !report.Allowed || report.Action != config.ActionWarn || report.Remediation != nil {
			t.Fatalf("A2A warn = %+v, want allowed A2A warning without remediation", report)
		}
		if !strings.Contains(strings.Join(report.Notes, " "), "a2a_scanning.action is warn") {
			t.Fatalf("A2A warn report lacks runtime direction: %+v", report.Notes)
		}
	})
}

func TestBuildMCPExplainReport_A2AContextAbsentStaysExplicitlyGeneric(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	cfg := explainA2ASignatureConfig(t, pub)

	report, err := buildMCPExplainReport(cfg, "vendor", explainSignedAgentCardRPC(t, priv, make([]byte, ed25519.SignatureSize)))
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	if !report.Allowed || report.Error != "" {
		t.Fatalf("generic report = %+v, want generic clean result", report)
	}
	notes := strings.Join(report.Notes, " ")
	if !strings.Contains(notes, "A2A request context was not supplied") || !strings.Contains(notes, "does not evaluate A2A-specific") {
		t.Fatalf("generic report must state its A2A scope: %+v", report.Notes)
	}
}

func TestBuildMCPExplainReport_A2AContextRejectsBatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	line := append([]byte{'['}, explainSignedAgentCardRPC(t, priv, make([]byte, ed25519.SignatureSize))...)
	line = append(line, ']')
	_, err = buildMCPExplainReportWithA2AContext(explainA2ASignatureConfig(t, pub), "(test)", "vendor", line, mcpExplainA2AContext{Method: "GetExtendedAgentCard", Origin: explainA2ACardURL})
	if err == nil {
		t.Fatal("batch accepted as a single request-correlated A2A response")
	}
}

func TestBuildMCPExplainReport_A2ADisabledUsesGenericPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	cfg := explainA2ASignatureConfig(t, pub)
	cfg.A2AScanning.Enabled = false
	report, err := buildMCPExplainReportWithA2AContext(cfg, "(test)", "vendor", explainSignedAgentCardRPC(t, priv, make([]byte, ed25519.SignatureSize)), mcpExplainA2AContext{
		Method: "GetExtendedAgentCard",
		Origin: explainA2ACardURL,
	})
	if err != nil {
		t.Fatalf("build report: %v", err)
	}
	if !report.Allowed || report.Scanner != "" || report.Remediation != nil {
		t.Fatalf("disabled A2A policy must retain generic clean result: %+v", report)
	}
	if !strings.Contains(strings.Join(report.Notes, " "), "a2a_scanning is disabled") {
		t.Fatalf("disabled A2A policy needs an explicit scope note: %+v", report.Notes)
	}
}

func TestExplainMCPResponseCmd_RejectsIncompleteA2AContext(t *testing.T) {
	for _, args := range [][]string{
		{"--a2a-method", "SendMessage"},
		{"--a2a-origin", explainA2ACardURL},
		{"--a2a-method", "SendMessage", "--a2a-origin", "not-a-url"},
		{"--a2a-method", "not-a2a", "--a2a-origin", explainA2ACardURL},
	} {
		cmd := explainMCPResponseCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetIn(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("args %v succeeded; incomplete or malformed A2A context must be a config error", args)
		}
		if out.Len() != 0 {
			t.Fatalf("args %v emitted a verdict despite invalid A2A context: %q", args, out.String())
		}
	}
}

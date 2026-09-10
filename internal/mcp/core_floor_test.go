// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// coreCredentialToken builds a value that trips the immutable "GitHub Token"
// core DLP pattern. It is assembled at runtime from split literals so gosec
// G101 does not flag a hardcoded credential.
func coreCredentialToken() string {
	return "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
}

// nonCoreSecretValue returns a non-core (Stripe Key) DLP credential. Warn, ask,
// adaptive-upgrade, and authority fixtures use it so they exercise the
// configured action path rather than the immutable core floor, which now
// hard-blocks core credentials regardless of the configured action.
func nonCoreSecretValue() string {
	return "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
}

// TestMCPInputCoreFloor_WarnActionStillBlocksCoreCredential proves the MCP
// input verdict hard-blocks a core-critical credential in a tools/call
// argument even when mcp_input_scanning.action is warn. The core floor cannot
// be suppressed by the configured action, matching the request-body floor.
func TestMCPInputCoreFloor_WarnActionStillBlocksCoreCredential(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	token := coreCredentialToken()
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"note":"` + token + `"}}}`)

	verdict := ScanRequest(context.Background(), msg, sc, config.ActionWarn, config.ActionBlock)
	if verdict.Clean {
		t.Fatalf("expected core credential to be detected, got clean verdict %+v", verdict)
	}
	got := inputVerdictEffectiveAction(verdict, config.ActionWarn)
	if got != config.ActionBlock {
		t.Fatalf("core credential under warn action: effective action = %q, want %q", got, config.ActionBlock)
	}
}

// TestMCPInputCoreFloor_WarnActionAllowsNonCoreConfigured confirms the floor is
// scoped: a non-core DLP finding under warn keeps following the configured
// warn action rather than hard-blocking.
func TestMCPInputCoreFloor_WarnActionAllowsNonCoreConfigured(t *testing.T) {
	// Stripe Key is a non-core built-in DLP pattern: it must keep following
	// the configured warn action, unlike the immutable core floor.
	sc := testScannerWithAction(t, config.ActionWarn)
	nonCore := "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"note":"` + nonCore + `"}}}`)

	verdict := ScanRequest(context.Background(), msg, sc, config.ActionWarn, config.ActionBlock)
	if verdict.Clean {
		t.Fatal("expected non-core Stripe key to be detected")
	}
	for _, m := range verdict.Matches {
		if config.IsCoreDLPPatternName(m.PatternName) {
			t.Fatalf("test value unexpectedly matched a core pattern %q", m.PatternName)
		}
	}
	got := inputVerdictEffectiveAction(verdict, config.ActionWarn)
	if got == config.ActionBlock {
		t.Fatalf("non-core finding under warn should not hard-block, got %q", got)
	}
}

// TestA2ACoreFloor_WarnActionStillBlocksCoreCredential proves the A2A body scan
// hard-blocks a core-critical credential regardless of a2a_scanning.action.
// This is the branch reached when request_body_scanning is disabled and A2A
// scanning carries the body floor.
func TestA2ACoreFloor_WarnActionStillBlocksCoreCredential(t *testing.T) {
	sc := testA2AScanner(t)
	cfg := config.Defaults().A2AScanning
	cfg.Enabled = true
	cfg.Action = config.ActionWarn
	token := coreCredentialToken()
	body := []byte(`{"message":{"parts":[{"text":"here is the token ` + token + `"}]}}`)

	result := ScanA2ARequestBody(context.Background(), body, sc, &cfg)
	if result.Clean {
		t.Fatalf("expected core credential to be detected, got clean result %+v", result)
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("core credential under a2a warn action: result action = %q, want %q", result.Action, config.ActionBlock)
	}
}

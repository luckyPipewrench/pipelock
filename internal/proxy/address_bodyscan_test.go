// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func newAddressProtectionScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = config.ActionBlock
	cfg.AddressProtection.UnknownAction = config.ActionAllow
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4
	cfg.AddressProtection.AllowedAddresses = []string{
		"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e",
	}
	eth := true
	f := false
	cfg.AddressProtection.Chains.ETH = &eth
	cfg.AddressProtection.Chains.BTC = &f
	cfg.AddressProtection.Chains.SOL = &f
	cfg.AddressProtection.Chains.BNB = &f
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func TestScanRequestBody_AddressPoisoningBlocked(t *testing.T) {
	sc := newAddressProtectionScanner(t)

	// JSON body with a poisoned ETH address (lookalike of allowlisted).
	body := `{"to": "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e", "amount": "1.0"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1024 * 1024,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("poisoned address in body should not be clean")
	}
	if len(result.AddressFindings) == 0 {
		t.Fatal("expected address findings")
	}
	if result.Reason == "" {
		t.Error("expected non-empty reason for address poisoning")
	}
	if !strings.Contains(result.Reason, "address poisoning") {
		t.Errorf("reason should mention address poisoning, got: %q", result.Reason)
	}
}

func TestScanRequestBody_AddressExactMatchClean(t *testing.T) {
	sc := newAddressProtectionScanner(t)

	// Exact allowlisted address — should pass clean.
	body := `{"to": "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "amount": "1.0"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1024 * 1024,
		Scanner:     sc,
	})
	if !result.Clean {
		t.Error("exact allowlisted address should be clean")
	}
}

func TestScanRequestBody_AddressUnknownAllowed(t *testing.T) {
	sc := newAddressProtectionScanner(t)

	// Unknown address with unknown_action=allow — should pass clean.
	body := `{"to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1024 * 1024,
		Scanner:     sc,
	})
	if !result.Clean {
		t.Error("unknown address with allow action should be clean")
	}
}

func TestScanRequestBody_NoAddressProtection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	sc := scanner.New(cfg)
	defer sc.Close()

	// No address protection enabled — should not crash.
	body := `{"to": "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1024 * 1024,
		Scanner:     sc,
	})
	if !result.Clean {
		t.Error("no address protection: should be clean")
	}
}

func TestScanRequestBody_AddressWithAgentID(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = config.ActionBlock
	cfg.AddressProtection.UnknownAction = config.ActionAllow
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4
	// Agent-only allowlist, no global.
	eth := true
	f := false
	cfg.AddressProtection.Chains.ETH = &eth
	cfg.AddressProtection.Chains.BTC = &f
	cfg.AddressProtection.Chains.SOL = &f
	cfg.AddressProtection.Chains.BNB = &f
	cfg.Agents = map[string]config.AgentProfile{
		"trader": {
			AllowedAddresses: []string{
				"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e",
			},
		},
	}
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	sc := scanner.New(cfg)
	defer sc.Close()

	// Poisoned address with agent ID "trader" — agent's allowlist should be consulted.
	body := `{"to": "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    1024 * 1024,
		Scanner:     sc,
		AgentID:     "trader",
	})
	if result.Clean {
		t.Fatal("poisoned address should be caught with agent allowlist")
	}
	if len(result.AddressFindings) == 0 {
		t.Error("expected address findings with agent allowlist")
	}
}

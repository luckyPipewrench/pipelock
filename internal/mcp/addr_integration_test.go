// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestScanRequestAddressPoisoning(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil

	eth := true
	f := false
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = "block"
	cfg.AddressProtection.UnknownAction = "allow"
	cfg.AddressProtection.AllowedAddresses = []string{
		"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e",
	}
	cfg.AddressProtection.Chains.ETH = &eth
	cfg.AddressProtection.Chains.BTC = &f
	cfg.AddressProtection.Chains.SOL = &f
	cfg.AddressProtection.Chains.BNB = &f
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4

	sc := scanner.New(cfg)

	// Verify checker exists.
	if sc.AddressChecker() == nil {
		t.Fatal("AddressChecker is nil")
	}

	// Poisoned address: same prefix/suffix payload, different middle.
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer","arguments":{"to":"0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e"}}}`
	verdict := ScanRequest([]byte(line), sc, config.ActionBlock, config.ActionBlock)
	t.Logf("Clean: %v, AddressFindings: %d, DLP: %d, Inject: %d, Error: %q",
		verdict.Clean, len(verdict.AddressFindings), len(verdict.Matches), len(verdict.Inject), verdict.Error)

	if verdict.Clean {
		t.Error("poisoned address should set Clean=false")
	}
	if len(verdict.AddressFindings) == 0 {
		t.Error("should have address findings")
	}
}

func TestScanRequestAddressExactMatch(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil

	eth := true
	f := false
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = "block"
	cfg.AddressProtection.UnknownAction = "allow"
	cfg.AddressProtection.AllowedAddresses = []string{
		"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e",
	}
	cfg.AddressProtection.Chains.ETH = &eth
	cfg.AddressProtection.Chains.BTC = &f
	cfg.AddressProtection.Chains.SOL = &f
	cfg.AddressProtection.Chains.BNB = &f
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4

	sc := scanner.New(cfg)

	// Exact allowlisted address.
	line := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"transfer","arguments":{"to":"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}}}`
	verdict := ScanRequest([]byte(line), sc, config.ActionBlock, config.ActionBlock)

	if !verdict.Clean {
		t.Error("exact allowlisted address should pass clean")
	}
}

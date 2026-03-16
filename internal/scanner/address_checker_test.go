// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAddressCheckerNilWhenDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := New(cfg)
	defer sc.Close()

	if sc.AddressChecker() != nil {
		t.Error("AddressChecker should be nil when address_protection is disabled")
	}
}

func TestAddressCheckerConstructed(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = config.ActionBlock
	cfg.AddressProtection.UnknownAction = config.ActionAllow
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4
	eth := true
	cfg.AddressProtection.Chains.ETH = &eth

	sc := New(cfg)
	defer sc.Close()

	if sc.AddressChecker() == nil {
		t.Error("AddressChecker should be non-nil when address_protection is enabled")
	}
}

func TestAddressCheckerWithAgentAddresses(t *testing.T) {
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
	cfg.AddressProtection.Chains.ETH = &eth
	cfg.Agents = map[string]config.AgentProfile{
		"trader": {
			AllowedAddresses: []string{
				"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			},
		},
	}

	sc := New(cfg)
	defer sc.Close()

	checker := sc.AddressChecker()
	if checker == nil {
		t.Fatal("AddressChecker should be non-nil")
	}

	// Global address should be found.
	result := checker.CheckText("0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(result.Hits) != 1 {
		t.Errorf("expected 1 hit for global address, got %d", len(result.Hits))
	}
}

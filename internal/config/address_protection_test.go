// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestApplyDefaults_AddressProtection(t *testing.T) {
	cfg := Defaults()
	cfg.AddressProtection.Enabled = true
	// Leave Action/UnknownAction/Similarity empty — ApplyDefaults should fill them.
	cfg.ApplyDefaults()

	if cfg.AddressProtection.Action != ActionBlock {
		t.Errorf("Action: got %q, want %q", cfg.AddressProtection.Action, ActionBlock)
	}
	if cfg.AddressProtection.UnknownAction != ActionAllow {
		t.Errorf("UnknownAction: got %q, want %q", cfg.AddressProtection.UnknownAction, ActionAllow)
	}
	if cfg.AddressProtection.Similarity.PrefixLength != 4 {
		t.Errorf("PrefixLength: got %d, want 4", cfg.AddressProtection.Similarity.PrefixLength)
	}
	if cfg.AddressProtection.Similarity.SuffixLength != 4 {
		t.Errorf("SuffixLength: got %d, want 4", cfg.AddressProtection.Similarity.SuffixLength)
	}
}

func TestApplyDefaults_AddressProtectionDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.AddressProtection.Enabled = false
	cfg.ApplyDefaults()

	// When disabled, defaults should NOT be applied (fields stay zero).
	if cfg.AddressProtection.Action != "" {
		t.Errorf("disabled: Action should be empty, got %q", cfg.AddressProtection.Action)
	}
}

func TestValidate_AddressProtectionValidActions(t *testing.T) {
	for _, action := range []string{ActionBlock, ActionWarn} {
		cfg := Defaults()
		cfg.AddressProtection.Enabled = true
		cfg.AddressProtection.Action = action
		cfg.AddressProtection.UnknownAction = ActionAllow
		cfg.AddressProtection.Similarity.PrefixLength = 4
		cfg.AddressProtection.Similarity.SuffixLength = 4
		eth := true
		cfg.AddressProtection.Chains.ETH = &eth

		if err := cfg.Validate(); err != nil {
			t.Errorf("action %q should be valid, got: %v", action, err)
		}
	}
}

func TestValidate_AddressProtectionInvalidAction(t *testing.T) {
	cfg := Defaults()
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = ActionAsk // invalid for address protection
	cfg.AddressProtection.UnknownAction = ActionAllow
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4
	eth := true
	cfg.AddressProtection.Chains.ETH = &eth

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for action=ask")
	}
	if !strings.Contains(err.Error(), "address_protection.action") {
		t.Errorf("error should mention address_protection.action: %v", err)
	}
}

func TestValidate_AddressProtectionInvalidUnknownAction(t *testing.T) {
	cfg := Defaults()
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = ActionBlock
	cfg.AddressProtection.UnknownAction = ActionStrip // invalid
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4
	eth := true
	cfg.AddressProtection.Chains.ETH = &eth

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for unknown_action=strip")
	}
	if !strings.Contains(err.Error(), "unknown_action") {
		t.Errorf("error should mention unknown_action: %v", err)
	}
}

func TestValidate_AddressProtectionNoChains(t *testing.T) {
	cfg := Defaults()
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = ActionBlock
	cfg.AddressProtection.UnknownAction = ActionAllow
	cfg.AddressProtection.Similarity.PrefixLength = 4
	cfg.AddressProtection.Similarity.SuffixLength = 4
	f := false
	cfg.AddressProtection.Chains.ETH = &f
	cfg.AddressProtection.Chains.BTC = &f
	cfg.AddressProtection.Chains.SOL = &f
	cfg.AddressProtection.Chains.BNB = &f

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error when no chains enabled")
	}
	if !strings.Contains(err.Error(), "chain") {
		t.Errorf("error should mention chains: %v", err)
	}
}

func TestValidate_AddressProtectionBadSimilarity(t *testing.T) {
	cfg := Defaults()
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = ActionBlock
	cfg.AddressProtection.UnknownAction = ActionAllow
	cfg.AddressProtection.Similarity.PrefixLength = 0 // invalid
	cfg.AddressProtection.Similarity.SuffixLength = 4
	eth := true
	cfg.AddressProtection.Chains.ETH = &eth

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for zero prefix length")
	}
}

func TestValidateReload_AddressProtectionDisabled(t *testing.T) {
	old := Defaults()
	old.AddressProtection.Enabled = true

	updated := Defaults()
	updated.AddressProtection.Enabled = false

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if strings.Contains(w.Field, "address_protection") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected reload warning when address protection disabled")
	}
}

func TestValidate_AddressProtectionDisabledSkipsValidation(t *testing.T) {
	cfg := Defaults()
	cfg.AddressProtection.Enabled = false
	cfg.AddressProtection.Action = "garbage" // should be ignored when disabled

	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config should not validate address_protection fields: %v", err)
	}
}

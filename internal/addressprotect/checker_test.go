// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const testActionWarn = "warn"

func boolPtr(b bool) *bool { return &b }

func enabledConfig() *config.AddressProtection {
	return &config.AddressProtection{
		Enabled:       true,
		Action:        "block",
		UnknownAction: "allow",
		Chains: config.AddressChains{
			ETH: boolPtr(true),
			BTC: boolPtr(true),
			SOL: boolPtr(false),
			BNB: boolPtr(false),
		},
		Similarity: config.SimilarityConfig{
			PrefixLength: 4,
			SuffixLength: 4,
		},
	}
}

func TestNewCheckerDisabled(t *testing.T) {
	cfg := &config.AddressProtection{Enabled: false}
	c := NewChecker(cfg, nil)
	if c != nil {
		t.Error("disabled config should return nil Checker")
	}
}

func TestNewCheckerNilConfig(t *testing.T) {
	c := NewChecker(nil, nil)
	if c != nil {
		t.Error("nil config should return nil Checker")
	}
}

func TestCheckTextNilChecker(t *testing.T) {
	var c *Checker
	result := c.CheckText("0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(result.Hits) != 0 {
		t.Error("nil checker should return empty result")
	}
}

func TestCheckTextNoAddressesInText(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	c := NewChecker(cfg, nil)

	result := c.CheckText("hello world no addresses here", "")
	if len(result.Hits) != 0 {
		t.Error("no addresses in text should return empty Hits")
	}
	if len(result.Findings) != 0 {
		t.Error("no addresses in text should return empty Findings")
	}
}

func TestCheckTextInertWithoutAllowlist(t *testing.T) {
	cfg := enabledConfig()
	// No allowed addresses configured.
	c := NewChecker(cfg, nil)

	result := c.CheckText("send to 0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(result.Hits) != 1 {
		t.Errorf("should detect 1 hit, got %d", len(result.Hits))
	}
	if len(result.Findings) != 0 {
		t.Error("inert (no allowlist): should produce no findings")
	}
}

func TestCheckTextExactMatch(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	c := NewChecker(cfg, nil)

	result := c.CheckText("send to 0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(result.Hits) != 1 {
		t.Errorf("should detect 1 hit, got %d", len(result.Hits))
	}
	if len(result.Findings) != 0 {
		t.Error("exact match should produce no findings")
	}
}

func TestCheckTextLookalike(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	c := NewChecker(cfg, nil)

	// Poisoned address: same first 4 + last 4 hex payload, different middle.
	// Poisoned: 0x + 742d (4) + 30 a's + f2bd3e (6) = 42 chars total.
	result := c.CheckText("send to 0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e", "")
	if len(result.Hits) != 1 {
		t.Errorf("should detect 1 hit, got %d", len(result.Hits))
	}
	if len(result.Findings) != 1 {
		t.Fatalf("should produce 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Verdict != VerdictLookalike {
		t.Errorf("verdict: got %d, want VerdictLookalike", result.Findings[0].Verdict)
	}
}

func TestCheckTextUnknownAllow(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	cfg.UnknownAction = "allow"
	c := NewChecker(cfg, nil)

	// Completely different address — unknown.
	result := c.CheckText("send to 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "")
	if len(result.Hits) != 1 {
		t.Errorf("should detect 1 hit, got %d", len(result.Hits))
	}
	if len(result.Findings) != 0 {
		t.Error("unknown with allow action should produce no findings")
	}
}

func TestCheckTextUnknownWarn(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	cfg.UnknownAction = testActionWarn
	c := NewChecker(cfg, nil)

	result := c.CheckText("send to 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "")
	if len(result.Findings) != 1 {
		t.Fatalf("unknown with warn action should produce 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Verdict != VerdictUnknown {
		t.Errorf("verdict: got %d, want VerdictUnknown", result.Findings[0].Verdict)
	}
}

func TestCheckTextAgentAllowlist(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	agentAddrs := map[string][]string{
		"trader": {"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
	}
	c := NewChecker(cfg, agentAddrs)

	// Agent "trader": global + agent addresses are merged.
	// The agent's address is an exact match → no finding.
	result := c.CheckText("send to 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "trader")
	if len(result.Findings) != 0 {
		t.Error("agent allowlist exact match should produce no findings")
	}

	// Without agent ID: only global → unknown (allow by default).
	result = c.CheckText("send to 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "")
	if len(result.Findings) != 0 {
		t.Error("unknown with allow action should produce no findings")
	}
}

func TestCheckTextAgentIDNotFound(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	agentAddrs := map[string][]string{
		"trader": {"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
	}
	c := NewChecker(cfg, agentAddrs)

	// Agent "unknown-agent" not in config → falls back to global only.
	result := c.CheckText("send to 0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "unknown-agent")
	if len(result.Findings) != 0 {
		t.Error("exact global match for unknown agent should produce no findings")
	}
}

func TestCheckTextZeroWidthChars(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	c := NewChecker(cfg, nil)

	// Zero-width chars injected into the address should be stripped.
	result := c.CheckText("send to 0x742d\u200B35cc6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(result.Hits) != 1 {
		t.Errorf("zero-width chars should be stripped, got %d hits", len(result.Hits))
	}
	if len(result.Findings) != 0 {
		t.Error("exact match after stripping should produce no findings")
	}
}

func TestCheckTextURLEncoded(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	c := NewChecker(cfg, nil)

	// URL-encoded address should be decoded and matched.
	result := c.CheckText("addr=0x742d35%63c6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(result.Hits) != 1 {
		t.Errorf("URL-encoded address should be decoded, got %d hits", len(result.Hits))
	}
}

func TestCheckTextBTCBech32(t *testing.T) {
	cfg := enabledConfig()
	cfg.AllowedAddresses = []string{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}
	c := NewChecker(cfg, nil)

	// Exact match.
	result := c.CheckText("pay bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "")
	if len(result.Hits) != 1 {
		t.Errorf("should detect 1 BTC hit, got %d", len(result.Hits))
	}
	if len(result.Findings) != 0 {
		t.Error("exact BTC match should produce no findings")
	}
}

func TestCheckerHotReload(t *testing.T) {
	cfg1 := enabledConfig()
	cfg1.AllowedAddresses = []string{"0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"}
	c1 := NewChecker(cfg1, nil)

	// Address matches allowlist A.
	r1 := c1.CheckText("send to 0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(r1.Findings) != 0 {
		t.Error("checker 1: exact match should pass")
	}

	// Build new checker with different allowlist (simulates hot reload).
	cfg2 := enabledConfig()
	cfg2.AllowedAddresses = []string{"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	c2 := NewChecker(cfg2, nil)

	// Old address is now unknown with c2.
	r2 := c2.CheckText("send to 0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "")
	if len(r2.Hits) != 1 {
		t.Error("checker 2: should still detect the address")
	}
	// unknown_action: allow → no findings even though not in new allowlist.
	if len(r2.Findings) != 0 {
		t.Error("checker 2: unknown with allow action should produce no findings")
	}
}

func TestCheckerAction(t *testing.T) {
	cfg := enabledConfig()
	cfg.Action = "warn"
	c := NewChecker(cfg, nil)
	if c.Action() != "warn" {
		t.Errorf("Action: got %q, want %q", c.Action(), "warn")
	}

	var nilChecker *Checker
	if nilChecker.Action() != "" {
		t.Error("nil checker Action should return empty string")
	}
}

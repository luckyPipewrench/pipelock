// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestETHNormalizeAllPaths(t *testing.T) {
	t.Parallel()

	v := ethValidator{}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase passthrough", "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"},
		{"uppercase lowered", "0X742D35CC6634C0532925A3B844BC9E7595F2BD3E", "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"},
		{"mixed case lowered", "0x742D35cC6634c0532925A3b844Bc9E7595f2bD3E", "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"},
		{"empty string", "", ""},
		{"short string", "0x", "0x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := v.Normalize(tt.input)
			if got != tt.want {
				t.Errorf("ETH Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBTCNormalizeAllPaths(t *testing.T) {
	t.Parallel()

	v := btcValidator{}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"bech32 lowercase passthrough", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{"bech32 uppercase lowered", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{"legacy P2PKH preserved", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{"legacy P2SH preserved", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := v.Normalize(tt.input)
			if got != tt.want {
				t.Errorf("BTC Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSOLNormalizeAllPaths(t *testing.T) {
	t.Parallel()

	v := solValidator{}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"identity", "11111111111111111111111111111111", "11111111111111111111111111111111"},
		{"empty string", "", ""},
		{"arbitrary base58", "So11111111111111111111111111111112", "So11111111111111111111111111111112"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := v.Normalize(tt.input)
			if got != tt.want {
				t.Errorf("SOL Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBNBNormalizeAllPaths(t *testing.T) {
	t.Parallel()

	v := bnbValidator{}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase passthrough", "bnb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq38lnxn", "bnb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq38lnxn"},
		{"uppercase lowered", "BNB1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ38LNXN", "bnb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq38lnxn"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := v.Normalize(tt.input)
			if got != tt.want {
				t.Errorf("BNB Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestETHCompareKeyEdgeCases(t *testing.T) {
	t.Parallel()

	v := ethValidator{}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal strips 0x", "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", "742d35cc6634c0532925a3b844bc9e7595f2bd3e"},
		{"short returns as-is", "0x", "0x"},
		{"single char returns as-is", "a", "a"},
		{"empty string returns as-is", "", ""},
		{"two chars returns as-is", "ab", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := v.CompareKey(tt.input)
			if got != tt.want {
				t.Errorf("ETH CompareKey(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBTCCompareKeyEdgeCases(t *testing.T) {
	t.Parallel()

	v := btcValidator{}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"bech32 strips bc1", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{"short bc1 returns as-is", "bc1", "bc1"},
		{"legacy P2PKH full string", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{"empty string", "", ""},
		{"non-bc1 prefix", "ab1qtest", "ab1qtest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := v.CompareKey(tt.input)
			if got != tt.want {
				t.Errorf("BTC CompareKey(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBNBCompareKeyEdgeCases(t *testing.T) {
	t.Parallel()

	v := bnbValidator{}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal strips bnb1", "bnb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq38lnxn", "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq38lnxn"},
		{"short bnb1 returns as-is", "bnb1", "bnb1"},
		{"three chars returns as-is", "bnb", "bnb"},
		{"empty string", "", ""},
		{"non-bnb prefix", "eth1qqqqq", "eth1qqqqq"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := v.CompareKey(tt.input)
			if got != tt.want {
				t.Errorf("BNB CompareKey(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestChainEnabled(t *testing.T) {
	t.Parallel()

	trueVal := true
	falseVal := false

	tests := []struct {
		name      string
		toggle    *bool
		defaultOn bool
		want      bool
	}{
		{"nil with default true", nil, true, true},
		{"nil with default false", nil, false, false},
		{"explicit true with default true", &trueVal, true, true},
		{"explicit true with default false", &trueVal, false, true},
		{"explicit false with default true", &falseVal, true, false},
		{"explicit false with default false", &falseVal, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := chainEnabled(tt.toggle, tt.defaultOn)
			if got != tt.want {
				t.Errorf("chainEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		slice []string
		s     string
		want  int
	}{
		{"empty slice adds element", nil, "a", 1},
		{"new element appended", []string{"a", "b"}, "c", 3},
		{"duplicate not appended", []string{"a", "b"}, "a", 2},
		{"duplicate at end", []string{"a", "b"}, "b", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := appendUnique(tt.slice, tt.s)
			if len(got) != tt.want {
				t.Errorf("appendUnique() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestNewCheckerDefaultSimilarity(t *testing.T) {
	t.Parallel()

	cfg := &config.AddressProtection{
		Enabled:       true,
		Action:        config.ActionBlock,
		UnknownAction: config.ActionAllow,
		Similarity: config.SimilarityConfig{
			PrefixLength: 0,  // should default to 4
			SuffixLength: -1, // should default to 4
		},
		Chains: config.AddressChains{
			ETH: boolPtr(true),
			BTC: boolPtr(false),
			SOL: boolPtr(false),
			BNB: boolPtr(false),
		},
	}
	c := NewChecker(cfg, nil)
	if c == nil {
		t.Fatal("NewChecker returned nil for enabled config")
	}
	if c.prefixLen != 4 {
		t.Errorf("prefixLen = %d, want 4 (default)", c.prefixLen)
	}
	if c.suffixLen != 4 {
		t.Errorf("suffixLen = %d, want 4 (default)", c.suffixLen)
	}
}

func TestNewCheckerSOLDefaultDisabled(t *testing.T) {
	t.Parallel()

	// SOL defaults to disabled (high FP risk); BNB defaults to enabled.
	cfg := &config.AddressProtection{
		Enabled:       true,
		Action:        config.ActionBlock,
		UnknownAction: config.ActionAllow,
		Chains:        config.AddressChains{}, // all nil — use defaults
		Similarity:    config.SimilarityConfig{PrefixLength: 4, SuffixLength: 4},
	}
	c := NewChecker(cfg, nil)
	if c == nil {
		t.Fatal("NewChecker returned nil for enabled config")
	}

	// ETH default on, BTC default on, SOL default off, BNB default on.
	if _, ok := c.validators[ChainETH]; !ok {
		t.Error("ETH should be enabled by default")
	}
	if _, ok := c.validators[ChainBTC]; !ok {
		t.Error("BTC should be enabled by default")
	}
	if _, ok := c.validators[ChainSOL]; ok {
		t.Error("SOL should be disabled by default")
	}
	if _, ok := c.validators[ChainBNB]; !ok {
		t.Error("BNB should be enabled by default")
	}
}

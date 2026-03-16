// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const testAllowedETH = "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"

func TestIterativeURLDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no encoding", "hello", "hello"},
		{"single encode", "hello%20world", "hello world"},
		{"double encode", "hello%2520world", "hello world"},
		{"invalid percent", "hello%zzworld", "hello%zzworld"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := iterativeURLDecode(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTryBase64Decode(t *testing.T) {
	// Valid base64 that decodes to UTF-8.
	addr := testAllowedETH
	encoded := base64.StdEncoding.EncodeToString([]byte(addr))
	decoded, ok := tryBase64Decode(encoded)
	if !ok {
		t.Fatal("expected successful base64 decode")
	}
	if decoded != addr {
		t.Errorf("got %q, want %q", decoded, addr)
	}

	// Invalid base64.
	_, ok = tryBase64Decode("not-valid-base64!!!")
	if ok {
		t.Error("expected failed decode for invalid base64")
	}

	// Empty string.
	_, ok = tryBase64Decode("")
	if ok {
		t.Error("expected failed decode for empty string")
	}
}

func TestTryHexDecode(t *testing.T) {
	// Valid hex that decodes to UTF-8.
	addr := "0x742d35cc"
	encoded := hex.EncodeToString([]byte(addr))
	decoded, ok := tryHexDecode(encoded)
	if !ok {
		t.Fatal("expected successful hex decode")
	}
	if decoded != addr {
		t.Errorf("got %q, want %q", decoded, addr)
	}

	// Invalid hex.
	_, ok = tryHexDecode("zzzz")
	if ok {
		t.Error("expected failed decode for invalid hex")
	}

	// Odd length.
	_, ok = tryHexDecode("abc")
	if ok {
		t.Error("expected failed decode for odd-length hex")
	}
}

func TestChainLabel(t *testing.T) {
	tests := []struct {
		chain string
		want  string
	}{
		{ChainETH, "ETH"},
		{ChainBTC, "BTC"},
		{ChainSOL, "SOL"},
		{ChainBNB, "BNB"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.chain, func(t *testing.T) {
			got := chainLabel(tt.chain)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// addrProtectCfg returns a reusable address protection config for coverage tests.
func addrProtectCfg() *config.AddressProtection {
	return &config.AddressProtection{
		Enabled:       true,
		Action:        config.ActionBlock,
		UnknownAction: config.ActionAllow,
		AllowedAddresses: []string{
			testAllowedETH,
		},
		Chains: config.AddressChains{
			ETH: boolPtr(true),
			BTC: boolPtr(false),
			SOL: boolPtr(false),
			BNB: boolPtr(false),
		},
		Similarity: config.SimilarityConfig{
			PrefixLength: 4,
			SuffixLength: 4,
		},
	}
}

const testPoisonedETH = "0x742daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf2bd3e"

func TestCheckTextBase64EncodedAddress(t *testing.T) {
	c := NewChecker(addrProtectCfg(), nil)

	encoded := base64.StdEncoding.EncodeToString([]byte(testPoisonedETH))
	result := c.CheckText(encoded, "")
	if len(result.Hits) == 0 {
		t.Fatal("should detect address in base64-encoded text")
	}
	if result.Hits[0].Chain != ChainETH {
		t.Errorf("chain: got %q, want %q", result.Hits[0].Chain, ChainETH)
	}
	if len(result.Findings) == 0 {
		t.Fatal("should produce poisoning finding")
	}
	if result.Findings[0].Verdict != VerdictLookalike {
		t.Errorf("verdict: got %d, want VerdictLookalike", result.Findings[0].Verdict)
	}
	if result.Findings[0].Action != config.ActionBlock {
		t.Errorf("action: got %q, want %q", result.Findings[0].Action, config.ActionBlock)
	}
}

func TestCheckTextHexEncodedAddress(t *testing.T) {
	c := NewChecker(addrProtectCfg(), nil)

	encoded := hex.EncodeToString([]byte(testPoisonedETH))
	result := c.CheckText(encoded, "")
	if len(result.Hits) == 0 {
		t.Fatal("should detect address in hex-encoded text")
	}
	if result.Hits[0].Chain != ChainETH {
		t.Errorf("chain: got %q, want %q", result.Hits[0].Chain, ChainETH)
	}
}

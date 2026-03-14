// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"strings"
	"testing"
)

// ---------- ETH ----------

func TestETHDetect(t *testing.T) {
	v := ethValidator{}
	tests := []struct {
		name  string
		text  string
		count int
	}{
		{"lowercase", "send to 0x742d35cc6634c0532925a3b844bc9e7595f2bd3e please", 1},
		{"uppercase", "addr: 0x742D35CC6634C0532925A3B844BC9E7595F2BD3E", 1},
		{"mixed case", "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3E", 1},
		{"two addresses", "from 0x742d35cc6634c0532925a3b844bc9e7595f2bd3e to 0xdead35cc6634c0532925a3b844bc9e7595f2beef", 2},
		{"too short 39 hex", "0x742d35cc6634c0532925a3b844bc9e7595f2bd3", 0},
		{"too long 41 hex", "0x742d35cc6634c0532925a3b844bc9e7595f2bd3ea", 0},
		{"non-hex chars", "0x742d35cc6634c0532925a3b844bc9e7595f2bGGG", 0},
		{"no match", "hello world", 0},
		{"embedded no boundary", "abc0x742d35cc6634c0532925a3b844bc9e7595f2bd3e", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := v.Detect(tt.text)
			if len(matches) != tt.count {
				t.Errorf("got %d matches, want %d", len(matches), tt.count)
			}
		})
	}
}

func TestETHValidate(t *testing.T) {
	v := ethValidator{}
	if !v.Validate("0x742d35cc6634c0532925a3b844bc9e7595f2bd3e") {
		t.Error("should validate lowercase ETH address")
	}
	if !v.Validate("0x742D35CC6634C0532925A3B844BC9E7595F2BD3E") {
		t.Error("should validate uppercase ETH address")
	}
	if !v.Validate("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3E") {
		t.Error("should validate mixed-case ETH address")
	}
}

func TestETHNormalize(t *testing.T) {
	v := ethValidator{}
	norm := v.Normalize("0x742D35CC6634C0532925A3B844BC9E7595F2BD3E")
	want := "0x742d35cc6634c0532925a3b844bc9e7595f2bd3e"
	if norm != want {
		t.Errorf("got %q, want %q", norm, want)
	}
}

func TestETHCompareKey(t *testing.T) {
	v := ethValidator{}
	key := v.CompareKey("0x742d35cc6634c0532925a3b844bc9e7595f2bd3e")
	if strings.HasPrefix(key, "0x") {
		t.Error("CompareKey should strip 0x prefix")
	}
	if len(key) != 40 {
		t.Errorf("CompareKey length: got %d, want 40", len(key))
	}
}

// ---------- BTC ----------

func TestBTCDetect(t *testing.T) {
	v := btcValidator{}
	tests := []struct {
		name  string
		text  string
		count int
	}{
		{"P2PKH genesis", "addr: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1},
		{"P2SH", "pay 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 1},
		{"bech32 v0 P2WPKH", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1},
		{"no match", "hello world", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := v.Detect(tt.text)
			if len(matches) != tt.count {
				t.Errorf("got %d matches, want %d", len(matches), tt.count)
			}
		})
	}
}

func TestBTCValidate(t *testing.T) {
	v := btcValidator{}
	tests := []struct {
		name  string
		addr  string
		valid bool
	}{
		{"P2PKH genesis", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", true},
		{"P2SH", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", true},
		{"bech32 v0", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", true},
		{"P2PKH bad checksum", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", false},
		{"P2PKH wrong version", "2A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", false},
		{"bech32 bad checksum", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.Validate(tt.addr)
			if got != tt.valid {
				t.Errorf("Validate(%q) = %v, want %v", tt.addr, got, tt.valid)
			}
		})
	}
}

func TestBTCNormalize(t *testing.T) {
	v := btcValidator{}
	// Bech32 normalizes to lowercase.
	norm := v.Normalize("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
	if norm != "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" {
		t.Errorf("bech32 normalize: got %q", norm)
	}
	// Legacy is case-sensitive — returned as-is.
	norm = v.Normalize("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	if norm != "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" {
		t.Errorf("legacy normalize: got %q", norm)
	}
}

func TestBTCCompareKey(t *testing.T) {
	v := btcValidator{}
	// Bech32: strip "bc1", keep witness version char.
	key := v.CompareKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
	if !strings.HasPrefix(key, "q") {
		t.Errorf("bech32 CompareKey should start with witness version 'q', got %q", key[:1])
	}
	if strings.HasPrefix(key, "bc1") {
		t.Error("bech32 CompareKey should strip bc1 prefix")
	}
	// Legacy: full string.
	key = v.CompareKey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	if key != "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" {
		t.Errorf("legacy CompareKey should be full string, got %q", key)
	}
}

// ---------- SOL ----------

func TestSOLDetect(t *testing.T) {
	v := solValidator{}
	tests := []struct {
		name  string
		text  string
		count int
	}{
		// System Program address (all 1s = 32 zero bytes in base58).
		{"system program", "11111111111111111111111111111111", 1},
		{"too short", "1111111111111111111111111111111", 0}, // 31 chars
		{"no match", "hello world", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := v.Detect(tt.text)
			if len(matches) != tt.count {
				t.Errorf("got %d matches, want %d", len(matches), tt.count)
			}
		})
	}
}

func TestSOLValidate(t *testing.T) {
	v := solValidator{}
	tests := []struct {
		name  string
		addr  string
		valid bool
	}{
		// System Program: 32 '1's = 32 zero bytes.
		{"system program", "11111111111111111111111111111111", true},
		// Invalid base58 char.
		{"invalid char", "1111111111111111111111111111111O", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.Validate(tt.addr)
			if got != tt.valid {
				t.Errorf("Validate(%q) = %v, want %v", tt.addr, got, tt.valid)
			}
		})
	}
}

func TestSOLNormalize(t *testing.T) {
	v := solValidator{}
	addr := "11111111111111111111111111111111"
	norm := v.Normalize(addr)
	if norm != addr {
		t.Errorf("SOL normalize should be identity, got %q", norm)
	}
}

func TestSOLCompareKey(t *testing.T) {
	v := solValidator{}
	addr := "11111111111111111111111111111111"
	key := v.CompareKey(addr)
	if key != addr {
		t.Error("SOL CompareKey should be full string")
	}
}

// ---------- BNB ----------

func TestBNBDetect(t *testing.T) {
	v := bnbValidator{}
	tests := []struct {
		name  string
		text  string
		count int
	}{
		{"no match", "hello world", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := v.Detect(tt.text)
			if len(matches) != tt.count {
				t.Errorf("got %d matches, want %d", len(matches), tt.count)
			}
		})
	}
}

func TestBNBCompareKey(t *testing.T) {
	v := bnbValidator{}
	// CompareKey strips "bnb1" prefix.
	norm := "bnb1" + strings.Repeat("q", 38)
	key := v.CompareKey(norm)
	if strings.HasPrefix(key, "bnb1") {
		t.Error("BNB CompareKey should strip bnb1 prefix")
	}
	if len(key) != 38 {
		t.Errorf("BNB CompareKey length: got %d, want 38", len(key))
	}
}

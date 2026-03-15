// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"errors"
	"testing"
)

func TestBech32DecodeValid(t *testing.T) {
	// BIP-173 valid bech32 test vectors (verified against reference implementation).
	tests := []struct {
		name    string
		input   string
		wantHRP string
		wantVer int
		wantLen int // expected data length (5-bit values, excluding checksum)
	}{
		{
			name:    "BTC SegWit v0 P2WPKH mainnet",
			input:   "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			wantHRP: "bc",
			wantVer: bech32Version,
			wantLen: 33, // witness version (1) + 32 five-bit groups
		},
		{
			name:    "BIP-173 test string",
			input:   "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
			wantHRP: "abcdef",
			wantVer: bech32Version,
			wantLen: 32,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hrp, data, ver, err := bech32Decode(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hrp != tt.wantHRP {
				t.Errorf("HRP: got %q, want %q", hrp, tt.wantHRP)
			}
			if ver != tt.wantVer {
				t.Errorf("version: got %d, want %d", ver, tt.wantVer)
			}
			if len(data) != tt.wantLen {
				t.Errorf("data length: got %d, want %d", len(data), tt.wantLen)
			}
		})
	}
}

func TestBech32mDecodeValid(t *testing.T) {
	// BIP-350 valid bech32m test vectors.
	tests := []struct {
		name    string
		input   string
		wantHRP string
		wantLen int
	}{
		{
			name:    "BIP-350 minimal",
			input:   "a1lqfn3a",
			wantHRP: "a",
			wantLen: 0, // just checksum, no data beyond it
		},
		{
			name:    "BIP-350 abcdef",
			input:   "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
			wantHRP: "abcdef",
			wantLen: 32,
		},
		{
			name:    "BTC Taproot v1 testnet",
			input:   "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
			wantHRP: "tb",
			wantLen: 53, // witness version (1) + 52 five-bit groups (32 bytes)
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hrp, data, ver, err := bech32Decode(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hrp != tt.wantHRP {
				t.Errorf("HRP: got %q, want %q", hrp, tt.wantHRP)
			}
			if ver != bech32mVersion {
				t.Errorf("version: got %d, want %d", ver, bech32mVersion)
			}
			if len(data) != tt.wantLen {
				t.Errorf("data length: got %d, want %d", len(data), tt.wantLen)
			}
		})
	}
}

func TestBech32DecodeInvalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "mixed case",
			input:   "bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			wantErr: errBech32MixedCase,
		},
		{
			name:    "bad checksum",
			input:   "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
			wantErr: errBech32Checksum,
		},
		{
			name:    "too short",
			input:   "bc1qqqq",
			wantErr: errBech32InvalidLength,
		},
		{
			name:    "no separator",
			input:   "abcdefghijklmn",
			wantErr: errBech32NoSeparator,
		},
		{
			name:    "separator at start",
			input:   "1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql6aptf",
			wantErr: errBech32NoSeparator,
		},
		{
			name:    "data too short for checksum",
			input:   "bc1qqqq",
			wantErr: errBech32InvalidLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := bech32Decode(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestBech32DecodeUpperCase(t *testing.T) {
	// BIP-173: all-uppercase is valid (gets lowercased internally).
	hrp, _, ver, err := bech32Decode("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hrp != "bc" {
		t.Errorf("HRP: got %q, want %q", hrp, "bc")
	}
	if ver != bech32Version {
		t.Errorf("version: got %d, want %d", ver, bech32Version)
	}
}

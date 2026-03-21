// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestBase58Decode(t *testing.T) {
	// Bitcoin wiki standard test vectors + additional cases.
	tests := []struct {
		name    string
		input   string
		wantHex string
	}{
		{"empty string", "", ""},
		{"single zero byte", "1", "00"},
		{"three zero bytes", "111", "000000"},
		{"hello world", "StV1DL6CwTryKyV", "68656c6c6f20776f726c64"},
		{"single non-zero", "2", "01"},
		{"leading ones mixed", "11StV1DL6CwTryKyV", "000068656c6c6f20776f726c64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base58Decode(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.wantHex {
				t.Errorf("got %s, want %s", gotHex, tt.wantHex)
			}
		})
	}
}

func TestBase58DecodeInvalidChars(t *testing.T) {
	invalid := []string{
		"0abc",     // '0' not in base58 alphabet
		"Odef",     // 'O' not in base58 alphabet
		"Ighi",     // 'I' not in base58 alphabet
		"test+abc", // '+' not in base58 alphabet
		"abc def",  // space not in base58 alphabet
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, err := base58Decode(s)
			if !errors.Is(err, errInvalidBase58Char) {
				t.Errorf("got %v, want errInvalidBase58Char", err)
			}
		})
	}
}

func TestBase58CheckDecode(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantVersion byte
		wantPayLen  int
	}{
		{
			// Genesis coinbase address (P2PKH, version 0x00).
			name:        "BTC P2PKH genesis",
			address:     "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			wantVersion: 0x00,
			wantPayLen:  20, // 20-byte pubkey hash
		},
		{
			// P2SH address (version 0x05).
			name:        "BTC P2SH",
			address:     "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
			wantVersion: 0x05,
			wantPayLen:  20,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, version, err := Base58CheckDecode(tt.address)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if version != tt.wantVersion {
				t.Errorf("version: got 0x%02x, want 0x%02x", version, tt.wantVersion)
			}
			if len(payload) != tt.wantPayLen {
				t.Errorf("payload length: got %d, want %d", len(payload), tt.wantPayLen)
			}
		})
	}
}

func TestBase58CheckDecodeInvalidChecksum(t *testing.T) {
	// Corrupt the last character of a valid P2PKH address.
	_, _, err := Base58CheckDecode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
	if !errors.Is(err, errBase58Checksum) {
		t.Errorf("got %v, want errBase58Checksum", err)
	}
}

func TestBase58CheckDecodeTooShort(t *testing.T) {
	// A string that decodes to fewer than 5 bytes (1 version + 4 checksum).
	_, _, err := Base58CheckDecode("1")
	if !errors.Is(err, errBase58TooShort) {
		t.Errorf("got %v, want errBase58TooShort", err)
	}
}

func TestBase58CheckDecodeInvalidChars(t *testing.T) {
	_, _, err := Base58CheckDecode("0InvalidAddress")
	if !errors.Is(err, errInvalidBase58Char) {
		t.Errorf("got %v, want errInvalidBase58Char", err)
	}
}

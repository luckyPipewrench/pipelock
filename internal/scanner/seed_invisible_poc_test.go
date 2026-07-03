// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

// TestScanTextForDLP_SeedZeroWidthSeparator probes whether a BIP-39 seed phrase
// whose inter-word spaces are replaced with ZERO-WIDTH (stripped, not space-like)
// separators still gets detected. The existing seed-evasion parity test only
// covers SPACE-LIKE separators (NBSP, en-dash, U+2028) which survive as word
// boundaries; zero-width chars are removed by StripZeroWidth, merging the words.
func TestScanTextForDLP_SeedZeroWidthSeparator(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	s := New(cfg)

	for _, tc := range []struct {
		name string
		sep  rune
	}{
		{"U+200B", 0x200B},
		{"U+1160", 0x1160},
		{"U+3164", 0x3164},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := strings.ReplaceAll(testSeedPhrase12, " ", string(tc.sep))
			r := s.ScanTextForDLP(context.Background(), payload)
			if r.Clean {
				t.Errorf("zero-width-separated (%s) seed phrase NOT detected via ScanTextForDLP: clean=true (want blocked)", tc.name)
			}
		})
	}
}

func TestScanTextForDLP_EncodedSeedZeroWidthSeparator(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	s := New(cfg)

	zw := string(rune(0x200B))
	seed := strings.ReplaceAll(testSeedPhrase12, " ", zw)
	for _, tc := range []struct {
		name        string
		payload     string
		wantEncoded string
	}{
		{"url", url.QueryEscape(seed), "url"},
		{"base64", base64.StdEncoding.EncodeToString([]byte(seed)), "base64"},
		{"hex", hex.EncodeToString([]byte(seed)), "hex"},
		{"base32", base32.StdEncoding.EncodeToString([]byte(seed)), "base32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := s.ScanTextForDLP(context.Background(), tc.payload)
			if r.Clean {
				t.Fatalf("%s-encoded zero-width-separated seed phrase NOT detected via ScanTextForDLP: clean=true (want blocked)", tc.name)
			}
			if got := r.Matches[0].Encoded; got != tc.wantEncoded {
				t.Fatalf("encoded label = %q, want %s", got, tc.wantEncoded)
			}
		})
	}
}

func TestScanTextForDLP_SeedZeroWidthSeparatorBenignSentence(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	s := New(cfg)

	zw := string(rune(0x200B))
	payload := strings.Join([]string{
		"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
		"golf", "hotel", "india", "juliet", "kilo", "lima",
	}, zw)
	r := s.ScanTextForDLP(context.Background(), payload)
	if !r.Clean {
		t.Fatalf("benign zero-width-separated sentence false-positived as seed phrase: %+v", r.Matches)
	}
}

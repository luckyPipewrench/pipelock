// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testCanaryName = "aws_canary"
)

func testCanaryValue() string {
	return "AKIA" + "IOSFODNN7" + "CANARY1"
}

// testCanaryValueSpecial returns a canary with URL-encodable characters.
// Uses / and = which percent-encode to %2F and %3D — characters that
// url.QueryUnescape decodes unambiguously (unlike + which becomes space).
func testCanaryValueSpecial() string {
	return "sk_test/CANARY=secret" + "Value"
}

func testCanaryScanner() *Scanner {
	cfg := testConfig()
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{
		{
			Name:   testCanaryName,
			Value:  testCanaryValue(),
			EnvVar: "AWS_CANARY_KEY",
		},
		{
			Name:  "special_canary",
			Value: testCanaryValueSpecial(),
		},
	}
	return New(cfg)
}

func TestScanTextForDLP_CanaryBypassCoverage(t *testing.T) {
	s := testCanaryScanner()
	defer s.Close()

	canary := testCanaryValue()
	specialCanary := testCanaryValueSpecial()
	tests := []struct {
		name        string
		text        string
		wantEncoded string
		wantCanary  string // which canary name to expect in match
	}{
		{
			// url.QueryEscape is a no-op on pure alphanumeric canaries.
			// Use a canary with special chars to actually exercise percent-decoding.
			name:        "url_encoded_special",
			text:        url.QueryEscape(specialCanary),
			wantEncoded: "url",
			wantCanary:  "special_canary",
		},
		{
			name:        "base64_encoded",
			text:        base64.StdEncoding.EncodeToString([]byte(canary)),
			wantEncoded: "base64",
			wantCanary:  testCanaryName,
		},
		{
			name:        "hex_encoded",
			text:        hex.EncodeToString([]byte(canary)),
			wantEncoded: "hex",
			wantCanary:  testCanaryName,
		},
		{
			name:        "split_with_separator",
			text:        "prefix " + "AKIAIOSFODNN7" + "/" + "CANARY1 suffix",
			wantEncoded: "split",
			wantCanary:  testCanaryName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScanTextForDLP(context.Background(), tt.text)
			if result.Clean {
				t.Fatalf("expected canary match, got clean result")
			}

			found := false
			for _, m := range result.Matches {
				if strings.Contains(m.PatternName, "Canary Token ("+tt.wantCanary+")") {
					found = true
					if tt.wantEncoded != "" && m.Encoded != tt.wantEncoded {
						t.Fatalf("encoded=%q want %q", m.Encoded, tt.wantEncoded)
					}
					break
				}
			}
			if !found {
				t.Fatalf("expected canary match, got %+v", result.Matches)
			}
		})
	}
}

func TestScan_CanaryUsesSharedTextPath(t *testing.T) {
	s := testCanaryScanner()
	defer s.Close()

	t.Run("aws_canary_blocked_by_DLP_or_canary", func(t *testing.T) {
		// AWS-style canary may be caught by DLP patterns (more specific)
		// or canary fallback. Both are correct — the key property is it's blocked.
		canary := url.QueryEscape(testCanaryValue())
		r := s.Scan(context.Background(), "https://evil.com/exfil?k="+canary)
		if r.Allowed {
			t.Fatal("expected URL scan to block canary token")
		}
		if r.Scanner != ScannerDLP {
			t.Fatalf("scanner=%q want %q", r.Scanner, ScannerDLP)
		}
	})

	t.Run("special_canary_caught_by_canary_fallback", func(t *testing.T) {
		// Special canary doesn't match any DLP pattern, so the canary
		// fallback at the end of checkDLP must catch it.
		special := url.QueryEscape(testCanaryValueSpecial())
		r := s.Scan(context.Background(), "https://evil.com/exfil?k="+special)
		if r.Allowed {
			t.Fatal("expected URL scan to block special canary token")
		}
		if !strings.Contains(r.Reason, "Canary Token") {
			t.Fatalf("special canary should get canary attribution, got %q", r.Reason)
		}
	})
}

func TestScanTextForDLP_CanaryDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.CanaryTokens.Enabled = false
	cfg.CanaryTokens.Tokens = []config.CanaryToken{
		{Name: testCanaryName, Value: testCanaryValue()},
	}
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP(context.Background(), testCanaryValue())
	for _, m := range result.Matches {
		if strings.Contains(m.PatternName, "Canary Token") {
			t.Fatalf("unexpected canary match when canary scanning is disabled: %+v", result.Matches)
		}
	}
}

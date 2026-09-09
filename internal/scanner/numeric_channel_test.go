// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func numericChannelCanaryScanner(t *testing.T, canary string, envSecret string) *Scanner {
	t.Helper()
	cfg := testConfig()
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "planted", Value: canary}}
	if envSecret != "" {
		cfg.DLP.ScanEnv = true
		t.Setenv("PIPELOCK_TEST_NUMERIC_SECRET", envSecret)
	}
	return MustNew(cfg)
}

func TestScanNumericChannelForKnownValues(t *testing.T) {
	canary := "canary-" + "7F3a9c2e4b1d"
	secret := "sk-" + "ant-numericchannel0123456789"
	s := numericChannelCanaryScanner(t, canary, secret)

	for _, tt := range []struct {
		name        string
		numeric     string
		wantPattern string
		wantEncoded string
	}{
		{name: "empty channel", numeric: ""},
		{name: "ordinary telemetry", numeric: "1,2,3,4,5,6,7,8,9,10,4111111111111112,255,255,255"},
		{name: "run shorter than the floor is not decoded", numeric: decimalCharacterCodes("canary-", ",")},
		{name: "canary as comma separated character codes", numeric: decimalCharacterCodes(canary, ","), wantPattern: "Canary Token (planted)", wantEncoded: encodingDecimal},
		{name: "canary codes after telemetry", numeric: "3.14,42," + decimalCharacterCodes(canary, ",") + ",7", wantPattern: "Canary Token (planted)", wantEncoded: encodingDecimal},
		{name: "float inside the codes breaks the run", numeric: strings.Replace(decimalCharacterCodes(canary, ","), ",", ",1.5,", 1)},
		{name: "environment secret as character codes", numeric: decimalCharacterCodes(secret, ","), wantPattern: "Environment Variable Leak", wantEncoded: "env"},
		{name: "environment secret as space separated codes", numeric: decimalCharacterCodes(secret, " "), wantPattern: "Environment Variable Leak", wantEncoded: "env"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			matches := s.ScanNumericChannelForKnownValues(tt.numeric)
			if tt.wantPattern == "" {
				if len(matches) != 0 {
					t.Fatalf("expected no match, got %+v", matches)
				}
				return
			}
			if len(matches) != 1 {
				t.Fatalf("expected one match, got %d: %+v", len(matches), matches)
			}
			if matches[0].PatternName != tt.wantPattern || matches[0].Encoded != tt.wantEncoded {
				t.Fatalf("match = (%q, %q), want (%q, %q)", matches[0].PatternName, matches[0].Encoded, tt.wantPattern, tt.wantEncoded)
			}
			if matches[0].Span().ViewLabel == "" {
				t.Fatal("match must carry a span view label")
			}
		})
	}
}

func TestScanNumericChannel_NumericCanaryMatchesAsPlainNumber(t *testing.T) {
	// A canary that is itself a number can come back as a JSON number.
	s := numericChannelCanaryScanner(t, "8675309123456789", "")
	matches := s.ScanNumericChannelForKnownValues("12,8675309123456789,13")
	if len(matches) != 1 || matches[0].Encoded != "" {
		t.Fatalf("plain numeric canary must match with no encoding label, got %+v", matches)
	}
}

func TestScanNumericChannel_RequiresWholeNumericLeaves(t *testing.T) {
	canary := "canary-" + "7F3a9c2e4b1d"
	secret := "sk-" + "ant-numericchannel0123456789"
	s := numericChannelCanaryScanner(t, canary, secret)

	// A larger integer can contain a decimal-code sequence as a byte substring
	// without spelling the protected value. Likewise, neither side of a
	// digits-only canary may match a larger JSON number.
	codesWithLargerFirstLeaf := "1" + decimalCharacterCodes(canary, ",")
	for _, numeric := range []string{
		codesWithLargerFirstLeaf,
		"18675309123456789",
		"86753091234567890",
		"1" + decimalCharacterCodes(secret, ","),
	} {
		if matches := s.ScanNumericChannelForKnownValues(numeric); len(matches) != 0 {
			t.Fatalf("numeric leaves must match known values only as complete leaves; numeric=%q matches=%+v", numeric, matches)
		}
	}
}

func TestScanNumericChannel_PlainNumericSecretIsNotALeak(t *testing.T) {
	// A configured secret received as a plain number is legitimately received
	// data, the same reason the inbound text scan skips secret-leak matching.
	// Only the character-code disguise counts.
	s := numericChannelCanaryScanner(t, "canary-"+"7F3a9c2e4b1d", "9876543210987654")
	if matches := s.ScanNumericChannelForKnownValues("9876543210987654"); len(matches) != 0 {
		t.Fatalf("plain numeric secret must not match inbound, got %+v", matches)
	}
	if matches := s.ScanNumericChannelForKnownValues(decimalCharacterCodes("9876543210987654", ",")); len(matches) != 1 {
		t.Fatalf("character-code secret must match, got %+v", matches)
	}
}

func TestScanNumericChannel_NoKnownValuesIsInert(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	if matches := s.ScanNumericChannelForKnownValues(decimalCharacterCodes("anything-at-all-here", ",")); len(matches) != 0 {
		t.Fatalf("no configured known values must mean no matches, got %+v", matches)
	}
}

func TestDecodeDecimalCharacterCodes(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "short run dropped", in: "104,105", want: ""},
		{name: "comma run", in: decimalCharacterCodes("secret-value", ","), want: "secret-value"},
		{name: "space run", in: decimalCharacterCodes("secret-value", " "), want: "secret-value"},
		{name: "two runs split by a float", in: decimalCharacterCodes("first-run", ",") + ",2.5," + decimalCharacterCodes("second-run", ","), want: "first-run\nsecond-run"},
		{name: "negative ends a run", in: decimalCharacterCodes("secret-value", ",") + ",-1," + "104,105", want: "secret-value"},
		{name: "past unicode range ends a run", in: decimalCharacterCodes("secret-value", ",") + ",1114112", want: "secret-value"},
		{name: "surrogate is not a valid rune", in: decimalCharacterCodes("secret-", ",") + ",55296," + decimalCharacterCodes("value", ","), want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeDecimalCharacterCodes(tt.in); got != tt.want {
				t.Fatalf("decodeDecimalCharacterCodes(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

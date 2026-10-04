// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// knownSecretEncodingSecrets covers ASCII, base64 '+' and '/' output, padding
// lengths 0/1/2, non-ASCII runes and a long value.
var knownSecretEncodingSecrets = []string{
	"Zq7Lm2Xc9Vb4Nn8Kp3Rt6Wy1",
	"Zq7Lm2Xc9Vb4Nn8Kp3Rt6Wy1a",
	"Zq7Lm2Xc9Vb4Nn8Kp3Rt6Wy1ab",
	"~~~???>>>~~~???>>>Q9z",
	"p\u00e4ssw\u00f6rd-\u00fc\u00df-77Hk2Lq9Tz",
	strings.Repeat("Lw8Qz3Vn5Rk2", 30),
}

func knownSecretEncodingScanner(t *testing.T, secrets []string) *Scanner {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.txt")
	if err := os.WriteFile(path, []byte(strings.Join(secrets, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if len(s.fileSecrets) != len(secrets) {
		t.Fatalf("loaded %d file secrets, want %d", len(s.fileSecrets), len(secrets))
	}
	return s
}

// knownSecretEncodingTexts returns texts that carry secret in every form the
// matcher supports, split and padded forms, plus near misses.
func knownSecretEncodingTexts(rng *testRand, secret, other string) []string {
	raw := []byte(secret)
	b64 := base64.StdEncoding.EncodeToString(raw)
	b64URL := base64.RawURLEncoding.EncodeToString(raw)
	hexEnc := hex.EncodeToString(raw)
	b32 := base32.StdEncoding.EncodeToString(raw)
	b32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	split := func(value, sep string) string {
		if len(value) < 4 {
			return value
		}
		cut := 1 + rng.IntN(len(value)-2)
		return value[:cut] + sep + value[cut:]
	}
	forms := []string{
		secret,
		secret[:len(secret)/2+1],
		b64, strings.TrimRight(b64, "="), split(b64, "\n"), split(b64, " "),
		b64URL, split(b64URL, "\r\n"),
		hexEnc, strings.ToUpper(hexEnc),
		hexByteSep(hexEnc, ":"), hexByteSep(hexEnc, " "), hexByteSep(hexEnc, "-"),
		hexByteSep(hexEnc, ","), hexBytePrefix(hexEnc, `\x`), hexBytePrefix(hexEnc, "0x"),
		split(hexEnc, "/"), split(hexEnc, "0x"),
		decimalCharacterCodes(secret, ","), decimalCharacterCodes(secret, " "),
		b32, b32NoPad, strings.ToLower(b32), split(b32NoPad, " "),
		base64.StdEncoding.EncodeToString([]byte(other)),
		"", "short", strings.Repeat("A", len(secret)*3),
	}
	texts := make([]string, 0, len(forms)*2)
	for _, form := range forms {
		texts = append(texts, form, "prefix "+form+" suffix")
	}
	return texts
}

// TestMatchSecretEncodingSpanMatchesReference holds the precomputed matcher to
// the exact result of the per-scan encoder it replaced: same match, same span,
// same view label, same encoding label, same partial length.
func TestMatchSecretEncodingSpanMatchesReference(t *testing.T) {
	s := knownSecretEncodingScanner(t, knownSecretEncodingSecrets)
	rng := newTestRand(1796)
	matched, compared := 0, 0
	for i, secret := range s.fileSecrets {
		encodings := s.knownSecretEncodings[secret]
		if encodings == nil {
			t.Fatalf("secret %d has no precomputed encodings", i)
		}
		other := s.fileSecrets[(i+1)%len(s.fileSecrets)]
		for _, text := range knownSecretEncodingTexts(rng, secret, other) {
			texts := []spanTextView{{text: text, viewLabel: ViewDLPNormalized}}
			lower := []spanTextView{{text: strings.ToLower(text), viewLabel: lowerViewLabel(ViewDLPNormalized)}}
			windows := s.knownSecretWindows[secret]
			wantMatch, wantStart, wantEnd, wantView, wantOK := matchSecretEncodingSpanReference(secret, windows, texts, lower)
			for _, enc := range []*knownSecretEncodings{encodings, nil} {
				gotMatch, gotStart, gotEnd, gotView, gotOK := matchSecretEncodingSpan(secret, windows, enc, texts, lower)
				if gotMatch != wantMatch || gotStart != wantStart || gotEnd != wantEnd || gotView != wantView || gotOK != wantOK {
					t.Errorf("secret %d text %q (precomputed=%v): got (%+v %d %d %q %v), want (%+v %d %d %q %v)",
						i, text, enc != nil, gotMatch, gotStart, gotEnd, gotView, gotOK, wantMatch, wantStart, wantEnd, wantView, wantOK)
				}
				compared++
			}
			if wantOK {
				matched++
			}
		}
	}
	// Equality over texts that never match would prove nothing.
	if matched < 30*len(s.fileSecrets) {
		t.Fatalf("only %d of %d texts matched; fixture does not exercise the encoders", matched, compared/2)
	}
}

// TestKnownSecretEncodingsScanVerdictsUnchanged compares full scan results on
// the precomputed path against the same scanner forced onto the per-scan path.
func TestKnownSecretEncodingsScanVerdictsUnchanged(t *testing.T) {
	precomputed := knownSecretEncodingScanner(t, knownSecretEncodingSecrets)
	perScan := knownSecretEncodingScanner(t, knownSecretEncodingSecrets)
	perScan.knownSecretEncodings = nil
	rng := newTestRand(7)
	ctx := context.Background()
	blocked := 0
	for i, secret := range precomputed.fileSecrets {
		other := precomputed.fileSecrets[(i+1)%len(precomputed.fileSecrets)]
		for _, text := range knownSecretEncodingTexts(rng, secret, other) {
			want := perScan.ScanTextForDLP(ctx, text)
			got := precomputed.ScanTextForDLP(ctx, text)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("text DLP differs for secret %d text %q:\n got %+v\nwant %+v", i, text, got, want)
			}
			if !got.Clean {
				blocked++
			}
			target := "https://api.vendor.example/v1?q=" + strings.ReplaceAll(text, " ", "%20")
			wantURL := perScan.Scan(ctx, target)
			gotURL := precomputed.Scan(ctx, target)
			if gotURL.Allowed != wantURL.Allowed || gotURL.Reason != wantURL.Reason || gotURL.Scanner != wantURL.Scanner {
				t.Errorf("URL verdict differs for secret %d text %q: got %+v want %+v", i, text, gotURL, wantURL)
			}
		}
	}
	if blocked == 0 {
		t.Fatal("no fixture text was detected; comparison is vacuous")
	}
}

// BenchmarkMatchSecretEncodingSpan compares, in one binary, the per-scan
// encoder with the precomputed forms on a clean receipt and 20 file secrets.
func BenchmarkMatchSecretEncodingSpan(b *testing.B) {
	secrets := make([]string, 20)
	for i := range secrets {
		secrets[i] = "bench-known-value-" + string(rune('A'+i)) + "-Zq7Lm2Xc9Vb4Nn8Kp3Rt6Wy1"
	}
	encodings := buildKnownSecretEncodings(knownSecretEncodingBudgetBytes, secrets)
	texts := []spanTextView{{text: benchReceipt, viewLabel: ViewDLPNormalized}}
	lower := []spanTextView{{text: strings.ToLower(benchReceipt), viewLabel: lowerViewLabel(ViewDLPNormalized)}}
	b.Run("per-scan-encode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, secret := range secrets {
				matchSecretEncodingSpanReference(secret, knownValueWindowIndex{}, texts, lower)
			}
		}
	})
	b.Run("precomputed", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, secret := range secrets {
				matchSecretEncodingSpan(secret, knownValueWindowIndex{}, encodings[secret], texts, lower)
			}
		}
	})
}

func TestBuildKnownSecretEncodingsBudget(t *testing.T) {
	secrets := []string{"Zq7Lm2Xc9Vb4Nn8Kp3Rt6Wy1", strings.Repeat("Lw8Qz3Vn5Rk2", 30), "Hk2Lq9Tz77p4Mx3Bn6Vc"}
	full := buildKnownSecretEncodings(knownSecretEncodingBudgetBytes, secrets)
	if len(full) != len(secrets) {
		t.Fatalf("full budget kept %d of %d secrets", len(full), len(secrets))
	}
	// A budget that fits the short secrets but not the long one skips only
	// the long one; later secrets still fit.
	budget := full[secrets[0]].retainedBytes + full[secrets[2]].retainedBytes
	partial := buildKnownSecretEncodings(budget, secrets)
	if partial[secrets[0]] == nil || partial[secrets[2]] == nil || partial[secrets[1]] != nil {
		t.Fatalf("budget selection wrong: %v", partial)
	}
	if got := buildKnownSecretEncodings(knownSecretEncodingBudgetBytes, []string{"", "dup-value-0123456789", "dup-value-0123456789"}); len(got) != 1 {
		t.Fatalf("empty and duplicate secrets: got %d entries, want 1", len(got))
	}
	// An over-budget secret is still found: the matcher encodes it per scan.
	long := secrets[1]
	texts := []spanTextView{{text: "x " + base64.StdEncoding.EncodeToString([]byte(long)), viewLabel: ViewDLPNormalized}}
	lower := []spanTextView{{text: strings.ToLower(texts[0].text), viewLabel: lowerViewLabel(ViewDLPNormalized)}}
	if match, _, _, _, ok := matchSecretEncodingSpan(long, knownValueWindowIndex{}, partial[long], texts, lower); !ok || match.encoding != encodingBase64 {
		t.Fatalf("over-budget secret not detected: ok=%v match=%+v", ok, match)
	}
}

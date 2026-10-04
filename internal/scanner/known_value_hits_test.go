// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

const knownValueHitsAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func knownValueHitsRandomValue(rng *testRand, n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(knownValueHitsAlphabet[rng.IntN(len(knownValueHitsAlphabet))])
	}
	return b.String()
}

// knownValueHitsSecrets adds generated values to the shared fixture: distinct
// values, values sharing a long prefix or suffix (their shared windows are
// excluded from the index), and a value repeating its own windows.
func knownValueHitsSecrets(rng *testRand) []string {
	secrets := append([]string(nil), knownSecretEncodingSecrets...)
	for range 24 {
		secrets = append(secrets, knownValueHitsRandomValue(rng, 20+rng.IntN(60)))
	}
	shared := knownValueHitsRandomValue(rng, 24)
	secrets = append(secrets,
		shared+knownValueHitsRandomValue(rng, 12),
		shared+knownValueHitsRandomValue(rng, 20),
		knownValueHitsRandomValue(rng, 10)+shared,
		strings.Repeat(knownValueHitsRandomValue(rng, 8), 6),
	)
	return secrets
}

// knownValueHitsTexts builds texts holding partial disclosures of one or more
// values at random offsets, mutated near misses, and the encoded forms.
func knownValueHitsTexts(rng *testRand, secrets []string) []string {
	partial := func(secret string) string {
		if len(secret) <= minKnownSecretSubstringLen {
			return secret
		}
		n := minKnownSecretSubstringLen - 2 + rng.IntN(len(secret)-minKnownSecretSubstringLen+3)
		n = min(n, len(secret))
		start := rng.IntN(len(secret) - n + 1)
		return secret[start : start+n]
	}
	var texts []string
	for i, secret := range secrets {
		other := secrets[(i+1)%len(secrets)]
		texts = append(texts, knownSecretEncodingTexts(rng, secret, other)...)
		for range 3 {
			p := partial(secret)
			texts = append(texts, p, "x="+p+"&y="+partial(other), partial(other)+"|"+p+"|"+partial(secrets[rng.IntN(len(secrets))]))
			if len(p) > 2 {
				cut := rng.IntN(len(p))
				texts = append(texts, p[:cut]+"#"+p[cut:])
			}
		}
	}
	for range 50 {
		texts = append(texts, knownValueHitsRandomValue(rng, rng.IntN(200)))
	}
	return texts
}

func TestKnownValueWindowHitsMatchDirectScan(t *testing.T) {
	rng := newTestRand(1798)
	secrets := knownValueHitsSecrets(rng)
	s := knownSecretEncodingScanner(t, secrets)
	partials, compared := 0, 0
	for _, text := range knownValueHitsTexts(rng, secrets) {
		viewSets := [][]spanTextView{
			{{text: text, viewLabel: ViewDLPNormalized}},
			{{text: text, viewLabel: "control_stripped_url"}, {text: strings.ToUpper(text) + text, viewLabel: "control_stripped_url:url_decoded"}},
		}
		for _, views := range viewSets {
			lower := make([]spanTextView, len(views))
			for i, view := range views {
				lower[i] = spanTextView{text: strings.ToLower(view.text), viewLabel: lowerViewLabel(view.viewLabel)}
			}
			memo := newKnownValueWindowHits(views)
			for _, secret := range s.fileSecrets {
				windows := s.knownSecretWindows[secret]
				ws, we, wl, wv, wok := indexKnownValueSubstring(secret, windows, views)
				gs, ge, gl, gv, gok := indexKnownValueSubstringWithHits(secret, windows, views, memo)
				if gs != ws || ge != we || gl != wl || gv != wv || gok != wok {
					t.Fatalf("partial match differs for secret %q in %q: got (%d %d %d %q %v), want (%d %d %d %q %v)",
						secret, text, gs, ge, gl, gv, gok, ws, we, wl, wv, wok)
				}
				if wok {
					partials++
				}
				wantMatch, wantStart, wantEnd, wantView, wantOK := matchSecretEncodingSpan(secret, windows, s.knownSecretEncodings[secret], views, lower)
				gotMatch, gotStart, gotEnd, gotView, gotOK := matchSecretEncodingSpanWithHits(secret, windows, s.knownSecretEncodings[secret], views, lower, memo)
				if gotMatch != wantMatch || gotStart != wantStart || gotEnd != wantEnd || gotView != wantView || gotOK != wantOK {
					t.Fatalf("secret match differs for %q in %q", secret, text)
				}
				compared++
			}
		}
	}
	// Agreement over texts with no partial disclosure would prove nothing.
	if partials < 500 {
		t.Fatalf("only %d of %d comparisons found a partial match", partials, compared)
	}
	t.Logf("compared %d secret/text/view cases, %d partial matches", compared, partials)
}

// referenceCheckSecretsInText is checkSecretsInText without the shared memo.
func referenceCheckSecretsInText(s *Scanner, secrets []string, text string) (knownSecretMatch, int, int, string, bool) {
	texts := []spanTextView{{text: text, viewLabel: ViewDLPNormalized}}
	lower := []spanTextView{{text: strings.ToLower(text), viewLabel: lowerViewLabel(ViewDLPNormalized)}}
	for _, secret := range secrets {
		if match, start, end, view, ok := matchSecretEncodingSpan(secret, s.knownSecretWindows[secret], s.knownSecretEncodings[secret], texts, lower); ok {
			return match, start, end, view, true
		}
	}
	return knownSecretMatch{}, 0, 0, "", false
}

func TestCheckSecretsInTextMatchesUnsharedScan(t *testing.T) {
	rng := newTestRand(1799)
	secrets := knownValueHitsSecrets(rng)
	s := knownSecretEncodingScanner(t, secrets)
	matched := 0
	for _, text := range knownValueHitsTexts(rng, secrets) {
		wantMatch, wantStart, wantEnd, wantView, wantOK := referenceCheckSecretsInText(s, s.fileSecrets, text)
		got := s.checkSecretsInText(s.fileSecrets, text, "Known Secret Leak", "")
		if !wantOK {
			if len(got) != 0 {
				t.Fatalf("unexpected match in %q: %+v", text, got)
			}
			continue
		}
		matched++
		wantSpan := newMatchSpan(wantStart, wantEnd, wantView, "Known Secret Leak", "", "")
		if len(got) != 1 || got[0].PartialLen != wantMatch.partialLen || got[0].Encoded != wantMatch.encoding || got[0].span != wantSpan {
			t.Fatalf("match differs in %q: got %+v, want %+v span %+v", text, got, wantMatch, wantSpan)
		}
	}
	if matched < 500 {
		t.Fatalf("only %d texts matched", matched)
	}
}

// TestKnownValueWindowHitsRejectsOtherViewsAndIndexes holds the memo to the
// inputs it was built for. Other views or another index scan directly.
func TestKnownValueWindowHitsRejectsOtherViewsAndIndexes(t *testing.T) {
	rng := newTestRand(1800)
	secrets := knownValueHitsSecrets(rng)
	s := knownSecretEncodingScanner(t, secrets)
	other := knownSecretEncodingScanner(t, secrets)
	secret := s.fileSecrets[len(knownSecretEncodingSecrets)]
	first := []spanTextView{{text: "a " + secret[2:20] + " b", viewLabel: ViewDLPNormalized}}
	second := []spanTextView{{text: "c " + secret[1:] + " d", viewLabel: ViewDLPNormalized}}
	memo := newKnownValueWindowHits(first)
	if _, ok := memo.forIndex(s.knownSecretWindows[secret], first); !ok {
		t.Fatal("memo must serve the views it was built for")
	}
	if _, ok := memo.forIndex(s.knownSecretWindows[secret], second); ok {
		t.Fatal("memo must not serve different views")
	}
	if _, ok := memo.forIndex(other.knownSecretWindows[secret], first); ok {
		t.Fatal("memo must not serve a different window index")
	}
	ws, we, wl, wv, wok := indexKnownValueSubstring(secret, s.knownSecretWindows[secret], second)
	gs, ge, gl, gv, gok := indexKnownValueSubstringWithHits(secret, s.knownSecretWindows[secret], second, memo)
	if !wok || gs != ws || ge != we || gl != wl || gv != wv || gok != wok {
		t.Fatalf("fallback differs: got (%d %d %d %q %v), want (%d %d %d %q %v)", gs, ge, gl, gv, gok, ws, we, wl, wv, wok)
	}
	var nilMemo *knownValueWindowHits
	if _, ok := nilMemo.forIndex(s.knownSecretWindows[secret], first); ok {
		t.Fatal("nil memo must scan directly")
	}
}

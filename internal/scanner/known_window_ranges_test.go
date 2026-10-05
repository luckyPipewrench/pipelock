// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func disableWindowByteRanges(sc *Scanner) {
	for k, v := range sc.knownSecretWindows {
		v.byteRanges = nil
		sc.knownSecretWindows[k] = v
	}
	for i := range sc.canaryTokens {
		sc.canaryTokens[i].partialWindows.byteRanges = nil
		sc.canaryTokens[i].canonicalPartialWindows.byteRanges = nil
	}
}

func TestKnownWindowRangeScanParity(t *testing.T) {
	const canary = "synthetic-canary-97F3D21A-nonproduction"
	const known = "fixture-known-93C41B8A-E671D2FF-no-real-secret"
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "fixture", Value: canary}}
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "fixture warn", Regex: `fixturewarn-[a-z]+`, Action: config.ActionWarn, Severity: config.SeverityHigh})
	makeSC := func() *Scanner {
		sc := MustNew(cfg)
		t.Cleanup(sc.Close)
		sc.envSecrets = []string{known}
		var err error
		sc.knownSecretWindows, err = buildKnownValueWindows(newKnownValueWindowBudget(maxKnownValueWindowEntries), sc.envSecrets)
		if err != nil {
			t.Fatal(err)
		}
		return sc
	}
	gotSC, wantSC := makeSC(), makeSC()
	disableWindowByteRanges(wantSC)
	inputs := []string{"", "ordinary text", "fixturewarn-sample", "\x00\xffＡ\u200b", strings.Repeat("ordinary ", 1000)}
	for _, secret := range []string{canary, known, awsExampleAccessKeyID(), githubClassicToken()} {
		for _, form := range encodedCredentialForms(t, secret) {
			inputs = append(inputs, form.value, `{"data":"`+form.value+`"}`, "https://api.vendor.example/"+form.value)
		}
		for i := 1; i < len(secret); i++ {
			for _, sep := range []string{" ", "\u200b", ".", "!"} {
				inputs = append(inputs, secret[:i]+sep+secret[i:])
			}
		}
		for i := 0; i+16 <= len(secret); i++ {
			part := secret[i : i+16]
			inputs = append(inputs, part, base64.StdEncoding.EncodeToString([]byte(part)), hex.EncodeToString([]byte(part)))
		}
	}
	// Real built-in corpus forms plus a deterministic malformed-input differential.
	rng := rand.New(rand.NewSource(724)) // #nosec G404 -- deterministic parity corpus.
	for i := 0; i < 500; i++ {
		buf := make([]byte, rng.Intn(180))
		_, _ = rng.Read(buf)
		inputs = append(inputs, string(buf))
	}
	clean, blocked, warned, comparisons := 0, 0, 0, 0
	for i, input := range inputs {
		for _, outbound := range []bool{true, false} {
			opts := textDLPOptions{scanSecretLeak: outbound}
			got := gotSC.scanTextForDLP(context.Background(), input, opts)
			want := wantSC.scanTextForDLP(context.Background(), input, opts)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("complete result parity input=%d outbound=%v", i, outbound)
			}
			comparisons++
			if got.Clean {
				clean++
			} else {
				blocked++
			}
			warned += len(got.InformationalMatches)
		}
	}
	if clean == 0 || blocked == 0 || warned == 0 {
		t.Fatalf("vacuous controls clean=%d blocked=%d warned=%d", clean, blocked, warned)
	}
	t.Logf("complete results including retained spans/identities: compared=%d clean=%d blocked=%d warned=%d", comparisons, clean, blocked, warned)
}

func TestKnownWindowRangeIndexParity(t *testing.T) {
	rng := rand.New(rand.NewSource(724)) // #nosec G404 -- deterministic parity corpus.
	values := []string{strings.Repeat("a", 64), strings.Repeat("a", 32) + "unique-middle-12345678" + strings.Repeat("a", 32)}
	for i := 0; i < 250; i++ {
		b := make([]byte, 64)
		_, _ = rng.Read(b)
		values = append(values, string(b))
	}
	set, err := buildKnownValueWindows(newKnownValueWindowBudget(maxKnownValueWindowEntries), values)
	if err != nil {
		t.Fatal(err)
	}
	comparisons := 0
	for _, value := range values {
		index := set[value]
		if index.byteRanges == nil {
			t.Fatal("first-byte range table absent")
		}
		reference := index
		reference.byteRanges = nil
		for i := 0; i+16 <= len(value); i++ {
			for _, text := range []string{value[i : i+16], "prefix" + value[i:i+16] + "suffix", strings.Repeat("a", 100)} {
				got := index.offsets(text[:16])
				want := reference.offsets(text[:16])
				if !reflect.DeepEqual(got, want) {
					t.Fatal("candidate order parity")
				}
				gs, ge, gl, gv, gok := indexKnownValueSubstring(value, index, []spanTextView{{text: text, viewLabel: "fixture"}})
				ws, we, wl, wv, wok := indexKnownValueSubstring(value, reference, []spanTextView{{text: text, viewLabel: "fixture"}})
				if fmt.Sprint(gs, ge, gl, gv, gok) != fmt.Sprint(ws, we, wl, wv, wok) {
					t.Fatal("longest disclosure span parity")
				}
				comparisons++
			}
		}
	}
	t.Logf("exact candidate and longest-span parity comparisons=%d", comparisons)
}

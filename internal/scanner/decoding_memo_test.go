// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDecodingMemoRequestAndModeIsolation(t *testing.T) {
	var memo decodingMemo
	inputs := []string{"first body", "second body", "%61", base64.StdEncoding.EncodeToString([]byte("first body")), "", "%61", "second body"}
	for pass := 0; pass < 2; pass++ {
		for _, input := range inputs {
			for _, includeURL := range []bool{false, true} {
				got := memo.decode(input, includeURL)
				want := referenceDecodeEncodingsFixpoint(input, includeURL)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("memo differs for %q (URL %v): got %#v, want %#v", input, includeURL, got, want)
				}
			}
		}
	}
	if len(memo.views) == 0 || memo.retainedBytes <= 0 {
		t.Fatal("memo parity never exercised retained views")
	}
}

func TestDecodingMemoRetentionLimitsKeepDecoding(t *testing.T) {
	input := base64.StdEncoding.EncodeToString([]byte("sample body"))
	want := referenceDecodeEncodingsFixpoint(input, true)
	if len(want) == 0 {
		t.Fatal("limit fixture has no decoded views")
	}
	for _, tt := range []struct {
		name string
		memo decodingMemo
	}{
		{name: "input budget", memo: decodingMemo{retainedBytes: maxDecodeTotalBytes}},
		{name: "output budget", memo: decodingMemo{retainedBytes: maxDecodeTotalBytes - len(input)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.memo.decode(input, true); !reflect.DeepEqual(got, want) {
				t.Fatalf("retention budget changed decoding: got %#v, want %#v", got, want)
			}
			if len(tt.memo.views) != 0 {
				t.Fatal("memo retained data past its byte budget")
			}
		})
	}
	memo := decodingMemo{views: make(map[decodingMemoKey][]decodedResult)}
	for i := 0; i < maxDecodeCandidates; i++ {
		memo.views[decodingMemoKey{text: fmt.Sprintf("retained-%d", i)}] = nil
	}
	if got := memo.decode(input, true); !reflect.DeepEqual(got, want) || len(memo.views) != maxDecodeCandidates {
		t.Fatalf("entry budget changed decoding or retention: got %#v, entries %d", got, len(memo.views))
	}
}

func TestTextDLPCompleteFindingsWithAndWithoutMemo(t *testing.T) {
	const canary = "parity-canary-value-abcdefgh"
	const known = "parity-known-value-abcdefgh"
	for _, defaults := range []bool{false, true} {
		t.Run(fmt.Sprintf("defaults_%v", defaults), func(t *testing.T) {
			cfg := testConfig()
			cfg.DLP.ScanEnv = false
			cfg.DLP.IncludeDefaults = ptrBool(defaults)
			if !defaults {
				cfg.DLP.Patterns = nil
			}
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "parity warning", Regex: `paritywarn-[a-z]+`, Severity: config.SeverityHigh, Action: config.ActionWarn})
			cfg.CanaryTokens.Enabled = true
			cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "parity", Value: canary}}
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			if defaults && len(sc.dlpPatterns) <= 1 || !defaults && len(sc.dlpPatterns) != 1 {
				t.Fatalf("parity configuration has %d patterns, defaults=%v", len(sc.dlpPatterns), defaults)
			}
			sc.envSecrets = []string{known}
			var warned []string
			sc.SetDLPWarnHook(func(_ context.Context, pattern, severity string) { warned = append(warned, pattern+":"+severity) })
			inputs := []string{"", "ordinary first body", "different second body", "paritywarn-sample", "\xff\x00", "MY======!", "CP======!", "ordinary first body"}
			for _, text := range []string{canary, known, awsExampleAccessKeyID(), githubClassicToken()} {
				for _, form := range encodedCredentialForms(t, text) {
					inputs = append(inputs, form.value, `{"sample":"`+form.value+`"}`)
				}
			}
			clean, enforced, informational := 0, 0, 0
			for _, input := range inputs {
				for _, outbound := range []bool{false, true} {
					options := textDLPOptions{emitWarns: true, scanSecretLeak: outbound}
					warned = nil
					want := sc.scanTextForDLPWithDecodes(context.Background(), input, options, nil)
					wantWarns := warned
					warned = nil
					got := sc.scanTextForDLP(context.Background(), input, options)
					if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(warned, wantWarns) {
						t.Fatalf("complete finding or warning differs for %q (outbound %v):\ngot %#v\nwant %#v\nwarns %v/%v", input, outbound, got, want, warned, wantWarns)
					}
					if got.Clean {
						clean++
					}
					enforced += len(got.Matches)
					informational += len(got.InformationalMatches)
				}
			}
			if clean == 0 || enforced == 0 || informational == 0 {
				t.Fatalf("incomplete parity evidence: clean=%d enforced=%d informational=%d", clean, enforced, informational)
			}
			t.Logf("compared %d complete results and warning sequences: clean=%d enforced=%d informational=%d", len(inputs)*2, clean, enforced, informational)
		})
	}
}

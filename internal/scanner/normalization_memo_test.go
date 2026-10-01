// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestNormalizationMemoPreservesDepthAndMixedInputs(t *testing.T) {
	var memo decodingMemo
	inputs := []string{"", "first body", "second body", "\xff\x00", "Ａ\u00a0Ｂ", "\uffa0", "e\u0301", "first body"}
	for _, input := range inputs {
		for range 3 {
			want := normalize.ForDLP(input)
			if got := memo.normalize(input); got != want {
				t.Fatalf("normalization differs for %q: got %q, want %q", input, got, want)
			}
			for _, includeURL := range []bool{false, true} {
				if got, wantDecoded := memo.decode(input, includeURL), referenceDecodeEncodingsFixpoint(input, includeURL); !reflect.DeepEqual(got, wantDecoded) {
					t.Fatalf("mixed memo changed decoded views for %q", input)
				}
			}
			input = want
		}
	}
	first := normalize.ForDLP("\uffa0")
	if first == normalize.ForDLP(first) {
		t.Fatal("depth fixture did not exercise a second changing normalization pass")
	}
	if len(memo.views) == 0 || len(memo.normalized) == 0 {
		t.Fatal("mixed memo did not retain both kinds of pure view")
	}
}

func TestNormalizationMemoSharesRetentionBounds(t *testing.T) {
	var memo decodingMemo
	for i := range maxDecodeCandidates {
		input := fmt.Sprintf("ordinary body %d", i)
		if i%2 == 0 {
			memo.normalize(input)
		} else {
			memo.decode(input, false)
		}
	}
	if len(memo.views)+len(memo.normalized) != maxDecodeCandidates {
		t.Fatal("combined entry limit was not reached")
	}
	retained := memo.retainedBytes
	if got, want := memo.normalize("Ａdifferent\x00body"), normalize.ForDLP("Ａdifferent\x00body"); got != want {
		t.Fatal("entry limit changed normalization")
	}
	if got, want := memo.decode("c2FtcGxlIGJvZHk=", false), referenceDecodeEncodingsFixpoint("c2FtcGxlIGJvZHk=", false); !reflect.DeepEqual(got, want) || len(got) == 0 {
		t.Fatal("entry limit changed nonempty decoding")
	}
	if len(memo.views)+len(memo.normalized) != maxDecodeCandidates || memo.retainedBytes != retained {
		t.Fatal("memo retained data after its shared entry bound")
	}
	for _, remaining := range []int{0, 3, 8} {
		bounded := decodingMemo{retainedBytes: maxDecodeTotalBytes - remaining}
		input := "Ａbody"
		if got, want := bounded.normalize(input), normalize.ForDLP(input); got != want || len(bounded.normalized) != 0 {
			t.Fatal("shared byte bound changed normalization or retained excess bytes")
		}
	}
	large := strings.Repeat("a", maxDecodeTotalBytes+1)
	var largeMemo decodingMemo
	if got := largeMemo.normalize(large); got != large || len(largeMemo.normalized) != 0 {
		t.Fatal("large input changed normalization or bypassed retention bound")
	}
}

func TestURLMemoCompleteResultParity(t *testing.T) {
	const canary = "parity-canary-value-abcdefgh"
	inputs := []string{"ordinary first body", "different second body", "paritywarn-sample", "\xff\x00", "MY======!", "CP======!", "ordinary first body"}
	for _, text := range []string{canary, awsExampleAccessKeyID(), githubClassicToken()} {
		for _, form := range encodedCredentialForms(t, text) {
			inputs = append(inputs, form.value)
		}
	}
	compared, allowed, blocked, warned := 0, 0, 0, 0
	for _, defaults := range []bool{false, true} {
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
		for _, host := range []string{"api.vendor.example", "other.vendor.example"} {
			for _, input := range inputs {
				parsed := &url.URL{Scheme: "https", Host: host, Path: "/sample", RawQuery: url.Values{"sample": {input, "ordinary second value"}}.Encode()}
				var memo decodingMemo
				wantCore := sc.checkCoreDLPWithDecodes(parsed, nil)
				gotCore := sc.checkCoreDLPWithDecodes(parsed, &memo)
				want, wantWarns := sc.checkDLPWithDecodes(parsed, nil)
				got, gotWarns := sc.checkDLPWithDecodes(parsed, &memo)
				if !reflect.DeepEqual(gotCore, wantCore) || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotWarns, wantWarns) {
					t.Fatalf("complete URL result differs for host=%s input=%q:\ncore=%#v/%#v\nconfigured=%#v/%#v\nwarns=%#v/%#v", host, input, gotCore, wantCore, got, want, gotWarns, wantWarns)
				}
				compared++
				bodyOptions := textDLPOptions{scanSecretLeak: true}
				if body, wantBody := sc.scanTextForDLPWithDecodes(context.Background(), input, bodyOptions, &memo), sc.scanTextForDLPWithDecodes(context.Background(), input, bodyOptions, nil); !reflect.DeepEqual(body, wantBody) {
					t.Fatal("mixed URL/body transforms changed the complete body result")
				}
				if got.Allowed && gotCore.Allowed {
					allowed++
				} else {
					blocked++
				}
				warned += len(gotWarns)
				// Finding coordinates are newly constructed, never memoized.
				if len(got.spans) > 0 {
					got.spans[0].ByteStart = -1
					again, againWarns := sc.checkDLPWithDecodes(parsed, &memo)
					if !reflect.DeepEqual(again, want) || !reflect.DeepEqual(againWarns, wantWarns) {
						t.Fatal("retained transform state aliased result metadata")
					}
				}
			}
		}
	}
	if allowed == 0 || blocked == 0 || warned == 0 {
		t.Fatalf("vacuous result oracle: allowed=%d blocked=%d warnings=%d", allowed, blocked, warned)
	}
	t.Logf("compared %d complete core/configured URL results and ordered warnings", compared)
}

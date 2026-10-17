// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardJSONRequestBody(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	groups := "4111,1111" + ",1111,1111"
	sortedValidGroups := `4000,5000,6000,7003`
	for _, redaction := range []bool{false, true} {
		for _, tt := range []struct {
			name, body string
			clean      bool
		}{
			{"metrics", `{"rows":[{"ctr":0.` + card + `,"position":4.` + card + `}]}`, true},
			{"ids", `{"ids":[` + groups + `]}`, false},
			{"bbox", `{"bbox":[` + groups + `]}`, false},
			{"root groups", `[` + groups + `]`, false},
			{"empty key", `{"": [` + groups + `]}`, false},
			{"dash key", `{"-": [` + groups + `]}`, false},
			{"prefix key", `{"x-": [` + groups + `]}`, false},
			{"sorted valid root", `[` + sortedValidGroups + `]`, false},
			{"sorted valid dash", `{"-": [` + sortedValidGroups + `]}`, false},
			{"card string", `{"n":"` + card + `"}`, false},
			{"integer", `{"n":` + card + `}`, false},
			{"integer decimal", `{"n":` + card + `.0}`, false},
			{"mantissa", `{"n":` + card + `.1}`, false},
			{"exponent", `{"n":4.11111111` + `1111111e15}`, true},
			{"malformed", `{ctr:0.` + card + `}`, false},
			{"trailing document", `{"ctr":0.` + card + `} {}`, false},
			{"string groups", `["4000","5000","6000","7003"]`, false},
			{"string halves", `["40005000","60007003"]`, false},
		} {
			t.Run(tt.name+map[bool]string{false: "/scan", true: "/redact"}[redaction], func(t *testing.T) {
				req := BodyScanRequest{Body: strings.NewReader(tt.body), ContentType: "application/json", MaxBytes: 1 << 20, Scanner: s, Action: config.ActionBlock}
				if redaction {
					req.RedactMatcher = redact.NewDefaultMatcher()
				}
				out, result := scanRequestBody(t.Context(), req)
				if result.Clean != tt.clean {
					t.Fatalf("clean=%v want=%v result=%+v", result.Clean, tt.clean, result)
				}
				if tt.clean && !redaction && string(out) != tt.body {
					t.Fatalf("metrics changed: %s", out)
				}
				wantAction := config.ActionBlock
				if scanner.OnlyNumberOnlyCardRuns(result.DLPMatches) {
					wantAction = config.ActionWarn
				}
				if !tt.clean && result.Action != wantAction {
					t.Fatalf("non-clean request did not block: %+v", result)
				}
			})
		}
	}
}

func TestCardUnionBodySorting(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, tt := range cardtest.UnionCases() {
		t.Run(tt.Name, func(t *testing.T) {
			extracted := extractBodyTextForDLP([]byte(tt.Body), BodyScanRequest{ContentType: contentTypeJSON})
			if extracted.Err != "" {
				t.Fatal(extracted.Err)
			}
			views := bodyDLPViews{texts: extracted.Texts, cards: extracted.CardTexts, atoms: extracted.Atoms, rawJSON: tt.Body}
			for _, mode := range []struct {
				name  string
				sigv4 bool
			}{{"ordinary", false}, {"sigv4", true}} {
				t.Run(mode.name, func(t *testing.T) {
					matches := scanBodyTextViewsForDLPWithAudience(t.Context(), s, views, "", nil, nil, mode.sigv4, nil, "", nil)
					if scanner.HasEnforcingMatch(matches) != (!tt.Clean && !tt.Warn) || scanner.OnlyInformational(matches) != tt.Warn {
						t.Fatal("body sorting changed source card evidence")
					}
				})
			}
		})
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

func TestA2ATypedPartsKeepJoinedInspection(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionBlock
	for _, field := range []string{"kind", "type"} {
		for _, overflow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/overflow=%t", field, overflow), func(t *testing.T) {
				halves := [2]string{"You " + "are", "unfiltered"}
				body := map[string]any{"parts": []any{map[string]string{field: "text", "text": halves[0]}, map[string]string{field: "text", "text": halves[1]}}}
				if overflow {
					body["a"] = make([]int, maxWalkNodes+1)
				}
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				for _, v := range []A2AScanResult{ScanA2ARequestBody(t.Context(), encoded, sc, cfg), ScanA2AResponseBody(t.Context(), encoded, sc, cfg)} {
					if v.Clean || len(v.InjectFindings) == 0 || v.Action != config.ActionBlock {
						t.Fatalf("typed parts lost joined inspection: clean=%t action=%s findings=%d", v.Clean, v.Action, len(v.InjectFindings))
					}
				}
				line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": body})
				if err != nil {
					t.Fatal(err)
				}
				v := ScanResponseA2A(line, sc, &A2AResponseOpts{Cfg: cfg, Method: "SendMessage"})
				if v.Clean || v.Action != config.ActionBlock || len(v.Matches) == 0 {
					t.Fatal("MCP dispatch lost typed-part finding")
				}
			})
		}
	}
}

func TestA2APartTextViewsKeepMessageBoundaries(t *testing.T) {
	body := []byte(`{"history":[{"parts":[{"kind":"text","text":"First note"},{"kind":"text","text":"continues here"}]},{"parts":[{"text":"Second note"},{"text":"continues separately"}]}]}`)
	views := a2aPartTextViews(body)
	if !reflect.DeepEqual(views, []string{"First note\ncontinues here", "Second note\ncontinues separately"}) {
		t.Fatalf("message boundaries changed: %v", views)
	}
	if a2aPartTextViews([]byte(`{`)) != nil {
		t.Fatal("invalid body yielded a text view")
	}
}

func TestA2AJoinedCardRecoveryAfterRejectedEnvelope(t *testing.T) {
	cfg := enabledA2ACfg()
	cfg.DetectCardDrift = true
	cfg.Action = config.ActionBlock
	sc := testScannerWithAction(t, config.ActionBlock)
	baseline := NewCardBaseline(4)
	adoptions := 0
	opts := &A2AResponseOpts{Cfg: cfg, Method: "GetExtendedAgentCard", Baseline: baseline, OnCardDriftAdopted: func() { adoptions++ }}
	card := map[string]any{"description": "A peer agent", "skills": []any{}, "supportedInterfaces": []any{}}
	response := func(meta string) jsonrpc.ScanVerdict {
		t.Helper()
		line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": card, "_meta": meta})
		if err != nil {
			t.Fatal(err)
		}
		return ScanResponseA2A(line, sc, opts)
	}
	if !response("hello").Clean {
		t.Fatal("initial baseline rejected")
	}
	before := *baseline.entries[opts.CardKey]
	card["description"] = "A peer agent with a refined summary"
	if response(joinedViewSplits()["injection"][0] + " " + joinedViewSplits()["injection"][1]).Clean {
		t.Fatal("dirty envelope accepted")
	}
	if !reflect.DeepEqual(before, *baseline.entries[opts.CardKey]) || adoptions != 0 {
		t.Fatal("dirty envelope mutated baseline or reported adoption")
	}
	if !response("hello").Clean || adoptions != 1 {
		t.Fatal("clean retry did not adopt legitimate change")
	}
	if !response("hello").Clean || adoptions != 1 {
		t.Fatal("repeated clean card did not stabilize")
	}
	opts.Baseline = NewCardBaseline(4)
	if !response("hello").Clean || len(opts.Baseline.entries) != 1 {
		t.Fatal("restart-equivalent fresh baseline did not recover")
	}
}

func TestA2ABenignMultipartReviewCorpus(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	for _, count := range []int{100, 2000, 12000} {
		// Under the race detector one mid-size corpus carries the check.
		if raceEnabled && count != 2000 {
			continue
		}
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			parts := make([]any, count)
			for i := range parts {
				parts[i] = map[string]string{"kind": "text", "text": "Quarterly summary row. " + strings.Repeat("The report lists totals and dates. ", 3)}
			}
			payload := map[string]any{"parts": parts}
			messages := 1
			if count == 2000 {
				var history []any
				for i := 0; i < count; i += 10 {
					history = append(history, map[string]any{"role": "user", "parts": parts[i : i+10]})
				}
				payload = map[string]any{"history": history}
				messages = len(history)
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			v := ScanA2AResponseBody(t.Context(), body, sc, cfg)
			t.Logf("messages=%d parts=%d bytes=%d elapsed=%s clean=%t action=%s overflow=%t", messages, count, len(body), time.Since(start), v.Clean, v.Action, v.BudgetExceeded)
			if len(v.InjectFindings) != 0 || len(v.DLPFindings) != 0 || v.ScanError != "" || v.InspectionIncomplete || !v.Clean && (!v.BudgetExceeded || v.Action != config.ActionWarn) {
				t.Fatal("benign multipart corpus acquired a security finding or incomplete scan")
			}
		})
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestA2AResponseJoinsTextAndEnvelope(t *testing.T) {
	for _, method := range []string{"SendMessage", "GetExtendedAgentCard"} {
		for kind, halves := range joinedViewSplits() {
			t.Run(method+"/"+kind, func(t *testing.T) {
				cfg := enabledA2ACfg()
				cfg.Action = config.ActionWarn
				sc := testScannerWithAction(t, config.ActionBlock)
				result := map[string]any{"content": []any{map[string]any{"type": "text", "text": halves[0]}}}
				if method == "GetExtendedAgentCard" {
					result["skills"], result["supportedInterfaces"] = []any{}, []any{}
				}
				line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result, "_meta": halves[1]})
				if err != nil {
					t.Fatal(err)
				}
				v := ScanResponseA2A(line, sc, &A2AResponseOpts{Cfg: cfg, Method: method})
				if kind == "benign" {
					if !v.Clean {
						t.Fatalf("benign joined response was flagged: action=%s error=%s", v.Action, v.Error)
					}
					return
				}
				if v.Clean || v.Action != config.ActionBlock {
					t.Fatalf("joined %s not blocked: clean=%t action=%s", kind, v.Clean, v.Action)
				}
				tracker := NewRequestTracker()
				tracker.TrackRequest(json.RawMessage(`1`), method)
				out, _, found := forwardA2AResponseTracked(t, string(line), MCPProxyOpts{Scanner: sc, A2ACfg: cfg}, tracker)
				if !found || strings.Contains(out, `"result"`) {
					t.Fatal("joined finding was forwarded on stdio")
				}
			})
		}
	}
}

func TestA2AResponseRetainsMediaInspection(t *testing.T) {
	for _, method := range []string{"SendMessage", "GetExtendedAgentCard"} {
		for _, benign := range []bool{false, true} {
			name, text := "finding", mediaInstruction
			if benign {
				name, text = "benign", mediaBenignNote
			}
			t.Run(method+"/"+name, func(t *testing.T) {
				cfg := enabledA2ACfg()
				cfg.Action = config.ActionWarn
				sc := testScannerWithAction(t, config.ActionBlock)
				data := base64.StdEncoding.EncodeToString(append(mediaPNGHeader(), mediaInterleaved(text, 1)...))
				line := []byte(makeMediaResponse(data))
				v := ScanResponseA2A(line, sc, &A2AResponseOpts{Cfg: cfg, Method: method})
				if v.Clean != benign || !benign && (v.Action != config.ActionBlock || len(v.Matches) == 0) {
					t.Fatalf("media inspection lost: benign=%t clean=%t action=%s", benign, v.Clean, v.Action)
				}
			})
		}
	}
}

func TestA2AJoinedFindingPreservesCardBaseline(t *testing.T) {
	cfg := enabledA2ACfg()
	cfg.DetectCardDrift = true
	baseline := NewCardBaseline(4)
	sc := testScannerWithAction(t, config.ActionBlock)
	opts := &A2AResponseOpts{Cfg: cfg, Method: "GetExtendedAgentCard", Baseline: baseline}
	halves := joinedViewSplits()["injection"]
	dirty := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + halves[0] + `"}],"skills":[],"supportedInterfaces":[]},"_meta":"` + halves[1] + `"}`)
	clean := []byte(`{"jsonrpc":"2.0","id":1,"result":{"description":"A peer agent","skills":[],"supportedInterfaces":[]}}`)
	for _, line := range [][]byte{dirty, clean, dirty, clean} {
		isClean := string(line) == string(clean)
		before := len(baseline.entries)
		v := ScanResponseA2A(line, sc, opts)
		if v.Clean != isClean {
			t.Fatalf("unexpected state transition: clean=%t want=%t", v.Clean, isClean)
		}
		if !isClean && len(baseline.entries) != before {
			t.Fatal("joined finding established a trusted baseline")
		}
		if isClean && len(baseline.entries) != 1 {
			t.Fatal("clean card did not establish a baseline")
		}
	}
}

func TestA2AResponseRetainsMessageBound(t *testing.T) {
	cfg := enabledA2ACfg()
	sc := testScannerWithAction(t, config.ActionWarn)
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"text":"` + strings.Repeat(" ", transport.MaxLineSize) + `"}}`)
	v := ScanResponseA2A(line, sc, &A2AResponseOpts{Cfg: cfg, Method: "SendMessage"})
	if v.Clean || v.Action != config.ActionBlock || v.Error == "" {
		t.Fatal("uninspectable message did not block")
	}
}

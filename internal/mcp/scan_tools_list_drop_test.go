// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The tools/list sibling-field scan drops findings on two paths: a response
// pattern the operator suppressed for this server, and a low-confidence
// inbound access-key match. Both must reach the drop callbacks while the
// verdict stays clean, and neither callback may change the verdict.
func TestScanToolsListNonToolFields_RecordsDroppedFindings(t *testing.T) {
	sc := testScanner(t)
	lowConfidenceAWS := strings.Join([]string{
		"AIDA", "in", "product", "name", "generated", "by", "random",
		"OCR", "context", "for", "assistant", "safety", "review",
	}, " ")

	// Discover the non-core pattern name the fixture trips so the suppress
	// entry names exactly what production would.
	base := ScanResponse(suppressResponse(1), sc)
	if base.Clean || len(base.Matches) == 0 {
		t.Fatal("baseline response must block before suppression")
	}
	patternName := base.Matches[0].PatternName

	note, err := json.Marshal(nonCoreResponseFinding + " " + lowConfidenceAWS)
	if err != nil {
		t.Fatalf("marshal note: %v", err)
	}
	line := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t1"}],"note":` + string(note) + `}}`

	const target = "mcp://code-assistant/response"
	suppress := []config.SuppressEntry{{Rule: patternName, Path: target}}

	// Unobserved: the drops happen and the verdict is clean.
	unobserved := scanToolsListNonToolFields([]byte(line), sc, ResponseScanOptions{Target: target, Suppress: suppress})
	if !unobserved.Clean {
		t.Fatalf("unobserved verdict = %+v, want clean", unobserved)
	}

	var suppressed []string
	var dropped []string
	opts := ResponseScanOptions{
		Target:   target,
		Suppress: suppress,
		OnSuppressedResponse: func(m scanner.ResponseMatch) {
			suppressed = append(suppressed, m.PatternName)
		},
		OnDroppedDLP: func(m scanner.TextDLPMatch, reason string) {
			dropped = append(dropped, m.PatternName+"/"+reason)
		},
	}
	observed := scanToolsListNonToolFields([]byte(line), sc, opts)
	if !observed.Clean {
		t.Fatalf("observed verdict = %+v, want clean", observed)
	}
	if len(suppressed) != 1 || suppressed[0] != patternName {
		t.Fatalf("suppressed callbacks = %v, want exactly [%s]", suppressed, patternName)
	}
	if len(dropped) != 1 || dropped[0] != "AWS Access ID/low_confidence" {
		t.Fatalf("dropped callbacks = %v, want exactly [AWS Access ID/low_confidence]", dropped)
	}

	// Without the suppress entry the same sibling field still blocks: the
	// record path never widened the allow.
	if v := scanToolsListNonToolFields([]byte(line), sc, ResponseScanOptions{Target: target}); v.Clean {
		t.Fatal("unsuppressed sibling finding must still block")
	}
}

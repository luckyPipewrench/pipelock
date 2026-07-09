// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestRenderSingleAgentHTML(t *testing.T) {
	fixedTime := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

	_, priv := generateTestKey(t)
	chain := buildTestChain(t, priv, 1)

	ev := SessionEvidenceOf("sess-1", chain, nil, false, 5000, 500)
	exps := []DecisionExplanation{ExplainReceipt(ev.Receipts[0])}

	var buf bytes.Buffer
	err := RenderSingleAgentHTML(&buf, ev, exps, RenderOptions{
		Title:       "Test Report",
		GeneratedAt: fixedTime,
	})
	if err != nil {
		t.Fatalf("RenderSingleAgentHTML error: %v", err)
	}

	html := buf.String()

	// Must contain key structural elements.
	for _, want := range []string{
		"<title>Test Report</title>",
		"Evidence Scorecard",
		"Each line is independently evaluated",
		"Timeline",
		"2026-07-08T12:00:00Z",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing expected content: %q", want)
		}
	}

	// Must be self-contained: no external asset references.
	for _, banned := range []string{
		`src="http`,
		`href="http`,
		`<link rel="stylesheet"`,
		`<script src`,
	} {
		if strings.Contains(html, banned) {
			t.Errorf("HTML contains external asset reference: %q", banned)
		}
	}

	// Must NOT contain aggregate-green wording (bounded-claims discipline).
	aggregateBanned := []string{
		"all checks passed",
		"everything verified",
		"system healthy",
		"all clear",
		"fully verified",
	}
	lowerHTML := strings.ToLower(html)
	for _, banned := range aggregateBanned {
		if strings.Contains(lowerHTML, banned) {
			t.Errorf("HTML contains banned aggregate wording: %q", banned)
		}
	}
}

func TestRenderSingleAgentHTML_EmptyEvidence(t *testing.T) {
	fixedTime := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	ev := SessionEvidenceOf("sess-empty", nil, nil, false, 5000, 500)

	var buf bytes.Buffer
	err := RenderSingleAgentHTML(&buf, ev, nil, RenderOptions{
		GeneratedAt: fixedTime,
	})
	if err != nil {
		t.Fatalf("RenderSingleAgentHTML error: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "Pipelock Evidence Report") {
		t.Error("default title not present")
	}
	if !strings.Contains(html, "ABSENT") {
		t.Error("absent scorecard chip not present")
	}
}

func TestRenderSingleAgentHTML_HTMLEscapesAttackerContent(t *testing.T) {
	fixedTime := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

	// Attacker-controlled content in Pattern/Target must be HTML-escaped.
	xssPayload := `<script>alert("xss")</script>`

	_, priv := generateTestKey(t)
	ar := receipt.ActionRecord{
		Version:         1,
		ActionID:        "act-xss",
		ActionType:      receipt.ActionRead,
		Timestamp:       fixedTime,
		Target:          xssPayload,
		Verdict:         "block",
		Transport:       "forward",
		Layer:           "dlp",
		Pattern:         xssPayload,
		Severity:        "high",
		PolicyHash:      "test-policy",
		SideEffectClass: receipt.SideEffectNone,
		Reversibility:   receipt.ReversibilityFull,
		ChainSeq:        0,
		ChainPrevHash:   receipt.GenesisHash,
	}
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ev := SessionEvidenceOf("sess-xss", []receipt.Receipt{r}, nil, false, 5000, 500)
	exps := []DecisionExplanation{ExplainReceipt(ev.Receipts[0])}

	var buf bytes.Buffer
	err = RenderSingleAgentHTML(&buf, ev, exps, RenderOptions{
		GeneratedAt: fixedTime,
	})
	if err != nil {
		t.Fatalf("RenderSingleAgentHTML error: %v", err)
	}
	html := buf.String()

	// The raw XSS payload must NOT appear unescaped.
	if strings.Contains(html, xssPayload) {
		t.Error("attacker XSS payload was NOT HTML-escaped in rendered output")
	}
	// The escaped form must be present.
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected HTML-escaped script tag in output")
	}
}

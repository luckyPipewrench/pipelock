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

func TestRenderSingleAgentHTML_OperatorConsoleThemeAndHonestScorecard(t *testing.T) {
	fixedTime := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	_, priv := generateTestKey(t)
	chain := buildTestChain(t, priv, 1)
	ev := SessionEvidenceOf("sess-theme", chain, nil, false, 5000, 500)

	var buf bytes.Buffer
	err := RenderSingleAgentHTML(&buf, ev, nil, RenderOptions{
		GeneratedAt: fixedTime,
	})
	if err != nil {
		t.Fatalf("RenderSingleAgentHTML error: %v", err)
	}
	html := buf.String()

	for _, want := range []string{
		`--accent:#00e5a0`,
		`--bg:#09090b`,
		`Pipelock <span>&middot; Operator Console / Evidence Report</span>`,
		`READ-ONLY`,
		`class="scorecard"`,
		`class="section"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing operator-console theme marker: %q", want)
		}
	}

	for _, want := range []string{
		"Unverified",
		"Authentic",
		"Chain intact",
		"Untampered",
		"Not anchored",
		"Anchored",
		"Boundary-limited",
		"Completeness",
		"Each line is independently evaluated. There is no aggregate status.",
		"Import the signer key from an operator-controlled source to upgrade this line.",
		"Every receipt links to the previous receipt hash.",
		"Add an external inclusion proof before treating ordering as independently anchored.",
		"Cannot prove that no unmediated action occurred outside the boundary.",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing honest scorecard content: %q", want)
		}
	}

	for _, banned := range []string{
		"aggregate healthy",
		"aggregate verified",
		"aggregate complete",
		"verified complete",
		"healthy",
	} {
		if strings.Contains(strings.ToLower(html), banned) {
			t.Errorf("HTML contains banned aggregate wording: %q", banned)
		}
	}
	for _, notWant := range []string{"Decision Detail", `class="explanation"`} {
		if strings.Contains(html, notWant) {
			t.Errorf("HTML should not contain %q when Explanations is nil", notWant)
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

func TestRenderSingleAgentHTML_EscapesEveryTemplateDataSurface(t *testing.T) {
	fixedTime := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	scriptPayload := `<script>alert("xss")</script>`
	imagePayload := `"><img src=x onerror=alert(1)>`
	assetPayload := `"><link rel="stylesheet" href="https://evil.example/x.css"><script src="https://evil.example/x.js"></script>`

	ev := SessionEvidence{
		ID:              "sess-" + imagePayload,
		Agent:           "agent-" + scriptPayload,
		ReceiptsEnabled: true,
		ReceiptCount:    1,
		Scorecard: Scorecard{
			Authentic: Line{
				State:  StateWarn,
				Chip:   "Signer " + imagePayload,
				Detail: "Signer key " + scriptPayload + " is not in the trusted-key set.",
				Sub:    "Source " + assetPayload,
			},
			Untampered: Line{
				State:  StateFail,
				Chip:   "Reason " + scriptPayload,
				Detail: "Receipt reason " + imagePayload,
				Sub:    "Block reason " + scriptPayload,
			},
			Anchored: Line{
				State:  StateWarn,
				Chip:   "Anchor " + imagePayload,
				Detail: "Destination " + scriptPayload,
				Sub:    "Proof " + imagePayload,
			},
			Completeness: Line{
				State:  StateLimited,
				Chip:   "Boundary " + scriptPayload,
				Detail: "Session " + imagePayload,
				Sub:    "Agent " + scriptPayload,
			},
		},
		Timeline: []TimelineItem{
			{
				Seq:          7,
				Time:         fixedTime,
				Verdict:      "block " + scriptPayload,
				Reason:       "dlp / " + imagePayload,
				PrevShort:    "prev-" + scriptPayload,
				HashShort:    "hash-" + imagePayload,
				Unverifiable: true,
			},
		},
	}
	explanations := []DecisionExplanation{
		{
			Verdict:     ExplanationField{Present: true, Label: "Verdict", Detail: "block " + scriptPayload},
			ChainSeq:    ExplanationField{Present: true, Label: "Chain Seq", Detail: "7 " + imagePayload},
			Pattern:     ExplanationField{Present: true, Label: "Pattern", Detail: "pattern " + scriptPayload},
			TaintReason: ExplanationField{Present: true, Label: "Taint Decision Reason", Detail: "taint " + imagePayload},
			Target:      ExplanationField{Present: true, Label: "Target", Detail: "https://api.vendor.example/" + assetPayload},
			Actor:       ExplanationField{Present: true, Label: "Actor", Detail: "actor " + scriptPayload},
			Principal:   ExplanationField{Present: true, Label: "Principal", Detail: "principal " + imagePayload},
		},
	}

	var buf bytes.Buffer
	if err := RenderSingleAgentHTML(&buf, ev, explanations, RenderOptions{
		Title:       "Title " + scriptPayload,
		GeneratedAt: fixedTime,
	}); err != nil {
		t.Fatalf("RenderSingleAgentHTML error: %v", err)
	}
	html := buf.String()

	for _, raw := range []string{scriptPayload, imagePayload, assetPayload} {
		if strings.Contains(html, raw) {
			t.Fatalf("rendered HTML contains unescaped attacker payload %q: %s", raw, html)
		}
	}
	for _, escaped := range []string{
		"&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;",
		"&#34;&gt;&lt;img src=x onerror=alert(1)&gt;",
		"&lt;link rel=&#34;stylesheet&#34; href=&#34;https://evil.example/x.css&#34;&gt;",
	} {
		if !strings.Contains(html, escaped) {
			t.Fatalf("rendered HTML missing escaped payload %q: %s", escaped, html)
		}
	}
	for _, banned := range []string{
		`<script`,
		`<img`,
		`<link rel="stylesheet"`,
		`src="https://evil.example`,
		`href="https://evil.example`,
	} {
		if strings.Contains(html, banned) {
			t.Fatalf("rendered HTML contains executable/external asset surface %q: %s", banned, html)
		}
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxydecision

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const testSpanDigest = "sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const testRedactedSourceSpanValue = "[redacted-value]"

// captureRecorder records entries in memory so tests can extract the signed
// receipt JSON and verify it offline.
type captureRecorder struct {
	entries []recorder.Entry
	err     error
}

func (c *captureRecorder) Record(e recorder.Entry) error {
	if c.err != nil {
		return c.err
	}
	c.entries = append(c.entries, e)
	return nil
}

func newTestEmitter(t *testing.T, rec Recorder, sanitize SanitizeFunc) (*Emitter, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := NewKeyedSigner(priv)
	em := NewEmitter(EmitterConfig{
		Recorder:  rec,
		Signer:    signer,
		Sanitize:  sanitize,
		Principal: "local",
		Actor:     "pipelock",
	})
	if em == nil {
		t.Fatal("NewEmitter returned nil for a valid config")
	}
	return em, pub, signer.KeyID()
}

// decodeReceipt extracts the signed EvidenceReceipt from a recorded entry.
func decodeReceipt(t *testing.T, e recorder.Entry) contractreceipt.EvidenceReceipt {
	t.Helper()
	raw, ok := e.Detail.(json.RawMessage)
	if !ok {
		t.Fatalf("entry Detail is %T, want json.RawMessage", e.Detail)
	}
	var rcpt contractreceipt.EvidenceReceipt
	if err := json.Unmarshal(raw, &rcpt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	return rcpt
}

func decodePayload(t *testing.T, rcpt contractreceipt.EvidenceReceipt) contractreceipt.PayloadProxyDecisionStruct {
	t.Helper()
	var p contractreceipt.PayloadProxyDecisionStruct
	if err := json.Unmarshal(rcpt.Payload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return p
}

func decodeSpannedPayload(t *testing.T, rcpt contractreceipt.EvidenceReceipt) contractreceipt.PayloadProxyDecisionWithSpansStruct {
	t.Helper()
	var p contractreceipt.PayloadProxyDecisionWithSpansStruct
	if err := json.Unmarshal(rcpt.Payload, &p); err != nil {
		t.Fatalf("unmarshal spanned payload: %v", err)
	}
	return p
}

func spannedEvidenceFixture() []contractruntime.SourceSpanEvidence {
	offset, length := 9, len(testRedactedSourceSpanValue)
	return []contractruntime.SourceSpanEvidence{{
		Span: contractreceipt.SourceSpan{
			SourceID:             "req-1",
			SourceKind:           contractreceipt.SourceKindMCPToolArgs,
			NormalizedView:       contractreceipt.NormalizedViewDLPNormalized,
			PipelockBinaryDigest: testSpanDigest,
			RulesBundleDigest:    testSpanDigest,
			TransformProfile:     "nfkc+zero-width-strip",
			PolicyHash:           testSpanDigest,
			RuleID:               "aws_access_key",
			Bundle:               "builtin",
			BundleVersion:        "2026.06.05",
			CharOffset:           &offset,
			CharLength:           &length,
			MatchClass:           "secret:aws_access_key",
			RedactedSample:       testRedactedSourceSpanValue,
		},
		MatchValue: testRedactedSourceSpanValue,
	}}
}

func TestEmit_BuildsVerifiableReceipt(t *testing.T) {
	rec := &captureRecorder{}
	em, pub, keyID := newTestEmitter(t, rec, nil)

	err := em.Emit(Decision{
		ActionType:    "http_request",
		Transport:     "forward",
		Target:        "https://api.vendor.example/v1/things",
		Verdict:       "block",
		WinningSource: SourceScanner,
		PolicySources: []string{SourceScanner},
		RuleID:        "prompt_injection",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(rec.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(rec.entries))
	}
	entry := rec.entries[0]
	if entry.Type != evidenceReceiptEntryType {
		t.Errorf("entry Type = %q, want %q", entry.Type, evidenceReceiptEntryType)
	}
	if entry.EventKind != string(contractreceipt.PayloadProxyDecision) {
		t.Errorf("entry EventKind = %q, want %q", entry.EventKind, contractreceipt.PayloadProxyDecision)
	}
	if entry.Transport != "forward" {
		t.Errorf("entry Transport = %q, want forward", entry.Transport)
	}

	rcpt := decodeReceipt(t, entry)
	// The Bundle A done-state: v2 proxy_decision verifies offline in Go.
	if err := contractreceipt.VerifyWithKey(rcpt, pub, keyID); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	if rcpt.RecordType != contractreceipt.RecordTypeEvidenceV2 {
		t.Errorf("RecordType = %q", rcpt.RecordType)
	}
	if rcpt.PayloadKind != contractreceipt.PayloadProxyDecision {
		t.Errorf("PayloadKind = %q", rcpt.PayloadKind)
	}
	if rcpt.ChainSeq != 0 {
		t.Errorf("ChainSeq = %d, want 0", rcpt.ChainSeq)
	}
	if rcpt.ChainPrevHash != recorder.GenesisHash {
		t.Errorf("ChainPrevHash = %q, want %q", rcpt.ChainPrevHash, recorder.GenesisHash)
	}

	p := decodePayload(t, rcpt)
	if p.ActionType != "http_request" || p.Verdict != "block" || p.Transport != "forward" {
		t.Errorf("payload core fields wrong: %+v", p)
	}
	if p.WinningSource != SourceScanner || len(p.PolicySources) != 1 || p.PolicySources[0] != SourceScanner {
		t.Errorf("payload provenance wrong: winning=%q sources=%v", p.WinningSource, p.PolicySources)
	}
	if p.RuleID != "prompt_injection" {
		t.Errorf("payload RuleID = %q", p.RuleID)
	}
}

func TestEmit_WithSpansBuildsVerifiableReceipt(t *testing.T) {
	rec := &captureRecorder{}
	em, pub, keyID := newTestEmitter(t, rec, nil)

	evidence := spannedEvidenceFixture()

	err := em.Emit(Decision{
		ActionType:         "mcp_tool_call",
		Transport:          "mcp_stdio",
		Target:             "tool://example/list",
		Verdict:            "block",
		WinningSource:      SourceScanner,
		PolicySources:      []string{SourceScanner},
		RuleID:             "aws_access_key",
		SpanHMACKey:        []byte("span-mac-key"),
		SourceSpanEvidence: evidence,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(rec.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(rec.entries))
	}
	entry := rec.entries[0]
	if entry.EventKind != string(contractreceipt.PayloadProxyDecisionWithSpans) {
		t.Fatalf("entry EventKind = %q, want %q", entry.EventKind, contractreceipt.PayloadProxyDecisionWithSpans)
	}
	if !strings.HasPrefix(entry.Summary, string(contractreceipt.PayloadProxyDecisionWithSpans)+":") {
		t.Fatalf("entry Summary = %q, want spanned payload kind prefix", entry.Summary)
	}

	rcpt := decodeReceipt(t, entry)
	if rcpt.PayloadKind != contractreceipt.PayloadProxyDecisionWithSpans {
		t.Fatalf("PayloadKind = %q, want %q", rcpt.PayloadKind, contractreceipt.PayloadProxyDecisionWithSpans)
	}
	if err := contractreceipt.VerifyWithKey(rcpt, pub, keyID); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	payload := decodeSpannedPayload(t, rcpt)
	if len(payload.SourceSpans) != 1 {
		t.Fatalf("source_spans length = %d, want 1", len(payload.SourceSpans))
	}
	span := payload.SourceSpans[0]
	wantHash, err := contractreceipt.SourceSpanMatchHash([]byte("span-mac-key"), rcpt.EventID, 0, span, testRedactedSourceSpanValue)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash: %v", err)
	}
	if span.MatchHash != wantHash {
		t.Fatalf("MatchHash = %q, want event_id-bound hash %q", span.MatchHash, wantHash)
	}
	if span.RedactedSample != testRedactedSourceSpanValue {
		t.Fatalf("RedactedSample = %q, want %q", span.RedactedSample, testRedactedSourceSpanValue)
	}
}

func TestEmit_WithSpansRejectsMalformedEvidenceBeforeRecording(t *testing.T) {
	rec := &captureRecorder{}
	em, _, _ := newTestEmitter(t, rec, nil)
	evidence := spannedEvidenceFixture()
	evidence[0].Span.SourceKind = "bogus"

	err := em.Emit(Decision{
		ActionType:         "mcp_tool_call",
		Transport:          "mcp_stdio",
		Target:             "tool://example/list",
		Verdict:            "block",
		WinningSource:      SourceScanner,
		PolicySources:      []string{SourceScanner},
		RuleID:             "aws_access_key",
		SpanHMACKey:        []byte("span-mac-key"),
		SourceSpanEvidence: evidence,
	})
	if !errors.Is(err, contractruntime.ErrInvalidProxyDecisionInput) {
		t.Fatalf("Emit err = %v, want ErrInvalidProxyDecisionInput", err)
	}
	if len(rec.entries) != 0 {
		t.Fatalf("recorded %d entries despite malformed source span", len(rec.entries))
	}
	if seq, _ := em.ChainState(); seq != 0 {
		t.Fatalf("chain advanced to %d despite malformed source span", seq)
	}
}

func TestEmit_WithSpansSanitizesSpanFieldsBeforeSigning(t *testing.T) {
	const secret = "AKIA" + "IOSFODNN7EXAMPLE"
	// Active DLP redaction: clean reports false for any text containing the
	// secret. A caller mistake puts raw matched bytes into "redacted" span
	// fields; the emitter must scrub them out of the SIGNED spanned payload,
	// exactly as it does for target/rule_id (#676).
	clean := func(text string) bool { return !strings.Contains(text, secret) }

	rec := &captureRecorder{}
	em, pub, keyID := newTestEmitter(t, rec, clean)

	evidence := spannedEvidenceFixture()
	evidence[0].Span.SourceID = "source:" + secret
	evidence[0].Span.RedactedSample = "sample:" + secret
	evidence[0].Span.RuleID = "dlp:" + secret
	evidence[0].Span.MatchClass = "class:" + secret

	err := em.Emit(Decision{
		ActionType:         "mcp_tool_call",
		Transport:          "mcp_stdio",
		Target:             "tool://example/list",
		Verdict:            "block",
		WinningSource:      SourceScanner,
		PolicySources:      []string{SourceScanner},
		RuleID:             "aws_access_key",
		SpanHMACKey:        []byte("span-mac-key"),
		SourceSpanEvidence: evidence,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	rcpt := decodeReceipt(t, rec.entries[0])
	if rcpt.PayloadKind != contractreceipt.PayloadProxyDecisionWithSpans {
		t.Fatalf("PayloadKind = %q, want %q", rcpt.PayloadKind, contractreceipt.PayloadProxyDecisionWithSpans)
	}
	// The signed receipt must still verify after pre-sign sanitization.
	if err := contractreceipt.VerifyWithKey(rcpt, pub, keyID); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	// The whole serialized receipt must be free of the secret.
	full, err := json.Marshal(rcpt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	if strings.Contains(string(full), secret) {
		t.Fatalf("serialized spanned receipt leaks secret: %s", full)
	}
	span := decodeSpannedPayload(t, rcpt).SourceSpans[0]
	if strings.Contains(span.RedactedSample, secret) {
		t.Errorf("signed RedactedSample leaks secret: %q", span.RedactedSample)
	}
	if strings.Contains(span.RuleID, secret) {
		t.Errorf("signed span RuleID leaks secret: %q", span.RuleID)
	}
	if strings.Contains(span.MatchClass, secret) {
		t.Errorf("signed span MatchClass leaks secret: %q", span.MatchClass)
	}
	wantHash, err := contractreceipt.SourceSpanMatchHash([]byte("span-mac-key"), rcpt.EventID, 0, span, testRedactedSourceSpanValue)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash: %v", err)
	}
	if span.MatchHash != wantHash {
		t.Fatalf("MatchHash = %q, want sanitized RuleID-bound hash %q", span.MatchHash, wantHash)
	}
	// The caller's evidence slice must not be mutated by sanitization.
	if evidence[0].Span.SourceID != "source:"+secret {
		t.Errorf("emitter mutated caller evidence SourceID: %q", evidence[0].Span.SourceID)
	}
	if evidence[0].Span.RedactedSample != "sample:"+secret {
		t.Errorf("emitter mutated caller evidence RedactedSample: %q", evidence[0].Span.RedactedSample)
	}
	if evidence[0].Span.RuleID != "dlp:"+secret {
		t.Errorf("emitter mutated caller evidence RuleID: %q", evidence[0].Span.RuleID)
	}
	if evidence[0].Span.MatchClass != "class:"+secret {
		t.Errorf("emitter mutated caller evidence MatchClass: %q", evidence[0].Span.MatchClass)
	}
}

func TestEmit_WithSpansRejectsMissingHMACKey(t *testing.T) {
	rec := &captureRecorder{}
	em, _, _ := newTestEmitter(t, rec, nil)

	err := em.Emit(Decision{
		ActionType:         "mcp_tool_call",
		Transport:          "mcp_stdio",
		Target:             "tool://example/list",
		Verdict:            "block",
		WinningSource:      SourceScanner,
		PolicySources:      []string{SourceScanner},
		RuleID:             "aws_access_key",
		SpanHMACKey:        nil, // evidence present but no key
		SourceSpanEvidence: spannedEvidenceFixture(),
	})
	if !errors.Is(err, contractruntime.ErrInvalidProxyDecisionInput) {
		t.Fatalf("Emit err = %v, want ErrInvalidProxyDecisionInput", err)
	}
	if len(rec.entries) != 0 {
		t.Fatalf("recorded %d entries despite missing span HMAC key", len(rec.entries))
	}
	if seq, _ := em.ChainState(); seq != 0 {
		t.Fatalf("chain advanced to %d despite missing span HMAC key", seq)
	}
}

func TestEmit_SanitizesTargetBeforeSigning(t *testing.T) {
	const secret = "AKIA" + "IOSFODNN7EXAMPLE"
	// clean reports false for any text containing the secret, mirroring a DLP
	// hit. The emitter must scrub the secret out of the SIGNED target.
	clean := func(text string) bool { return !strings.Contains(text, secret) }

	rec := &captureRecorder{}
	em, pub, keyID := newTestEmitter(t, rec, clean)

	rawTarget := "https://api.vendor.example/v1/items?key=" + secret
	err := em.Emit(Decision{
		ActionType:    "http_request",
		Transport:     "forward",
		Target:        rawTarget,
		Verdict:       "block",
		WinningSource: SourceScanner,
		PolicySources: []string{SourceScanner},
		RuleID:        "dlp:" + secret, // rule label echoing the matched bytes
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	rcpt := decodeReceipt(t, rec.entries[0])
	if err := contractreceipt.VerifyWithKey(rcpt, pub, keyID); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	p := decodePayload(t, rcpt)
	if strings.Contains(p.Target, secret) {
		t.Errorf("signed target leaks secret: %q", p.Target)
	}
	if strings.Contains(p.RuleID, secret) {
		t.Errorf("signed rule_id leaks secret: %q", p.RuleID)
	}
	// The whole serialized receipt must be free of the secret.
	if strings.Contains(string(rcpt.Payload), secret) {
		t.Errorf("serialized payload leaks secret: %s", rcpt.Payload)
	}
}

func TestEmit_ProvenanceShapes(t *testing.T) {
	tests := []struct {
		name        string
		decision    Decision
		wantWinning string
		wantSources []string
		wantStamped bool
	}{
		{
			name: "scanner block",
			decision: Decision{
				ActionType: "http_request", Transport: "fetch", Target: "https://x.example/a",
				Verdict: "block", WinningSource: SourceScanner, PolicySources: []string{SourceScanner},
				RuleID: "ssrf",
			},
			wantWinning: SourceScanner, wantSources: []string{SourceScanner}, wantStamped: false,
		},
		{
			name: "kill switch",
			decision: Decision{
				ActionType: "http_request", Transport: "intercept", Target: "https://x.example/b",
				Verdict: "block", WinningSource: SourceKillSwitch, PolicySources: []string{SourceKillSwitch},
				RuleID: "kill_switch_active",
			},
			wantWinning: SourceKillSwitch, wantSources: []string{SourceKillSwitch}, wantStamped: false,
		},
		{
			name: "contract decision stamps envelope",
			decision: Decision{
				ActionType: "http_request", Transport: "forward", Target: "https://x.example/c",
				Verdict: "block", WinningSource: SourceContract,
				PolicySources:      []string{"observation", SourceContract},
				RuleID:             "rule-42",
				ActiveManifestHash: "sha256:manifest", ContractHash: "sha256:contract",
				SelectorID: "sel-1", ContractGeneration: 7,
			},
			wantWinning: SourceContract, wantSources: []string{"observation", SourceContract}, wantStamped: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &captureRecorder{}
			em, pub, keyID := newTestEmitter(t, rec, nil)
			if err := em.Emit(tc.decision); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			rcpt := decodeReceipt(t, rec.entries[0])
			if err := contractreceipt.VerifyWithKey(rcpt, pub, keyID); err != nil {
				t.Fatalf("VerifyWithKey: %v", err)
			}
			p := decodePayload(t, rcpt)
			if p.WinningSource != tc.wantWinning {
				t.Errorf("winning_source = %q, want %q", p.WinningSource, tc.wantWinning)
			}
			if strings.Join(p.PolicySources, ",") != strings.Join(tc.wantSources, ",") {
				t.Errorf("policy_sources = %v, want %v", p.PolicySources, tc.wantSources)
			}
			gotStamped := rcpt.ActiveManifestHash != "" || rcpt.ContractHash != "" ||
				rcpt.SelectorID != "" || rcpt.ContractGeneration != 0
			if gotStamped != tc.wantStamped {
				t.Errorf("envelope stamped = %v, want %v (manifest=%q contract=%q selector=%q gen=%d)",
					gotStamped, tc.wantStamped, rcpt.ActiveManifestHash, rcpt.ContractHash,
					rcpt.SelectorID, rcpt.ContractGeneration)
			}
			if tc.wantStamped {
				if rcpt.ActiveManifestHash != tc.decision.ActiveManifestHash ||
					rcpt.ContractHash != tc.decision.ContractHash ||
					rcpt.SelectorID != tc.decision.SelectorID ||
					rcpt.ContractGeneration != tc.decision.ContractGeneration {
					t.Errorf("stamped envelope mismatch: %+v", rcpt)
				}
			}
		})
	}
}

func TestEmit_ChainAdvancesAndLinks(t *testing.T) {
	rec := &captureRecorder{}
	em, _, _ := newTestEmitter(t, rec, nil)
	base := Decision{
		ActionType: "http_request", Transport: "forward", Target: "https://x.example/a",
		Verdict: "allow", WinningSource: SourceScanner, PolicySources: []string{SourceScanner},
	}
	for i := 0; i < 3; i++ {
		if err := em.Emit(base); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if len(rec.entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(rec.entries))
	}
	var prevHash string
	for i, e := range rec.entries {
		rcpt := decodeReceipt(t, e)
		if rcpt.ChainSeq != uint64(i) {
			t.Errorf("entry %d ChainSeq = %d, want %d", i, rcpt.ChainSeq, i)
		}
		if i == 0 {
			if rcpt.ChainPrevHash != recorder.GenesisHash {
				t.Errorf("first ChainPrevHash = %q, want genesis", rcpt.ChainPrevHash)
			}
		} else if rcpt.ChainPrevHash != prevHash {
			t.Errorf("entry %d ChainPrevHash = %q, want %q", i, rcpt.ChainPrevHash, prevHash)
		}
		h, err := contractreceipt.ReceiptHash(rcpt)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		prevHash = h
	}
	seq, head := em.ChainState()
	if seq != 3 || head != prevHash {
		t.Errorf("ChainState = (%d,%q), want (3,%q)", seq, head, prevHash)
	}
}

func TestEmit_ResumeContinuity(t *testing.T) {
	// First emitter produces one receipt, then we capture its head and build a
	// replacement (as a hot reload would) seeded with ResumeSeq/ResumePrevHash.
	rec := &captureRecorder{}
	em1, _, _ := newTestEmitter(t, rec, nil)
	base := Decision{
		ActionType: "http_request", Transport: "forward", Target: "https://x.example/a",
		Verdict: "allow", WinningSource: SourceScanner, PolicySources: []string{SourceScanner},
	}
	if err := em1.Emit(base); err != nil {
		t.Fatalf("Emit em1: %v", err)
	}
	seq, head := em1.ChainState()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewKeyedSigner(priv)
	em2 := NewEmitter(EmitterConfig{
		Recorder: rec, Signer: signer, Principal: "local", Actor: "pipelock",
		ResumeSeq: seq, ResumePrevHash: head,
	})
	if err := em2.Emit(base); err != nil {
		t.Fatalf("Emit em2: %v", err)
	}
	rcpt := decodeReceipt(t, rec.entries[1])
	if err := contractreceipt.VerifyWithKey(rcpt, pub, signer.KeyID()); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	if rcpt.ChainSeq != seq {
		t.Errorf("resumed ChainSeq = %d, want %d", rcpt.ChainSeq, seq)
	}
	if rcpt.ChainPrevHash != head {
		t.Errorf("resumed ChainPrevHash = %q, want %q", rcpt.ChainPrevHash, head)
	}
}

func TestEmit_TamperBreaksSignature(t *testing.T) {
	rec := &captureRecorder{}
	em, pub, keyID := newTestEmitter(t, rec, nil)
	if err := em.Emit(Decision{
		ActionType: "http_request", Transport: "forward", Target: "https://x.example/a",
		Verdict: "allow", WinningSource: SourceScanner, PolicySources: []string{SourceScanner},
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	rcpt := decodeReceipt(t, rec.entries[0])
	if err := contractreceipt.VerifyWithKey(rcpt, pub, keyID); err != nil {
		t.Fatalf("baseline VerifyWithKey: %v", err)
	}
	// Flip a payload field; the JCS preimage changes, so verification must fail.
	tampered := rcpt
	tampered.Payload = json.RawMessage(strings.Replace(string(rcpt.Payload), `"allow"`, `"forward"`, 1))
	if err := contractreceipt.VerifyWithKey(tampered, pub, keyID); err == nil {
		t.Fatal("tampered receipt verified; signature did not bind payload")
	}
}

func TestNewEmitter_DisabledWhenMissingDeps(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if NewEmitter(EmitterConfig{Signer: NewKeyedSigner(priv)}) != nil {
		t.Error("NewEmitter with nil recorder should return nil")
	}
	if NewEmitter(EmitterConfig{Recorder: &captureRecorder{}}) != nil {
		t.Error("NewEmitter with nil signer should return nil")
	}
}

func TestNilEmitter_IsNoOp(t *testing.T) {
	var em *Emitter
	if err := em.Emit(Decision{Verdict: "block"}); err != nil {
		t.Errorf("nil Emit returned %v, want nil", err)
	}
	seq, head := em.ChainState()
	if seq != 0 || head != recorder.GenesisHash {
		t.Errorf("nil ChainState = (%d,%q), want (0,genesis)", seq, head)
	}
}

func TestEmit_InvalidProvenanceFailsFast(t *testing.T) {
	// Missing policy_sources / winning_source must fail at build time (the v2
	// payload validator rejects them) rather than emit a malformed receipt.
	rec := &captureRecorder{}
	em, _, _ := newTestEmitter(t, rec, nil)
	err := em.Emit(Decision{
		ActionType: "http_request", Transport: "forward", Target: "https://x.example/a",
		Verdict: "block", // no WinningSource / PolicySources
	})
	if err == nil {
		t.Fatal("Emit with empty provenance succeeded; want build error")
	}
	if len(rec.entries) != 0 {
		t.Errorf("recorded %d entries on failed build, want 0", len(rec.entries))
	}
	// Chain must not advance on a failed build.
	if seq, head := em.ChainState(); seq != 0 || head != recorder.GenesisHash {
		t.Errorf("chain advanced on failure: (%d,%q)", seq, head)
	}
}

func TestKeyedSigner(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := NewKeyedSigner(priv)
	if len(s.KeyID()) != ed25519.PublicKeySize*2 { // hex of 32-byte pubkey
		t.Errorf("KeyID length = %d, want %d", len(s.KeyID()), ed25519.PublicKeySize*2)
	}
	msg := []byte("preimage bytes")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature did not verify against the public key")
	}
	var zero KeyedSigner
	if _, err := zero.Sign(msg); err == nil {
		t.Error("zero-value signer should fail to sign")
	}
}

func TestEmit_RecorderErrorPropagates(t *testing.T) {
	rec := &captureRecorder{err: errTestRecorder}
	em, _, _ := newTestEmitter(t, rec, nil)
	err := em.Emit(Decision{
		ActionType: "http_request", Transport: "forward", Target: "https://x.example/a",
		Verdict: "allow", WinningSource: SourceScanner, PolicySources: []string{SourceScanner},
	})
	if err == nil {
		t.Fatal("Emit succeeded despite recorder error")
	}
	// Chain must not advance when the record fails.
	if seq, _ := em.ChainState(); seq != 0 {
		t.Errorf("chain advanced to %d on record failure", seq)
	}
}

var errTestRecorder = &recorderError{"boom"}

type recorderError struct{ msg string }

func (e *recorderError) Error() string { return e.msg }

func newDeterministicClock() func() time.Time {
	base := time.Date(2026, 6, 5, 22, 0, 0, 0, time.UTC)
	return func() time.Time { return base }
}

func TestEmit_UsesInjectedClock(t *testing.T) {
	rec := &captureRecorder{}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewKeyedSigner(priv)
	em := NewEmitter(EmitterConfig{
		Recorder: rec, Signer: signer, Principal: "local", Actor: "pipelock",
		Clock: newDeterministicClock(),
	})
	if err := em.Emit(Decision{
		ActionType: "http_request", Transport: "forward", Target: "https://x.example/a",
		Verdict: "allow", WinningSource: SourceScanner, PolicySources: []string{SourceScanner},
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	rcpt := decodeReceipt(t, rec.entries[0])
	if err := contractreceipt.VerifyWithKey(rcpt, pub, signer.KeyID()); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	if !rcpt.Timestamp.Equal(time.Date(2026, 6, 5, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("Timestamp = %v, want injected clock value", rcpt.Timestamp)
	}
}

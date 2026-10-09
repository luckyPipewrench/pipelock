// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// chosenRunSuffix has the exact shape of a generated run suffix but was
// chosen by the caller; it is registered as a canary in the tests below.
const chosenRunSuffix = "0123456789abcdef0123456789abcdef"

// runSuffixPattern matches any full run session string. It stands in for a
// rule bundle pattern that happens to match a generated suffix: a projection
// that scanned the suffix would refuse every handle.
const runSuffixPattern = `\.run\.[0-9a-f]{8}`

func sessionTestRecorder(t *testing.T, canaries []string, patterns ...config.DLPPattern) (*recorder.Recorder, string, ed25519.PrivateKey) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, patterns...)
	tokens := make([]config.CanaryToken, 0, len(canaries))
	for i, v := range canaries {
		tokens = append(tokens, config.CanaryToken{Name: fmt.Sprintf("session_canary_%d", i), Value: v})
	}
	if len(tokens) > 0 {
		cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: tokens}
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: dir, Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	return rec, dir, key
}

func signedTestReceipt(t *testing.T, key ed25519.PrivateKey) receipt.Receipt {
	t.Helper()
	signed, err := receipt.Sign(receipt.ActionRecord{
		Version: receipt.ActionRecordVersion, ActionID: receipt.NewActionID(), ActionType: receipt.ActionRead,
		Timestamp: time.Now().UTC(), Principal: "local", Actor: "pipelock", Target: "https://api.vendor.example/data",
		Verdict: config.ActionAllow, Transport: "fetch", PolicyHash: strings.Repeat("a", 64), ChainPrevHash: receipt.GenesisHash,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyWithKey(signed, fmt.Sprintf("%x", key.Public())); err != nil {
		t.Fatal(err)
	}
	return signed
}

func sessionEntries(t *testing.T, dir, session string) int {
	t.Helper()
	found, err := recorder.QuerySession(dir, session, nil)
	if err != nil {
		return 0
	}
	return len(found.Entries)
}

// Round-2 C: a cryptographically verified clean receipt with a bound
// preflight still persisted a detector-positive outer Summary.
func TestReviewR2OuterMirrorBypassesDetailScan(t *testing.T) {
	rec, dir, key := sessionTestRecorder(t, nil, config.DLPPattern{Name: "outer mirror fixture", Regex: "mirrorfixture", Severity: config.SeverityHigh})
	signed := signedTestReceipt(t, key)
	scan, err := rec.PreflightSignedReceiptDetail(signed)
	if err != nil {
		t.Fatal(err)
	}
	entry := recorder.Entry{SessionID: "mirror-session", Type: "action_receipt", Transport: "fetch", Summary: "mirrorfixture", Detail: signed}
	if err := rec.RecordWithReceiptScan(entry, &scan); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("detector-positive Summary err = %v, want content rejection", err)
	}
	if n := sessionEntries(t, dir, "mirror-session"); n != 0 {
		t.Fatalf("refused entry persisted: %d entries", n)
	}
	entry.Summary = "safe"
	if err := rec.RecordWithReceiptScan(entry, &scan); err != nil {
		t.Fatalf("clean Summary refused: %v", err)
	}
}

// Round-3 F2: a caller-chosen suffix in the run-session grammar is not
// generated origin, and a clean bound detail must not carry it to disk.
func TestReviewR3OuterGrammarAllowsChosenSecret(t *testing.T) {
	rec, dir, key := sessionTestRecorder(t, []string{chosenRunSuffix})
	sid := "proxy.run." + chosenRunSuffix
	signed := signedTestReceipt(t, key)
	scan, err := rec.PreflightSignedReceiptDetail(signed)
	if err != nil {
		t.Fatal(err)
	}
	err = rec.RecordWithReceiptScan(recorder.Entry{SessionID: sid, Type: "action_receipt", Transport: "http", Summary: "safe", Detail: signed}, &scan)
	if !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("chosen run suffix err = %v, want session_id content rejection", err)
	}
	if strings.Contains(err.Error(), chosenRunSuffix) {
		t.Fatalf("rejection echoed the handle: %v", err)
	}
	if n := sessionEntries(t, dir, sid); n != 0 {
		t.Fatalf("chosen session persisted: %d entries", n)
	}
	if err := rec.AcquireSession(sid); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("explicit acquisition err = %v, want content rejection", err)
	}
	minted, err := recorder.AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatalf("minted run session refused: %v", err)
	}
	if err := rec.RecordWithReceiptScan(recorder.Entry{SessionID: minted, Type: "action_receipt", Transport: "http", Summary: "safe", Detail: signed}, &scan); err != nil {
		t.Fatalf("receipt under the acquired session refused: %v", err)
	}
	// After acquisition no other handle is accepted, whatever its content.
	err = rec.RecordWithReceiptScan(recorder.Entry{SessionID: "proxy", Type: "action_receipt", Transport: "http", Summary: "safe", Detail: signed}, &scan)
	if err == nil || !strings.Contains(err.Error(), "session_id mismatch") {
		t.Fatalf("unacquired handle err = %v", err)
	}
}

// Round-3 F2: a generated suffix does not make an operator base generated.
func TestReviewR3GeneratedRunIDStillCarriesOperatorBase(t *testing.T) {
	secretBase := "r3Aa1Bb2" + "Cc3Dd4Ee5Ff6"
	rec, _, _ := sessionTestRecorder(t, []string{secretBase})
	_, err := recorder.AcquireRunSession(rec, secretBase)
	if !errors.Is(err, receiptcontent.ErrRejected) || strings.Contains(err.Error(), secretBase) {
		t.Fatalf("detector-positive base err = %v, want content rejection without the value", err)
	}
	other, _, _ := sessionTestRecorder(t, []string{secretBase})
	sessions := make([]string, 2)
	for i := range sessions {
		base := "proxy"
		if i == 1 {
			base = secretBase
		}
		if sessions[i], err = recorder.NewRunSessionID(base); err != nil {
			t.Fatal(err)
		}
	}
	if err := other.AcquireGroupSessions(sessions); !errors.Is(err, receiptcontent.ErrRejected) || strings.Contains(err.Error(), secretBase) {
		t.Fatalf("group acquisition err = %v, want content rejection without the value", err)
	}
	if other.SessionID() != "" {
		t.Fatal("refused group acquisition bound a session")
	}
	// Torn-run recovery mints a new handle from a base: same contract.
	if _, err := recorder.AcquireRunSession(rec, "proxy"); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RecoverTornRunSession(secretBase); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("recovery with a detector-positive base err = %v", err)
	}
}

// The wedge class must not return through the session handle: a pattern that
// matches every run session string refuses chosen suffixes but never a
// generated one, in acquisition, group gates, session opens and roots.
func TestGeneratedRunSuffixIsNeverDetectorInput(t *testing.T) {
	rec, dir, key := sessionTestRecorder(t, nil, config.DLPPattern{Name: "bundle-like run suffix", Regex: runSuffixPattern, Severity: config.SeverityHigh})
	if err := rec.AcquireSession("proxy.run." + chosenRunSuffix); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("precondition: the pattern must refuse an unproven run session, got %v", err)
	}
	session, err := recorder.AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatalf("generated run session refused: %v", err)
	}
	em := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, Session: session, Principal: "local", Actor: "pipelock"})
	if em.InitError() != nil {
		t.Fatalf("activation with a generated run session: %v", em.InitError())
	}
	if err := em.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Target: "https://api.vendor.example/data", Verdict: config.ActionAllow, Transport: "fetch"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := em.EmitTranscriptRoot(session); err != nil {
		t.Fatalf("root naming the generated run session: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if n := sessionEntries(t, dir, session); n < 2 {
		t.Fatalf("recorded %d entries under the run session", n)
	}
}

// Round-3 F2: structural equality proves a mirror's origin, not that its
// changed representation was scanned. A Summary formatted from clean atoms
// can form a detector-positive string; the derived mirror is in the views.
func TestReviewR3DerivedSummaryCanCreateSecret(t *testing.T) {
	rec, _, _ := sessionTestRecorder(t, nil, config.DLPPattern{Name: "review-derived", Regex: `leftfragment:rightfragment`, Severity: config.SeverityHigh})
	p := receiptcontent.Register(receiptcontent.Schema{
		Kind:   "recorder.test.derived_summary",
		Fields: map[string]receiptcontent.Class{"a": receiptcontent.Content, "b": receiptcontent.Content},
		Outer: func(detail []byte) (receiptcontent.Outer, error) {
			var d struct{ A, B string }
			err := json.Unmarshal(detail, &d)
			return receiptcontent.Outer{Type: "evidence_receipt", EventKind: "k", Summary: d.A + ":" + d.B}, err
		},
	})
	if _, err := rec.BindLifecycleContent(p, []byte(`{"a":"leftfragment","b":"rightfragment"}`)); !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), receiptcontent.OuterKey) {
		t.Fatalf("derived summary err = %v, want rejection naming the mirror", err)
	}
	if _, err := rec.BindLifecycleContent(p, []byte(`{"a":"left","b":"right"}`)); err != nil {
		t.Fatalf("clean derived summary refused: %v", err)
	}
}

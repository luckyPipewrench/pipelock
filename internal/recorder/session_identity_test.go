// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

var runSessionPattern = regexp.MustCompile(`^proxy\.run\.[0-9a-f]{32}$`)

func TestNewRunSessionID_Format(t *testing.T) {
	id, err := NewRunSessionID("proxy")
	if err != nil {
		t.Fatalf("NewRunSessionID: %v", err)
	}
	if !runSessionPattern.MatchString(id) {
		t.Fatalf("run session id %q does not match expected shape <base>.run.<32 hex>", id)
	}
}

func TestNewRunSessionID_UniquePerCall(t *testing.T) {
	seen := make(map[string]bool)
	const n = 200
	for i := 0; i < n; i++ {
		id, err := NewRunSessionID("proxy")
		if err != nil {
			t.Fatalf("NewRunSessionID: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate run session id %q after %d calls", id, i)
		}
		seen[id] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d unique ids, got %d", n, len(seen))
	}
}

func TestNewRunSessionID_RejectsReservedBase(t *testing.T) {
	cases := []string{
		"proxy.run.deadbeef",
		"a/b",
		`a\b`,
		"",
	}
	for _, base := range cases {
		if _, err := NewRunSessionID(base); err == nil {
			t.Errorf("NewRunSessionID(%q): expected refusal, got nil error", base)
		} else if !errors.Is(err, evidencename.ErrReservedSessionID) {
			t.Errorf("NewRunSessionID(%q): expected ErrReservedSessionID, got %v", base, err)
		}
	}
}

func TestNewRunSessionID_DifferentBasesPreserved(t *testing.T) {
	id, err := NewRunSessionID("proxy-decision")
	if err != nil {
		t.Fatalf("NewRunSessionID: %v", err)
	}
	if !strings.HasPrefix(id, "proxy-decision.run.") {
		t.Fatalf("run session id %q does not preserve base %q", id, "proxy-decision")
	}
}

// TestValidateOperatorSessionID_RejectsReservedInfix is the refusal proof
// required by the design: an operator-supplied session id containing the
// reserved ".run." infix is refused, with a message naming what to change.
func TestValidateOperatorSessionID_RejectsReservedInfix(t *testing.T) {
	err := evidencename.ValidateOperatorSessionID("proxy.run.abc123")
	if err == nil {
		t.Fatal("expected refusal for operator session id containing reserved infix, got nil")
	}
	if !errors.Is(err, evidencename.ErrReservedSessionID) {
		t.Fatalf("expected ErrReservedSessionID, got %v", err)
	}
	if !strings.Contains(err.Error(), ".run.") {
		t.Fatalf("error message does not name the offending infix: %v", err)
	}
}

// TestValidateOperatorSessionID_RejectsPathSeparators covers the "/" and "\"
// refusal half of the same guard.
func TestValidateOperatorSessionID_RejectsPathSeparators(t *testing.T) {
	for _, id := range []string{"a/b", `a\b`, "/etc/passwd", `..\..\x`} {
		if err := evidencename.ValidateOperatorSessionID(id); err == nil {
			t.Errorf("ValidateOperatorSessionID(%q): expected refusal, got nil", id)
		} else if !errors.Is(err, evidencename.ErrReservedSessionID) {
			t.Errorf("ValidateOperatorSessionID(%q): expected ErrReservedSessionID, got %v", id, err)
		}
	}
}

// TestValidateOperatorSessionID_AcceptsPlainID is the positive control for
// the two refusal tests above: an ordinary operator-chosen session id must
// still pass, so the guard is proven to reject the bad shape specifically
// and not merely reject everything.
func TestValidateOperatorSessionID_AcceptsPlainID(t *testing.T) {
	for _, id := range []string{"proxy", "my-agent-session", "session_123", "a.b.c"} {
		if err := evidencename.ValidateOperatorSessionID(id); err != nil {
			t.Errorf("ValidateOperatorSessionID(%q): unexpected refusal: %v", id, err)
		}
	}
}

func TestValidateOperatorSessionID_RejectsEmpty(t *testing.T) {
	if err := evidencename.ValidateOperatorSessionID(""); err == nil {
		t.Fatal("expected refusal for empty session id, got nil")
	}
}

func newTestRecorderForAcquire(t *testing.T) *Recorder {
	t.Helper()
	rec, err := New(Config{
		Enabled:            true,
		Dir:                t.TempDir(),
		CheckpointInterval: 100,
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	return rec
}

func TestAcquireSession_BindsOnce(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	if err := rec.AcquireSession("proxy.run.aaaa"); err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	if rec.sessionID != "proxy.run.aaaa" {
		t.Fatalf("sessionID = %q, want %q", rec.sessionID, "proxy.run.aaaa")
	}
}

// TestAcquireSession_SameSessionIsNoop proves repeated acquisition with the
// same session ID does not error - a caller may legitimately call this more
// than once (e.g. once eagerly at startup, defensively again before first
// write).
func TestAcquireSession_SameSessionIsNoop(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	if err := rec.AcquireSession("proxy.run.aaaa"); err != nil {
		t.Fatalf("first AcquireSession: %v", err)
	}
	if err := rec.AcquireSession("proxy.run.aaaa"); err != nil {
		t.Fatalf("second AcquireSession (same id): %v", err)
	}
}

// TestAcquireSession_ForeignSessionRefused is the "one session per recorder"
// proof at the acquisition boundary: acquiring a second, different session on
// an already-bound recorder is refused rather than silently rebinding.
func TestAcquireSession_ForeignSessionRefused(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	if err := rec.AcquireSession("proxy.run.aaaa"); err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	err := rec.AcquireSession("proxy.run.bbbb")
	if err == nil {
		t.Fatal("expected refusal acquiring a second session on an already-bound recorder, got nil")
	}
	if !strings.Contains(err.Error(), "already bound") {
		t.Fatalf("error does not explain the refusal: %v", err)
	}
}

// TestAcquireSession_ThenRecordMismatchStillRefused proves AcquireSession and
// the existing per-Record mismatch check agree: once acquired, a Record call
// under a foreign session id is refused exactly as if the session had been
// bound implicitly by the first Record call.
func TestAcquireSession_ThenRecordMismatchStillRefused(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	if err := rec.AcquireSession("proxy.run.aaaa"); err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	err := rec.Record(Entry{
		SessionID: "proxy.run.bbbb",
		Type:      "request",
		Transport: "fetch",
	})
	if err == nil {
		t.Fatal("expected Record under a foreign session to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "session_id mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAcquireSession_NilAndNopRecorderAreNoop(t *testing.T) {
	var nilRec *Recorder
	if err := nilRec.AcquireSession("anything"); err != nil {
		t.Fatalf("nil recorder AcquireSession: %v", err)
	}
	nop := &Recorder{nop: true}
	if err := nop.AcquireSession("anything"); err != nil {
		t.Fatalf("nop recorder AcquireSession: %v", err)
	}
}

func TestAcquireRunSession_NilAndNopReturnBaseUnchanged(t *testing.T) {
	var nilRec *Recorder
	got, err := AcquireRunSession(nilRec, "proxy")
	if err != nil {
		t.Fatalf("AcquireRunSession(nil): %v", err)
	}
	if got != "proxy" {
		t.Fatalf("AcquireRunSession(nil) = %q, want unchanged base %q", got, "proxy")
	}

	nop := &Recorder{nop: true}
	got, err = AcquireRunSession(nop, "proxy")
	if err != nil {
		t.Fatalf("AcquireRunSession(nop): %v", err)
	}
	if got != "proxy" {
		t.Fatalf("AcquireRunSession(nop) = %q, want unchanged base %q", got, "proxy")
	}
}

// TestAcquireRunSession_RealRecorderMintsAndBinds is the end-to-end proof for
// design point 1+2 together: a real recorder given a base gets back a fresh
// run session id and is bound to it, so a subsequent Record under that id
// succeeds and a Record under the base literal is refused.
func TestAcquireRunSession_RealRecorderMintsAndBinds(t *testing.T) {
	rec := newTestRecorderForAcquire(t)
	runSession, err := AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatalf("AcquireRunSession: %v", err)
	}
	if !runSessionPattern.MatchString(runSession) {
		t.Fatalf("run session %q does not match expected shape", runSession)
	}
	if err := rec.Record(Entry{SessionID: runSession, Type: "request", Transport: "fetch"}); err != nil {
		t.Fatalf("Record under acquired run session: %v", err)
	}
	err = rec.Record(Entry{SessionID: "proxy", Type: "request", Transport: "fetch"})
	if err == nil {
		t.Fatal("expected Record under the bare base literal to be refused after run-session acquisition, got nil")
	}
}

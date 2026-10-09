// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

// A session close seals the pre-close tail. A refused close must report no
// seal: the chain stays open, a later clean close succeeds, and the refused
// reason never reaches disk, redacted or not.
func TestSessionCloseRefusalReportsNoSeal(t *testing.T) {
	f := newBoundaryFixture(t)
	if err := f.em.Emit(baseOpts()); err != nil {
		t.Fatal(err)
	}
	err := f.em.EmitSessionClose("shutdown " + boundaryCanary)
	if !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), "close_reason") {
		t.Fatalf("dirty close err = %v, want a rejection naming close_reason", err)
	}
	if f.em.HealthError() != nil {
		t.Fatal("a refused close poisoned the emitter")
	}
	if err := f.em.Emit(baseOpts()); err != nil {
		t.Fatalf("a refused close sealed the chain: %v", err)
	}
	if err := f.em.EmitSessionClose("shutdown"); err != nil {
		t.Fatalf("clean close after a refusal: %v", err)
	}
	closes := 0
	for _, r := range f.receipts(t) {
		raw, _ := Marshal(r)
		if strings.Contains(string(raw), boundaryCanary) || strings.Contains(string(raw), "REDACTED") {
			t.Fatalf("refused or redacted lifecycle content reached disk: %s", raw)
		}
		if sc := r.ActionRecord.SessionControl; sc != nil && sc.Kind == SessionControlClose {
			closes++
		}
	}
	if closes != 1 {
		t.Fatalf("close receipts = %d, want 1", closes)
	}
}

// A group gate is validate-or-fail: its generated members never reach the
// detector, so the wedged head and the signer key the bundle pattern matched
// are accepted, while a chosen shard session is refused, never redacted.
func TestGroupGateContentIsValidateOrFail(t *testing.T) {
	f := newBoundaryFixture(t)
	defer func() { _ = f.rec.Close() }()
	gate := func(session string) []byte {
		raw, err := json.Marshal(map[string]any{
			"group_id": strings.Repeat("a", 32), "shard_index": 0, "session_id": session,
			"open_manifest_sha256": wedgedHead, "signer_key": f.pubH,
			"previous_group_id": "", "previous_open_manifest_sha256": wedgedHead,
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := f.rec.BindLifecycleContent(groupGateProducer, gate("proxy.run."+strings.Repeat("0", 32))); err != nil {
		t.Fatalf("gate with generated members matching the bundle pattern refused: %v", err)
	}
	_, err := f.rec.BindLifecycleContent(groupGateProducer, gate(boundaryCanary+".run."+strings.Repeat("0", 32)))
	if !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), "session_id") || strings.Contains(err.Error(), boundaryCanary) {
		t.Fatalf("chosen shard session err = %v, want a rejection naming session_id without the value", err)
	}
}

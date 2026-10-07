// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestEmitterOversizedRecorderLineKeepsReceiptChainPosition(t *testing.T) {
	publicKey, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	emitter := NewEmitter(EmitterConfig{
		Recorder: rec, PrivKey: key, Session: session,
		ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor,
	})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	before, _ := emitter.HealthSnapshot()
	tooLarge := EmitOpts{
		ActionID: NewActionID(), Verdict: config.ActionAllow,
		Transport: "fetch", Method: http.MethodGet,
		Target: "https://api.vendor.example/" + strings.Repeat("x", recorder.MaxEntryLineBytes),
	}
	if err := emitter.EmitDurable(tooLarge); !errors.Is(err, recorder.ErrSerializedEntryTooLarge) {
		t.Fatalf("oversized receipt = %v", err)
	}
	after, _ := emitter.HealthSnapshot()
	if after.ChainSeq != before.ChainSeq || after.PrevHash != before.PrevHash || emitter.HealthError() != nil {
		t.Fatalf("oversized receipt changed chain state: before=%+v after=%+v health=%v", before, after, emitter.HealthError())
	}
	valid := tooLarge
	valid.ActionID = NewActionID()
	valid.Target = "https://api.vendor.example/ok"
	if err := emitter.EmitDurable(valid); err != nil {
		t.Fatalf("valid receipt after size rejection: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	receipts := readAllReceiptsFromDir(t, dir, publicKey)
	if len(receipts) != 2 || receipts[1].ActionRecord.ChainSeq != 1 {
		t.Fatalf("receipt chain after size rejection: %+v", receipts)
	}
	if result := VerifyChain(receipts, receipts[0].SignerKey); !result.Valid {
		t.Fatalf("receipt chain after size rejection: %+v", result)
	}
}

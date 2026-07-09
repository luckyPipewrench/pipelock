//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	testReceiptEntryType = "action_receipt"
	zeroSessionID        = "empty-agent"
)

func TestReadModel_IntegrationRealReadPathAndZeroReceiptSession(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	rec := newTestRecorder(t, dir, priv)
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testPolicyHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionAllow,
			Transport: testTransport,
			Method:    http.MethodGet,
			Layer:     "allowlist",
			Pattern:   "example.com",
			SessionID: testSessionID,
			Agent:     testActor,
		}); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}
	_ = rec.Close()
	writeZeroReceiptSessionFile(t, dir, zeroSessionID)

	model := NewReadModel(Options{
		ReceiptDir: dir,
		TrustedKeys: map[string]TrustedKey{
			keyHex: {Source: trustedKeySource},
		},
	})
	sessions, err := model.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("len(Sessions) = %d, want 2", len(sessions))
	}

	evidence, err := model.Session("proxy")
	if err != nil {
		t.Fatalf("Session(proxy): %v", err)
	}
	if evidence.Scorecard.Authentic.State != StateVerify {
		t.Fatalf("Authentic.State = %q, want %q", evidence.Scorecard.Authentic.State, StateVerify)
	}
	if !evidence.ReceiptsEnabled {
		t.Fatal("proxy session should have receipts enabled")
	}

	zero, err := model.Session(zeroSessionID)
	if err != nil {
		t.Fatalf("Session(%s): %v", zeroSessionID, err)
	}
	if zero.ReceiptsEnabled {
		t.Fatal("zero-receipt session should be marked receipts disabled")
	}
	wantChip := evidenceview.AbsentScorecard().Authentic.Chip
	if zero.Scorecard.Authentic.Chip != wantChip {
		t.Fatalf("zero Authentic.Chip = %q, want %q", zero.Scorecard.Authentic.Chip, wantChip)
	}
}

func TestReadModel_ReadLimitDowngradesEvidence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 4))

	model := NewReadModel(Options{
		ReceiptDir:       dir,
		ReceiptReadLimit: 2,
		TimelineLimit:    1,
		TrustedKeys: map[string]TrustedKey{
			keyHex: {Source: trustedKeySource},
		},
	})
	sessions, err := model.Sessions()
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len(Sessions) = %d, want 1", len(sessions))
	}
	if !sessions[0].ReadLimited {
		t.Fatal("summary should report read-limited evidence")
	}
	if sessions[0].ReceiptCount != 2 {
		t.Fatalf("ReceiptCount = %d, want 2", sessions[0].ReceiptCount)
	}

	evidence, err := model.Session(testSessionID)
	if err != nil {
		t.Fatalf("Session(%s): %v", testSessionID, err)
	}
	if !evidence.ReadLimited {
		t.Fatal("evidence should report read-limited session")
	}
	if evidence.Scorecard.Authentic.State != StateLimited {
		t.Fatalf("Authentic.State = %q, want %q", evidence.Scorecard.Authentic.State, StateLimited)
	}
	if evidence.Scorecard.Untampered.State != StateLimited {
		t.Fatalf("Untampered.State = %q, want %q", evidence.Scorecard.Untampered.State, StateLimited)
	}
	if len(evidence.Timeline) != 1 {
		t.Fatalf("len(Timeline) = %d, want 1", len(evidence.Timeline))
	}
	if evidence.TimelineWindow != "first" {
		t.Fatalf("TimelineWindow = %q, want first", evidence.TimelineWindow)
	}
}

func writeReceiptsToDir(t *testing.T, dir string, receipts []receipt.Receipt) {
	t.Helper()
	rec := newTestRecorder(t, dir, nil)
	for i, r := range receipts {
		if err := rec.Record(recorder.Entry{
			SessionID: testSessionID,
			Type:      testReceiptEntryType,
			EventKind: string(r.ActionRecord.ActionType),
			Transport: r.ActionRecord.Transport,
			Summary:   "receipt",
			Detail:    r,
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	_ = rec.Close()
}

func newTestRecorder(t *testing.T, dir string, priv ed25519.PrivateKey) *recorder.Recorder {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	return rec
}

func writeZeroReceiptSessionFile(t *testing.T, dir, sessionID string) {
	t.Helper()
	path := filepath.Join(dir, "evidence-"+sessionID+"-000000.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

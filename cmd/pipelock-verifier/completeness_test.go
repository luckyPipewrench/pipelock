// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type completenessFixture struct {
	t      *testing.T
	priv   ed25519.PrivateKey
	keyHex string
	prev   string
	seq    uint64
	base   time.Time
	offset time.Duration
}

func newCompletenessFixture(t *testing.T) *completenessFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return &completenessFixture{
		t:      t,
		priv:   priv,
		keyHex: hex.EncodeToString(pub),
		prev:   receipt.GenesisHash,
		base:   time.Date(2026, 7, 6, 13, 0, 0, 0, time.UTC),
	}
}

func (f *completenessFixture) sign(ar receipt.ActionRecord) receipt.Receipt {
	f.t.Helper()
	if ar.Version == 0 {
		ar.Version = receipt.ActionRecordVersion
	}
	if ar.ActionID == "" {
		ar.ActionID = receipt.NewActionID()
	}
	if ar.ActionType == "" {
		ar.ActionType = receipt.ActionRead
	}
	if ar.Timestamp.IsZero() {
		ar.Timestamp = f.base.Add(f.offset)
	}
	if ar.Target == "" {
		ar.Target = "https://api.vendor.example/completeness-cli"
	}
	if ar.Verdict == "" {
		ar.Verdict = verdictAllowed
	}
	if ar.Transport == "" {
		ar.Transport = "fetch"
	}
	if ar.PolicyHash == "" {
		ar.PolicyHash = "policy-completeness-cli"
	}
	ar.ChainPrevHash = f.prev
	ar.ChainSeq = f.seq
	r, err := receipt.Sign(ar, f.priv)
	if err != nil {
		f.t.Fatalf("Sign: %v", err)
	}
	hash, err := receipt.ReceiptHash(r)
	if err != nil {
		f.t.Fatalf("ReceiptHash: %v", err)
	}
	f.prev = hash
	f.seq++
	f.offset += time.Second
	return r
}

func (f *completenessFixture) open(runNonce, openNonce string) receipt.Receipt {
	f.t.Helper()
	open := receipt.SessionOpen{
		RunNonce:         runNonce,
		OpenNonce:        openNonce,
		RecorderSession:  "proxy",
		PolicyHash:       "policy-completeness-cli",
		SignerKeyEpoch:   "epoch-cli",
		HeartbeatSeconds: 10,
		ChainOpenSeq:     f.seq,
	}
	genesis := receipt.ComputeSessionOpenGenesis(open)
	open.GenesisHash = genesis
	f.prev = genesis
	return f.sign(receipt.ActionRecord{
		ActionType: receipt.ActionUnclassified,
		Target:     "pipelock://session/open",
		Transport:  "session_control",
		RunNonce:   runNonce,
		SessionControl: &receipt.SessionControl{
			Kind: receipt.SessionControlOpen,
			Open: &open,
		},
	})
}

func (f *completenessFixture) heartbeat(runNonce, openNonce string) receipt.Receipt {
	f.t.Helper()
	const beat = 1
	return f.sign(receipt.ActionRecord{
		ActionType: receipt.ActionUnclassified,
		Target:     "pipelock://session/heartbeat",
		Transport:  "session_control",
		RunNonce:   runNonce,
		SessionControl: &receipt.SessionControl{
			Kind: receipt.SessionControlHeartbeat,
			Heartbeat: &receipt.SessionHeartbeat{
				RunNonce:         runNonce,
				OpenNonce:        openNonce,
				Beat:             beat,
				ChainHead:        f.prev,
				ChainSeqHead:     f.seq,
				HeartbeatTime:    f.base.Add(f.offset).Format(time.RFC3339Nano),
				DurabilityBlocks: beat,
			},
		},
	})
}

func (f *completenessFixture) close(runNonce, openNonce string) receipt.Receipt {
	f.t.Helper()
	finalSeq := uint64(0)
	if f.seq > 0 {
		finalSeq = f.seq - 1
	}
	return f.sign(receipt.ActionRecord{
		ActionType: receipt.ActionUnclassified,
		Target:     "pipelock://session/close",
		Transport:  "session_control",
		RunNonce:   runNonce,
		SessionControl: &receipt.SessionControl{
			Kind: receipt.SessionControlClose,
			Close: &receipt.SessionClose{
				RunNonce:         runNonce,
				OpenNonce:        openNonce,
				FinalSeq:         finalSeq,
				RootHash:         f.prev,
				ReceiptCount:     f.seq,
				CloseReason:      "normal",
				DurabilityBlocks: 1,
			},
		},
	})
}

func (f *completenessFixture) intent(runNonce, actionID string) receipt.Receipt {
	f.t.Helper()
	return f.sign(receipt.ActionRecord{
		ActionID:      actionID,
		ActionType:    receipt.ActionRead,
		Target:        "https://api.vendor.example/completeness-cli/action",
		Transport:     "fetch",
		RunNonce:      runNonce,
		DecisionPhase: receipt.DecisionPhaseIntent,
	})
}

func (f *completenessFixture) outcome(runNonce, actionID string) receipt.Receipt {
	f.t.Helper()
	return f.sign(receipt.ActionRecord{
		ActionID:      actionID,
		ActionType:    receipt.ActionRead,
		Target:        "https://api.vendor.example/completeness-cli/action",
		Transport:     "fetch",
		RunNonce:      runNonce,
		DecisionPhase: receipt.DecisionPhaseOutcome,
	})
}

func writeCompletenessJSONL(t *testing.T, receipts []receipt.Receipt) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	var buf bytes.Buffer
	for _, r := range receipts {
		line, err := receipt.Marshal(r)
		if err != nil {
			t.Fatalf("receipt.Marshal: %v", err)
		}
		_, _ = buf.Write(line)
		_ = buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	return path
}

func parseCompletenessReport(t *testing.T, stdout string) completeness.Report {
	t.Helper()
	var report completeness.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal report: %v\nstdout=%s", err, stdout)
	}
	return report
}

func TestCompletenessCLIJSONVerdictsAndExitCodes(t *testing.T) {
	t.Parallel()
	const (
		runNonce  = "run-completeness-cli"
		openNonce = "open-completeness-cli"
	)

	t.Run("limited_bounded_closed_exits_zero", func(t *testing.T) {
		t.Parallel()
		f := newCompletenessFixture(t)
		actionID := "action-cli-limited"
		path := writeCompletenessJSONL(t, []receipt.Receipt{
			f.open(runNonce, openNonce),
			f.intent(runNonce, actionID),
			f.outcome(runNonce, actionID),
			f.heartbeat(runNonce, openNonce),
			f.close(runNonce, openNonce),
		})
		stdout, stderr, code := runRoot(t, "completeness", "--json", "--key", f.keyHex, path)
		if code != cliutil.ExitOK {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		report := parseCompletenessReport(t, stdout)
		if report.Status != completeness.StatusLimited || report.Reason != completeness.ReasonBoundedClosed {
			t.Fatalf("report=%s/%s, want LIMITED/bounded_closed", report.Status, report.Reason)
		}
	})

	t.Run("lifecycle_no_open_exits_nonzero", func(t *testing.T) {
		t.Parallel()
		f := newCompletenessFixture(t)
		path := writeCompletenessJSONL(t, []receipt.Receipt{
			f.heartbeat(runNonce, openNonce),
			f.close(runNonce, openNonce),
		})
		stdout, stderr, code := runRoot(t, "completeness", "--json", "--key", f.keyHex, path)
		if code != cliutil.ExitGeneral {
			t.Fatalf("code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
		}
		report := parseCompletenessReport(t, stdout)
		if report.Status != completeness.StatusBroken || report.Reason != completeness.ReasonChainBroken {
			t.Fatalf("report=%s/%s, want BROKEN/chain_broken", report.Status, report.Reason)
		}
		if !report.SignaturesVerified {
			t.Fatalf("signatures_verified=false, want true for signed malformed lifecycle: %#v", report)
		}
	})

	t.Run("forged_no_open_exits_nonzero", func(t *testing.T) {
		t.Parallel()
		f := newCompletenessFixture(t)
		receipts := []receipt.Receipt{
			f.heartbeat(runNonce, openNonce),
			f.close(runNonce, openNonce),
		}
		receipts[0].ActionRecord.Target = "https://api.vendor.example/forged-no-open-cli"
		path := writeCompletenessJSONL(t, receipts)
		stdout, stderr, code := runRoot(t, "completeness", "--json", "--key", f.keyHex, path)
		if code != cliutil.ExitGeneral {
			t.Fatalf("code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
		}
		report := parseCompletenessReport(t, stdout)
		if report.Status != completeness.StatusBroken || report.Reason != completeness.ReasonChainBroken {
			t.Fatalf("report=%s/%s, want BROKEN/chain_broken", report.Status, report.Reason)
		}
		if report.SignaturesVerified {
			t.Fatalf("signatures_verified=true for forged chain: %#v", report)
		}
	})

	t.Run("broken_no_open_without_key_stays_nonzero_with_unpinned_flag", func(t *testing.T) {
		t.Parallel()
		f := newCompletenessFixture(t)
		path := writeCompletenessJSONL(t, []receipt.Receipt{
			f.heartbeat(runNonce, openNonce),
			f.close(runNonce, openNonce),
		})
		stdout, stderr, code := runRoot(t, "completeness", "--json", path)
		if code != cliutil.ExitGeneral {
			t.Fatalf("code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
		}
		report := parseCompletenessReport(t, stdout)
		if !report.Unpinned {
			t.Fatalf("unpinned=false, want true: %#v", report)
		}

		stdout, stderr, code = runRoot(t, "completeness", "--json", "--allow-unpinned", path)
		if code != cliutil.ExitGeneral {
			t.Fatalf("allow-unpinned code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
		}
		report = parseCompletenessReport(t, stdout)
		if report.Status != completeness.StatusBroken || report.Reason != completeness.ReasonChainBroken || !report.Unpinned {
			t.Fatalf("allow-unpinned report=%s/%s unpinned=%t, want BROKEN/chain_broken unpinned", report.Status, report.Reason, report.Unpinned)
		}
	})

	t.Run("broken_chain_exits_nonzero", func(t *testing.T) {
		t.Parallel()
		f := newCompletenessFixture(t)
		actionID := "action-cli-broken"
		receipts := []receipt.Receipt{
			f.open(runNonce, openNonce),
			f.intent(runNonce, actionID),
			f.outcome(runNonce, actionID),
		}
		receipts[1].ActionRecord.Target = "https://api.vendor.example/tampered"
		path := writeCompletenessJSONL(t, receipts)
		stdout, stderr, code := runRoot(t, "completeness", "--json", "--key", f.keyHex, path)
		if code != cliutil.ExitGeneral {
			t.Fatalf("code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
		}
		report := parseCompletenessReport(t, stdout)
		if report.Status != completeness.StatusBroken || report.Reason != completeness.ReasonChainBroken {
			t.Fatalf("report=%s/%s, want BROKEN/chain_broken", report.Status, report.Reason)
		}
	})
}

func TestCompletenessCLINeverPrintsGreenTopline(t *testing.T) {
	t.Parallel()
	const (
		runNonce  = "run-completeness-human"
		openNonce = "open-completeness-human"
	)
	f := newCompletenessFixture(t)
	actionID := "action-cli-human"
	path := writeCompletenessJSONL(t, []receipt.Receipt{
		f.open(runNonce, openNonce),
		f.intent(runNonce, actionID),
		f.outcome(runNonce, actionID),
		f.heartbeat(runNonce, openNonce),
		f.close(runNonce, openNonce),
	})
	stdout, stderr, code := runRoot(t, "completeness", "--key", f.keyHex, path)
	if code != cliutil.ExitOK {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "completeness: LIMITED (bounded_closed)") {
		t.Fatalf("stdout missing LIMITED topline: %s", stdout)
	}
	for _, forbidden := range []string{"COMPLETE", "PASS", "OK"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("stdout contains forbidden green term %q: %s", forbidden, stdout)
		}
	}
}

func TestCompletenessCLITranscriptRootAfterCloseDoesNotTripPostCloseGuard(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:           true,
		Dir:               dir,
		MaxEntriesPerFile: 100,
		FileMode:          0o600,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "policy-completeness-cli",
		Principal:  "user",
		Actor:      "agent",
	})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := e.EmitSessionClose("normal"); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := e.EmitTranscriptRoot("proxy"); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}

	stdout, stderr, code := runRoot(t, "completeness", "--json", "--key", hex.EncodeToString(pub), dir)
	if code != cliutil.ExitOK {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	report := parseCompletenessReport(t, stdout)
	if report.Status != completeness.StatusLimited || report.Reason != completeness.ReasonBoundedClosed {
		t.Fatalf("report=%s/%s, want LIMITED/bounded_closed: %#v", report.Status, report.Reason, report)
	}
	if report.ReceiptCount != 2 {
		t.Fatalf("receipt_count=%d, want 2 action receipts with transcript_root ignored: %#v", report.ReceiptCount, report)
	}
}

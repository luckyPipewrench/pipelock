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
				ChainSeqHead:     receipt.PreviousChainSeq(f.seq),
				HeartbeatTime:    f.base.Add(f.offset).Format(time.RFC3339Nano),
				DurabilityBlocks: beat,
			},
		},
	})
}

func (f *completenessFixture) close(runNonce, openNonce string) receipt.Receipt {
	f.t.Helper()
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
				FinalSeq:         f.seq,
				RootHash:         f.prev,
				ReceiptCount:     f.seq + 1,
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

	t.Run("empty_chain_is_unverified_and_exits_nonzero", func(t *testing.T) {
		t.Parallel()
		f := newCompletenessFixture(t)
		path := writeCompletenessJSONL(t, nil)
		stdout, stderr, code := runRoot(t, "completeness", "--json", "--key", f.keyHex, path)
		if code != cliutil.ExitGeneral {
			t.Fatalf("code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
		}
		report := parseCompletenessReport(t, stdout)
		if report.Status != completeness.StatusUnverified || report.Reason != completeness.ReasonNoReceipts {
			t.Fatalf("report=%s/%s, want UNVERIFIED/no_receipts", report.Status, report.Reason)
		}
		if report.SignaturesVerified {
			t.Fatalf("empty chain claimed signatures_verified: %#v", report)
		}
	})

	t.Run("integrity_verified_no_open_is_unverified_and_exits_nonzero", func(t *testing.T) {
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
		if report.Status != completeness.StatusUnverified || report.Reason != completeness.ReasonNoOpen {
			t.Fatalf("report=%s/%s, want UNVERIFIED/no_open", report.Status, report.Reason)
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

	t.Run("unverified_no_open_remains_nonzero_with_unpinned_opt_in", func(t *testing.T) {
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
		if report.Status != completeness.StatusUnverified || report.Reason != completeness.ReasonNoOpen || !report.Unpinned {
			t.Fatalf("allow-unpinned report=%s/%s unpinned=%t, want UNVERIFIED/no_open unpinned", report.Status, report.Reason, report.Unpinned)
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

func TestCompletenessCLILocationSelector(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	locationID := filepath.Join("recorder-a", "run-a")
	locationDir := filepath.Join(root, locationID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:           true,
		Dir:               locationDir,
		MaxEntriesPerFile: 100,
		FileMode:          0o600,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "policy-completeness-location",
		Principal:  "user",
		Actor:      "agent",
	})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	if err := emitter.EmitSessionClose("normal"); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}

	stdout, stderr, code := runRoot(t,
		"completeness", "--json",
		"--location", filepath.ToSlash(locationID),
		"--key", hex.EncodeToString(pub),
		root,
	)
	if code != cliutil.ExitOK {
		t.Fatalf("selected location code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	report := parseCompletenessReport(t, stdout)
	if report.Status != completeness.StatusLimited || report.Reason != completeness.ReasonBoundedClosed {
		t.Fatalf("report=%s/%s, want LIMITED/bounded_closed: %#v", report.Status, report.Reason, report)
	}
	stdout, stderr, code = runRoot(t, "completeness", "--json", "--key", hex.EncodeToString(pub), root)
	if code != cliutil.ExitOK {
		t.Fatalf("implicit location code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	nestedDir := filepath.Join(locationDir, "nested")
	if err := os.MkdirAll(nestedDir, 0o750); err != nil {
		t.Fatalf("create nested location: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nestedDir, "evidence-other-0.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write nested evidence: %v", err)
	}
	stdout, stderr, code = runRoot(t,
		"completeness", "--json",
		"--location", filepath.ToSlash(locationID),
		"--key", hex.EncodeToString(pub),
		root,
	)
	if code != cliutil.ExitOK {
		t.Fatalf("selected parent code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	var out, errOut bytes.Buffer
	err = runCompleteness(&out, &errOut, root, completenessOptions{locationID: "missing/run"})
	if err == nil || !strings.Contains(err.Error(), "resolve evidence location") {
		t.Fatalf("unknown location error = %v, want resolution failure", err)
	}
	selectedPath := filepath.Join(locationDir, "evidence-proxy-0.jsonl")
	err = runCompleteness(&out, &errOut, selectedPath, completenessOptions{locationID: "recorder-a/run-a"})
	if err == nil || !strings.Contains(err.Error(), "--location requires an evidence directory") {
		t.Fatalf("file target error = %v, want directory requirement", err)
	}
	err = runCompleteness(&out, &errOut, filepath.Join(root, "absent"), completenessOptions{locationID: "recorder-a/run-a"})
	if err == nil || !strings.Contains(err.Error(), "stat") {
		t.Fatalf("missing target error = %v, want stat failure", err)
	}
	secondLocation := filepath.Join(root, "recorder-b", "run-b")
	if err := os.MkdirAll(secondLocation, 0o750); err != nil {
		t.Fatalf("create second location: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secondLocation, "evidence-proxy-0.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write second location: %v", err)
	}
	err = runCompleteness(&out, &errOut, root, completenessOptions{})
	if err == nil || !strings.Contains(err.Error(), "multiple evidence locations") {
		t.Fatalf("ambiguous root error = %v", err)
	}
}

func TestExtractCompletenessReceiptsResolvedLocationReplacementFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "run")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	location, err := recorder.ResolveEvidenceLocation(root, "run")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.WriteFile(dir, []byte("not evidence"), 0o600); err != nil {
		t.Fatalf("WriteFile replacement: %v", err)
	}
	_, _, err = extractCompletenessReceipts(dir, "proxy", &location)
	if err == nil || !strings.Contains(err.Error(), "open evidence location component") {
		t.Fatalf("extractCompletenessReceipts error = %v, want resolved-path refusal", err)
	}
}

// writeChainRecorderJSONL wraps v1 receipts in recorder entries. The chain
// command attempts v2 evidence extraction first and FAILS CLOSED on an unknown
// entry shape, so a bare receipt-per-line file (which writeCompletenessJSONL
// produces, and which the completeness command reads happily) aborts with a
// config error before the v1 path is ever reached.
func writeChainRecorderJSONL(t *testing.T, receipts []receipt.Receipt) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	var buf bytes.Buffer
	prev := recorder.GenesisHash
	base := time.Date(2026, 5, 10, 14, 0, 0, 0, time.UTC)
	for i, r := range receipts {
		entry := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  uint64(i),
			Timestamp: base.Add(time.Duration(i) * time.Second),
			SessionID: "proxy",
			Type:      "action_receipt",
			Detail:    r,
			PrevHash:  prev,
		}
		entry.Hash = recorder.ComputeHash(entry)
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal recorder entry: %v", err)
		}
		prev = entry.Hash
		_, _ = buf.Write(line)
		_ = buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write recorder jsonl: %v", err)
	}
	return path
}

func TestChainAndCompletenessAcceptSameBareV1JSONL(t *testing.T) {
	t.Parallel()
	fixture := newCompletenessFixture(t)
	path := writeCompletenessJSONL(t, []receipt.Receipt{
		fixture.open("run-bare-v1", "open-bare-v1"),
		fixture.close("run-bare-v1", "open-bare-v1"),
	})

	for _, command := range []string{"chain", "completeness"} {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runRoot(t, command, "--json", "--key", fixture.keyHex, path)
			if code != cliutil.ExitOK {
				t.Fatalf("bare v1 %s should verify: code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
			}
		})
	}
}

func TestChainAndCompletenessRejectMalformedBareV1JSONL(t *testing.T) {
	t.Parallel()
	fixture := newCompletenessFixture(t)
	path := writeCompletenessJSONL(t, []receipt.Receipt{
		fixture.open("run-malformed-bare-v1", "open-malformed-bare-v1"),
	})
	file, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	if _, err := file.WriteString(`{"record_type":"evidence_receipt_v2"}` + "\n"); err != nil {
		_ = file.Close()
		t.Fatalf("append mixed record: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	for _, command := range []string{"chain", "completeness"} {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runRoot(t, command, "--json", "--key", fixture.keyHex, path)
			if code == cliutil.ExitOK {
				t.Fatalf("mixed bare v1 %s input accepted: stdout=%q stderr=%q", command, stdout, stderr)
			}
		})
	}
}

// TestChainCLIShowsCompletenessReasonForATailDroppedChain proves the PATH, not
// the formatter. The sibling unit test hands emitScorecard a reason and checks
// it prints; that cannot fail if the analyzer stopped classifying a missing
// close, or if the chain command stopped feeding the analyzer's reason into the
// scorecard. This drives the real command over two real chains that differ only
// by the presence of session_close.
//
// The distinction matters because integrity and completeness answer different
// questions here. Dropping the tail leaves a valid prefix, so the chain still
// verifies and still exits 0, which is correct. What an operator needs is to see
// that the run ended abnormally rather than bounded, and both map to LIMITED, so
// the status alone cannot carry it.
func TestChainCLIShowsCompletenessReasonForATailDroppedChain(t *testing.T) {
	t.Parallel()
	const (
		runNonce  = "run-chain-reason"
		openNonce = "open-chain-reason"
	)

	closedFixture := newCompletenessFixture(t)
	actionID := "action-chain-reason"
	closedPath := writeChainRecorderJSONL(t, []receipt.Receipt{
		closedFixture.open(runNonce, openNonce),
		closedFixture.intent(runNonce, actionID),
		closedFixture.outcome(runNonce, actionID),
		closedFixture.close(runNonce, openNonce),
	})

	// Same shape, with the close dropped: the tail-drop this guards against.
	openFixture := newCompletenessFixture(t)
	droppedPath := writeChainRecorderJSONL(t, []receipt.Receipt{
		openFixture.open(runNonce, openNonce),
		openFixture.intent(runNonce, actionID),
		openFixture.outcome(runNonce, actionID),
	})

	closedOut, stderr, code := runRoot(t, "chain", "--key", closedFixture.keyHex, closedPath)
	if code != cliutil.ExitOK {
		t.Fatalf("closed chain should verify: code=%d stdout=%q stderr=%q", code, closedOut, stderr)
	}
	droppedOut, stderr, code := runRoot(t, "chain", "--key", openFixture.keyHex, droppedPath)
	if code != cliutil.ExitOK {
		t.Fatalf("a tail-dropped chain is a valid prefix and must still verify: code=%d stderr=%q", code, stderr)
	}

	if !strings.Contains(closedOut, "reason="+string(completeness.ReasonBoundedClosed)) {
		t.Fatalf("closed chain output does not report bounded_closed:\n%s", closedOut)
	}
	if !strings.Contains(droppedOut, "reason="+string(completeness.ReasonAbnormalEnd)) {
		t.Fatalf("tail-dropped chain output does not report abnormal_end:\n%s", droppedOut)
	}

	closedLine := scorecardLine(t, closedOut)
	droppedLine := scorecardLine(t, droppedOut)
	if closedLine == droppedLine {
		t.Fatalf("a bounded chain and a tail-dropped one print the same completeness line: %s", closedLine)
	}
}

func TestChainCLIRejectsLifecycleBrokenChain(t *testing.T) {
	t.Parallel()
	fixture := newCompletenessFixture(t)
	path := writeChainRecorderJSONL(t, []receipt.Receipt{
		fixture.open("run-chain-broken", "open-chain-broken"),
		fixture.outcome("run-chain-broken", "outcome-without-intent"),
	})

	stdout, stderr, code := runRoot(t, "chain", "--json", "--key", fixture.keyHex, path)
	if code != cliutil.ExitGeneral {
		t.Fatalf("lifecycle-broken chain code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
	}
	var report chainReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout)
	}
	if report.Valid || report.Scorecard == nil {
		t.Fatalf("lifecycle-broken chain accepted or omitted scorecard: %+v", report)
	}
	if report.Scorecard.Authentic.Status != "FAIL" || report.Scorecard.Untampered.Status != "FAIL" {
		t.Fatalf("lifecycle-broken scorecard left a pass: %+v", report.Scorecard)
	}
	if !strings.Contains(report.Error, "lifecycle: chain_broken") {
		t.Fatalf("missing lifecycle error: %q", report.Error)
	}
	if report.BrokenAtSeq == 0 {
		t.Fatalf("lifecycle break sequence omitted: %+v", report)
	}
	if report.Scorecard.Untampered.BrokenAtSeq != report.BrokenAtSeq {
		t.Fatalf("scorecard break sequence = %d, want lifecycle break sequence %d: %+v",
			report.Scorecard.Untampered.BrokenAtSeq, report.BrokenAtSeq, report.Scorecard.Untampered)
	}
}

func TestChainCLIPreservesIntegrityFailureInsteadOfRelabelingItAsLifecycle(t *testing.T) {
	t.Parallel()
	fixture := newCompletenessFixture(t)
	chain := []receipt.Receipt{
		fixture.open("run-integrity-broken", "open-integrity-broken"),
		fixture.close("run-integrity-broken", "open-integrity-broken"),
	}
	chain[1].ActionRecord.Target = "https://api.vendor.example/forged"
	path := writeChainRecorderJSONL(t, chain)

	stdout, stderr, code := runRoot(t, "chain", "--json", "--key", fixture.keyHex, path)
	if code != cliutil.ExitGeneral {
		t.Fatalf("integrity-broken chain code=%d, want %d stdout=%q stderr=%q", code, cliutil.ExitGeneral, stdout, stderr)
	}
	var report chainReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout)
	}
	if strings.Contains(report.Error, "lifecycle:") || !strings.Contains(report.Error, "signature") {
		t.Fatalf("integrity error relabeled as lifecycle: %q", report.Error)
	}
}

// The bare-v1 detector reads the whole file before deciding a route, so its
// failure paths decide whether an unreadable or oversized file is refused or
// silently falls through to the v2 route. Each case below drives the real
// command so the exit path is proven, not just the helper.

func TestChainRefusesOversizedEvidenceFile(t *testing.T) {
	t.Parallel()
	fixture := newCompletenessFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "oversized.jsonl")
	line := append(bytes.Repeat([]byte("a"), 11<<20), '\n')
	if err := os.WriteFile(path, line, 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := runChain(&stdout, &stderr, path, chainOptions{signerKey: fixture.keyHex})
	if err == nil {
		t.Fatalf("oversized evidence line accepted: stdout=%q", stdout.String())
	}
	// Ordinary malformed input is classified as not-bare-v1 and refused later on
	// a different route. Pinning the detector scan error is what proves this test
	// exercises the line-length bound rather than generic rejection.
	// The detector reads the whole file before classifying it, so the reader's
	// total-size bound is what stops an oversized input from being buffered.
	// Pinning that message is what proves this test exercises the size bound
	// rather than ordinary malformed-input rejection.
	if !strings.Contains(err.Error(), "input exceeds") {
		t.Fatalf("oversized file must fail on the reader size bound: err=%v", err)
	}
	if got := exitCodeFor(err); got != cliutil.ExitConfig {
		t.Fatalf("oversized line exit=%d, want %d", got, cliutil.ExitConfig)
	}
}

func TestChainAcceptsBareV1JSONLWithBlankLines(t *testing.T) {
	t.Parallel()
	fixture := newCompletenessFixture(t)
	path := writeCompletenessJSONL(t, []receipt.Receipt{
		fixture.open("run-blank-lines", "open-blank-lines"),
		fixture.close("run-blank-lines", "open-blank-lines"),
	})
	file, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	if _, err := file.WriteString("\n   \n"); err != nil {
		_ = file.Close()
		t.Fatalf("append blank lines: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	stdout, stderr, code := runRoot(t, "chain", "--json", "--key", fixture.keyHex, path)
	if code != cliutil.ExitOK {
		t.Fatalf("blank-line bare v1 chain should verify: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

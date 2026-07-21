// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// buildRotatedChainJSONL emits `aN` receipts under key A, then reopens the same
// evidence dir with key B (which triggers the emitter's rotation -> new segment)
// and emits `bN` more. Returns the evidence dir and both public keys.
func buildRotatedChainJSONL(t *testing.T, aN, bN int) (dir string, pubA, pubB ed25519.PublicKey) {
	t.Helper()
	dir = t.TempDir()

	pa, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	pb, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}

	emitInto(t, dir, privA, aN, 0)
	emitInto(t, dir, privB, bN, aN)
	return dir, pa, pb
}

func buildEndorsedRotatedChainJSONL(t *testing.T) (dir string, pubA ed25519.PublicKey, endorsementPath string) {
	t.Helper()
	dir = t.TempDir()
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}
	emitInto(t, dir, privA, 2, 0)
	emitInto(t, dir, privB, 2, 2)
	receipts, err := receipt.ExtractReceiptsFromSessionDir(dir, "proxy")
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	boundary := -1
	for i := 1; i < len(receipts); i++ {
		if receipts[i].ActionRecord.KeyTransition != nil {
			boundary = i
			break
		}
	}
	if boundary < 1 {
		t.Fatal("rotated fixture has no key transition")
	}
	prior := receipts[boundary-1]
	priorHash, err := receipt.ReceiptHash(prior)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	endorsement, err := receipt.SignRotationEndorsement(receipt.RotationEndorsement{
		SessionID:     "proxy",
		PriorFinalSeq: prior.ActionRecord.ChainSeq,
		PriorTailHash: priorHash,
		NewSignerKey:  receipts[boundary].SignerKey,
		RotatedAt:     time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}, privA)
	if err != nil {
		t.Fatalf("SignRotationEndorsement: %v", err)
	}
	data, err := json.Marshal(endorsement)
	if err != nil {
		t.Fatalf("Marshal endorsement: %v", err)
	}
	endorsementPath = filepath.Join(dir, "rotation-endorsement.json")
	if err := os.WriteFile(endorsementPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile endorsement: %v", err)
	}
	return dir, pubA, endorsementPath
}

func emitInto(t *testing.T, dir string, priv ed25519.PrivateKey, count, startIdx int) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:  rec,
		PrivKey:   priv,
		Principal: "test",
		Actor:     "test",
	})
	if err := emitter.InitError(); err != nil {
		t.Fatalf("emitter init error: %v", err)
	}
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for i := range count {
		if err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   "allow",
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    fmt.Sprintf("https://example.com/%d", startIdx+i),
			SessionID: "agent-session",
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
}

func TestVerifyReceiptCmd_BlankKeyDoesNotDowngradeToTOFU(t *testing.T) {
	dir, _, _ := buildRotatedChainJSONL(t, 2, 2)

	var buf bytes.Buffer
	cmd := VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", " "})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected blank --key to fail instead of falling back to trust-on-first-use")
	}
	if !strings.Contains(err.Error(), "--key was provided but no valid signer keys were resolved") {
		t.Fatalf("err = %v, want explicit blank-key rejection", err)
	}
}

func TestVerifyReceiptCmd_RotatedChainNeedsBothKeys(t *testing.T) {
	dir, pubA, pubB := buildRotatedChainJSONL(t, 3, 2)
	keyA := hex.EncodeToString(pubA)
	keyB := hex.EncodeToString(pubB)

	// Only key A trusted: the rotation to B must be flagged.
	var buf bytes.Buffer
	cmd := VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", keyA})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected failure: rotation to an untrusted key must be flagged")
	}
	if !strings.Contains(buf.String(), "Untrusted signer key: "+keyB) {
		t.Errorf("expected untrusted key %s in output, got: %s", keyB, buf.String())
	}

	// Both keys trusted: verifies end-to-end across the rotation.
	buf.Reset()
	cmd = VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", keyA, "--key", keyB})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rotated chain with both keys trusted must verify: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "CHAIN VALID") {
		t.Errorf("expected CHAIN VALID, got: %s", out)
	}
	if !strings.Contains(out, "signing key rotated") {
		t.Errorf("expected rotation note, got: %s", out)
	}
	if !strings.Contains(out, keyA) || !strings.Contains(out, keyB) {
		t.Errorf("expected both segment keys reported, got: %s", out)
	}
}

func TestVerifyReceiptCmd_RotatedChainTrustOnFirstUseFlags(t *testing.T) {
	dir, _, pubB := buildRotatedChainJSONL(t, 2, 2)
	keyB := hex.EncodeToString(pubB)

	var buf bytes.Buffer
	cmd := VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// No --key: trust-on-first-use adopts A; rotation to B must be flagged.
	cmd.SetArgs([]string{"--chain", dir})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected failure: trust-on-first-use must flag the rotation")
	}
	if !strings.Contains(buf.String(), keyB) {
		t.Errorf("expected the rotated-to key in output, got: %s", buf.String())
	}
}

func TestVerifyReceiptCmd_RotationEndorsementAuthorizesSuccessor(t *testing.T) {
	dir, pubA, endorsementPath := buildEndorsedRotatedChainJSONL(t)
	keyA := hex.EncodeToString(pubA)

	var buf bytes.Buffer
	cmd := VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", keyA, "--rotation-endorsement", endorsementPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("endorsed CLI verification failed: %v\n%s", err, buf.String())
	}
	if out := buf.String(); !strings.Contains(out, "CHAIN VALID") || !strings.Contains(out, "(endorsed)") {
		t.Fatalf("endorsed trust basis missing from output:\n%s", out)
	}

	buf.Reset()
	cmd = VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--rotation-endorsement", endorsementPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "trusted root key") {
		t.Fatalf("unpinned endorsement verification did not fail closed: err=%v output=%s", err, buf.String())
	}
}

func TestVerifyReceiptCmd_RotationEndorsementRejectsJSONLSessionMismatch(t *testing.T) {
	dir, pubA, endorsementPath := buildEndorsedRotatedChainJSONL(t)
	query, err := recorder.QuerySession(dir, "proxy", nil)
	if err != nil {
		t.Fatalf("QuerySession: %v", err)
	}
	if len(query.Entries) == 0 {
		t.Fatal("fixture has no recorder entries")
	}
	writeEntries := func(name string, mutate func(int, *recorder.Entry)) string {
		t.Helper()
		entries := append([]recorder.Entry(nil), query.Entries...)
		for i := range entries {
			mutate(i, &entries[i])
			if i == 0 {
				entries[i].PrevHash = recorder.GenesisHash
			} else {
				entries[i].PrevHash = entries[i-1].Hash
			}
			entries[i].Hash = recorder.ComputeHash(entries[i])
		}
		path := filepath.Join(t.TempDir(), name)
		file, openErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- test-controlled temp path.
		if openErr != nil {
			t.Fatalf("OpenFile: %v", openErr)
		}
		enc := json.NewEncoder(file)
		for _, entry := range entries {
			if encodeErr := enc.Encode(entry); encodeErr != nil {
				_ = file.Close()
				t.Fatalf("Encode entry: %v", encodeErr)
			}
		}
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("Close: %v", closeErr)
		}
		return path
	}
	foreignPath := writeEntries("mixed.jsonl", func(i int, entry *recorder.Entry) {
		if i > 0 {
			entry.SessionID = "other"
		}
	})

	var buf bytes.Buffer
	cmd := VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{foreignPath, "--session", "proxy", "--key", hex.EncodeToString(pubA), "--rotation-endorsement", endorsementPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "mixes recorder sessions") {
		t.Fatalf("foreign-session JSONL accepted: err=%v output=%s", err, buf.String())
	}

	foreignPath = writeEntries("foreign.jsonl", func(_ int, entry *recorder.Entry) {
		entry.SessionID = "other"
	})
	buf.Reset()
	cmd = VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{foreignPath, "--session", "proxy", "--key", hex.EncodeToString(pubA), "--rotation-endorsement", endorsementPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), `endorsed receipt session "proxy" does not match evidence session "other"`) {
		t.Fatalf("consistent foreign-session JSONL accepted: err=%v output=%s", err, buf.String())
	}
}

func TestVerifyReceiptCmd_RotationEndorsementFlagConflicts(t *testing.T) {
	dir, pubA, endorsementPath := buildEndorsedRotatedChainJSONL(t)
	keyA := hex.EncodeToString(pubA)
	files, err := filepath.Glob(filepath.Join(dir, "evidence-proxy-*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("find evidence JSONL: files=%v err=%v", files, err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing endorsement file",
			args:    []string{"--chain", dir, "--key", keyA, "--rotation-endorsement", filepath.Join(dir, "missing.json")},
			wantErr: "loading --rotation-endorsement",
		},
		{
			name:    "fleet report",
			args:    []string{"ignored.json", "--fleet-report", "--key", keyA, "--rotation-endorsement", endorsementPath},
			wantErr: "cannot be combined with --fleet-report",
		},
		{
			name:    "chain clean report",
			args:    []string{"--chain", dir, "--key", keyA, "--clean-report", filepath.Join(dir, "clean.json"), "--rotation-endorsement", endorsementPath},
			wantErr: "cannot be combined with --clean-report",
		},
		{
			name:    "jsonl clean report",
			args:    []string{files[0], "--key", keyA, "--clean-report", filepath.Join(dir, "clean.json"), "--rotation-endorsement", endorsementPath},
			wantErr: "cannot be combined with --clean-report",
		},
		{
			name:    "single receipt",
			args:    []string{"ignored.json", "--key", keyA, "--rotation-endorsement", endorsementPath},
			wantErr: "requires --chain or a JSONL receipt file",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := VerifyReceiptCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want %q; output=%s", err, tc.wantErr, buf.String())
			}
		})
	}
}

func TestTranscriptRootCmd_RotatedChainNeedsBothKeys(t *testing.T) {
	dir, pubA, pubB := buildRotatedChainJSONL(t, 2, 3)
	keyA := hex.EncodeToString(pubA)
	keyB := hex.EncodeToString(pubB)

	// Both keys: produces a transcript root over the full rotated chain.
	var buf bytes.Buffer
	cmd := TranscriptRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", keyA, "--key", keyB})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("transcript root over rotated chain must succeed with both keys: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "Receipt count: 7") {
		t.Errorf("expected 7 receipts in transcript root, got: %s", buf.String())
	}

	// Only key A: must fail (rotation key untrusted).
	buf.Reset()
	cmd = TranscriptRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", keyA})
	if err := cmd.Execute(); err == nil {
		t.Fatal("transcript root must fail when a segment key is untrusted")
	}
}

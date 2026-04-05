// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyReceiptCmd_ValidReceipt(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ar := receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       time.Now().UTC(),
		Target:          "https://example.com/api",
		Verdict:         "block",
		Transport:       "fetch",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
	}
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := receipt.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "OK:") {
		t.Errorf("expected OK in output, got: %s", output)
	}
	if !strings.Contains(output, ar.ActionID) {
		t.Errorf("expected action_id in output, got: %s", output)
	}
}

func TestVerifyReceiptCmd_WithExpectedKey(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKey := priv.Public().(ed25519.PublicKey)
	keyHex := hex.EncodeToString(pubKey)

	ar := receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionWrite,
		Timestamp:       time.Now().UTC(),
		Target:          "https://api.example.com/data",
		Verdict:         "allow",
		Transport:       "forward",
		SideEffectClass: receipt.SideEffectExternalWrite,
		Reversibility:   receipt.ReversibilityCompensatable,
	}
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := receipt.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--key", keyHex})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !strings.Contains(buf.String(), "OK:") {
		t.Errorf("expected OK in output, got: %s", buf.String())
	}
}

func TestVerifyReceiptCmd_WrongKey(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ar := receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       time.Now().UTC(),
		Target:          "https://example.com",
		Verdict:         "block",
		Transport:       "fetch",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
	}
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := receipt.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Generate a different key
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--key", hex.EncodeToString(otherPub)})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for wrong key")
	}

	if !strings.Contains(buf.String(), "FAILED") {
		t.Errorf("expected FAILED in output, got: %s", buf.String())
	}
}

func TestVerifyReceiptCmd_InvalidFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestVerifyReceiptCmd_MissingFile(t *testing.T) {
	t.Parallel()

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"/nonexistent/receipt.json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestVerifyReceiptCmd_NoArgs(t *testing.T) {
	t.Parallel()

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestVerifyReceiptCmd_ReceiptWithMethodShowsFullRecord(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ar := receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       time.Now().UTC(),
		Target:          "https://example.com/api",
		Verdict:         "block",
		Transport:       "fetch",
		Method:          "GET",
		Layer:           "blocklist",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
	}
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := receipt.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	// When method/layer are present, full record JSON is printed
	if !strings.Contains(output, "Full record:") {
		t.Errorf("expected full record in output, got: %s", output)
	}
}

// buildChainJSONL creates a JSONL file with a valid receipt chain using the
// emitter, which handles chain state (prev_hash, seq) automatically.
func buildChainJSONL(t *testing.T, count int) (string, ed25519.PublicKey) {
	t.Helper()

	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}

	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "test-chain-hash",
		Principal:  "test",
		Actor:      "test",
	})

	for i := range count {
		err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   "allow",
			Transport: "fetch",
			Method:    "GET",
			Target:    "https://example.com/" + string(rune('a'+i)),
		})
		if err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	// Find the JSONL file
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, de := range entries {
		if strings.HasSuffix(de.Name(), ".jsonl") {
			return filepath.Join(dir, de.Name()), priv.Public().(ed25519.PublicKey)
		}
	}
	t.Fatal("no JSONL file found")
	return "", nil
}

func TestVerifyReceiptCmd_ChainValid(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 5)

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CHAIN VALID") {
		t.Errorf("expected CHAIN VALID, got: %s", output)
	}
	if !strings.Contains(output, "Receipts:  5") {
		t.Errorf("expected 5 receipts, got: %s", output)
	}
}

func TestVerifyReceiptCmd_ChainWithKey(t *testing.T) {
	t.Parallel()

	path, pubKey := buildChainJSONL(t, 3)
	keyHex := hex.EncodeToString(pubKey)

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--key", keyHex})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !strings.Contains(buf.String(), "CHAIN VALID") {
		t.Errorf("expected CHAIN VALID, got: %s", buf.String())
	}
}

func TestTranscriptRootCmd_Valid(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 4)

	cmd := TranscriptRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Transcript Root") {
		t.Errorf("expected Transcript Root header, got: %s", output)
	}
	if !strings.Contains(output, "Receipt count: 4") {
		t.Errorf("expected 4 receipts, got: %s", output)
	}
	if !strings.Contains(output, "Root hash:") {
		t.Errorf("expected root hash, got: %s", output)
	}
}

func TestTranscriptRootCmd_NoArgs(t *testing.T) {
	t.Parallel()

	cmd := TranscriptRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestTranscriptRootCmd_MissingFile(t *testing.T) {
	t.Parallel()

	cmd := TranscriptRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"/nonexistent/file.jsonl"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing file")
	}
}

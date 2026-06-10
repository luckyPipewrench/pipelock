// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"

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
	for i := range count {
		if err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   "allow",
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    fmt.Sprintf("https://example.com/%d", startIdx+i),
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
	if !strings.Contains(buf.String(), "Receipt count: 5") {
		t.Errorf("expected 5 receipts in transcript root, got: %s", buf.String())
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

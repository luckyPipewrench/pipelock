// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	sigutil "github.com/luckyPipewrench/pipelock/internal/signing"
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
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected unpinned receipt verification to exit non-zero")
	}

	output := buf.String()
	if !strings.Contains(output, "UNPINNED:") {
		t.Errorf("expected UNPINNED in output, got: %s", output)
	}
	if !strings.Contains(output, unpinnedReceiptBanner) {
		t.Errorf("expected unpinned banner in output, got: %s", output)
	}
	if !strings.Contains(output, ar.ActionID) {
		t.Errorf("expected action_id in output, got: %s", output)
	}
}

func TestVerifyReceiptCmd_AllowUnpinnedValidReceipt(t *testing.T) {
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
	cmd.SetArgs([]string{path, "--allow-unpinned"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !strings.Contains(buf.String(), "UNPINNED:") {
		t.Errorf("expected UNPINNED in output, got: %s", buf.String())
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

func TestVerifyReceiptCmd_FleetReportWithExpectedKey(t *testing.T) {
	t.Parallel()

	pub, path := writeFleetReportFixture(t)
	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--fleet-report", "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"FLEET RECEIPT OK:",
		"Org/Fleet:        pipelab/dogfood",
		"Source batches:   1",
		"Total actions:    2",
		"Mediated fraction: 1",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q:\n%s", want, output)
		}
	}
}

// TestVerifyReceiptCmd_FleetReportHumanKeyID proves --key <hex> verifies a
// report whose signer key id is a human label (not the hex of the public key).
// The trusted-key map is resolved by the envelope's signer key id, so a bare
// hex key must be bound to that id; otherwise the offline-verify flow only ever
// worked when the key id happened to equal the public-key hex.
func TestVerifyReceiptCmd_FleetReportHumanKeyID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, path := writeFleetReportFixtureSigned(t, "fleet-report-2026", pub, priv)

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--fleet-report", "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "FLEET RECEIPT OK:") || !strings.Contains(buf.String(), "Signer:           fleet-report-2026") {
		t.Fatalf("output:\n%s", buf.String())
	}

	// The same human key id with the WRONG public key must still fail closed:
	// binding to the signer id does not bypass the Ed25519 signature check.
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(wrong): %v", err)
	}
	wrongCmd := VerifyReceiptCmd()
	var wrongBuf bytes.Buffer
	wrongCmd.SetOut(&wrongBuf)
	wrongCmd.SetArgs([]string{path, "--fleet-report", "--key", hex.EncodeToString(wrongPub)})
	if err := wrongCmd.Execute(); err == nil {
		t.Fatalf("expected wrong-key verification to fail closed:\n%s", wrongBuf.String())
	}
	if !strings.Contains(wrongBuf.String(), "FAILED:") {
		t.Fatalf("wrong-key output missing FAILED:\n%s", wrongBuf.String())
	}
}

func TestVerifyReceiptCmd_FleetReportRequiresPinByDefault(t *testing.T) {
	t.Parallel()

	_, path := writeFleetReportFixture(t)
	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--fleet-report"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected unpinned fleet report verification to exit non-zero")
	}
	if !strings.Contains(buf.String(), "FLEET RECEIPT UNPINNED:") {
		t.Fatalf("output missing unpinned warning:\n%s", buf.String())
	}
}

func TestVerifyReceiptCmd_FleetReportRejectsSessionSelector(t *testing.T) {
	t.Parallel()

	_, path := writeFleetReportFixture(t)
	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--fleet-report", "--session", "operator"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected --fleet-report with --session to fail")
	}
	if !strings.Contains(err.Error(), "--fleet-report cannot be combined with --session") {
		t.Fatalf("Execute error = %v, want --session conflict", err)
	}
}

func TestVerifyReceiptCmd_FleetReportFailsClosedOnTamper(t *testing.T) {
	t.Parallel()

	pub, path := writeFleetReportFixture(t)
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var env fleetreceipt.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Flip one byte of the signed payload; the Ed25519 signature must no
	// longer verify and the command must exit non-zero with FAILED.
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	payload[0] ^= 0x01
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	tamperedBytes, err := fleetreceipt.MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered.dsse.json")
	if err := os.WriteFile(tamperedPath, tamperedBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{tamperedPath, "--fleet-report", "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected tampered fleet report verification to exit non-zero")
	}
	if !strings.Contains(buf.String(), "FAILED:") {
		t.Fatalf("output missing FAILED marker:\n%s", buf.String())
	}
}

func TestVerifyReceiptCmd_FleetReportRejectsChainSelector(t *testing.T) {
	t.Parallel()

	_, path := writeFleetReportFixture(t)
	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--fleet-report", "--chain", filepath.Dir(path)})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected --fleet-report with --chain to fail")
	}
	if !strings.Contains(err.Error(), "--fleet-report cannot be combined with --chain") {
		t.Fatalf("Execute error = %v, want --chain conflict", err)
	}
}

func TestVerifyReceiptCmd_WithExpectedKeyFile(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubKey := priv.Public().(ed25519.PublicKey)

	ar := receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       time.Now().UTC(),
		Target:          "https://example.com/receipt",
		Verdict:         "allow",
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
	keyPath := filepath.Join(dir, "pub.key")
	if err := os.WriteFile(keyPath, []byte(sigutil.EncodePublicKey(pubKey)), 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--key", keyPath})
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
	cmd.SetArgs([]string{path, "--allow-unpinned"})
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
	cmd.SetArgs([]string{path, "--allow-unpinned"})
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
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}

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

func buildDeferredCleanChainJSONL(t *testing.T) (string, ed25519.PublicKey) {
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
		Principal:  "operator",
		Actor:      "agent",
	})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}

	deferID := receipt.NewActionID()
	if err := emitter.Emit(receipt.EmitOpts{
		ActionID:         deferID,
		Verdict:          config.ActionDefer,
		Transport:        "mcp_stdio",
		Method:           "tools/call",
		Target:           "dangerous_tool",
		DecisionPhase:    receipt.DecisionPhaseDefer,
		DeferID:          deferID,
		ResolutionPolicy: `{"allow_on":{"approval":true}}`,
		SessionID:        "sess-1",
	}); err != nil {
		t.Fatalf("Emit defer: %v", err)
	}
	if err := emitter.Emit(receipt.EmitOpts{
		ActionID:         receipt.NewActionID(),
		ParentActionID:   deferID,
		Verdict:          config.ActionBlock,
		Transport:        "mcp_stdio",
		Method:           "tools/call",
		Target:           "dangerous_tool",
		DecisionPhase:    receipt.DecisionPhaseResolution,
		DeferID:          deferID,
		ResolutionSource: "approval",
		SessionID:        "sess-1",
	}); err != nil {
		t.Fatalf("Emit resolution: %v", err)
	}
	if err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: "fetch",
		Method:    "GET",
		Target:    "https://example.com/ok",
	}); err != nil {
		t.Fatalf("Emit allow: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

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

func buildRestartChainDir(t *testing.T, counts ...int) (string, ed25519.PublicKey) {
	t.Helper()

	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	for i, count := range counts {
		rec, err := recorder.New(recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
			MaxEntriesPerFile:  1,
		}, nil, priv)
		if err != nil {
			t.Fatalf("recorder.New[%d]: %v", i, err)
		}

		emitter := receipt.NewEmitter(receipt.EmitterConfig{
			Recorder:   rec,
			PrivKey:    priv,
			ConfigHash: "test-chain-hash",
			Principal:  "test",
			Actor:      "test",
		})
		if err := emitter.EmitSessionOpen(); err != nil {
			t.Fatalf("EmitSessionOpen[%d]: %v", i, err)
		}

		for j := range count {
			err := emitter.Emit(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   "allow",
				Transport: "fetch",
				Method:    "GET",
				Target:    "https://example.com/restart/" + string(rune('a'+j)),
			})
			if err != nil {
				t.Fatalf("Emit[%d][%d]: %v", i, j, err)
			}
		}
		if err := rec.Close(); err != nil {
			t.Fatalf("recorder.Close[%d]: %v", i, err)
		}
	}

	return dir, pub
}

func TestVerifyReceiptCmd_ChainValid(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 5)

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected unpinned chain verification to exit non-zero")
	}

	output := buf.String()
	if !strings.Contains(output, "CHAIN UNPINNED") {
		t.Errorf("expected CHAIN UNPINNED, got: %s", output)
	}
	if !strings.Contains(output, unpinnedReceiptBanner) {
		t.Errorf("expected unpinned banner, got: %s", output)
	}
	if !strings.Contains(output, "Receipts:  6") {
		t.Errorf("expected 6 receipts, got: %s", output)
	}
}

func TestVerifyReceiptCmd_ChainAllowUnpinned(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 5)

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--allow-unpinned"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CHAIN UNPINNED") {
		t.Errorf("expected CHAIN UNPINNED, got: %s", output)
	}
	if !strings.Contains(output, "Receipts:  6") {
		t.Errorf("expected 6 receipts, got: %s", output)
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

func TestVerifyReceiptCmd_CleanReportJSONLWithDeferPair(t *testing.T) {
	t.Parallel()

	path, pubKey := buildDeferredCleanChainJSONL(t)
	reportPath := filepath.Join(t.TempDir(), "clean-report.json")
	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{path, "--key", hex.EncodeToString(pubKey), "--clean-report", reportPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "CLEAN REPORT VALID") {
		t.Fatalf("output missing clean report success:\n%s", buf.String())
	}
	raw, err := os.ReadFile(filepath.Clean(reportPath))
	if err != nil {
		t.Fatalf("ReadFile(report): %v", err)
	}
	var report cleanActionReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("Unmarshal(report): %v", err)
	}
	if report.Chain.ReceiptCount != 4 || report.Chain.FinalSeq != 3 {
		t.Fatalf("chain summary = %+v, want 4 receipts seq 3", report.Chain)
	}
	if len(report.Actions) != 4 {
		t.Fatalf("actions = %d, want 4", len(report.Actions))
	}
	if report.Actions[1].DecisionPhase != receipt.DecisionPhaseDefer || report.Actions[2].DecisionPhase != receipt.DecisionPhaseResolution {
		t.Fatalf("defer pair phases = (%q,%q)", report.Actions[1].DecisionPhase, report.Actions[2].DecisionPhase)
	}
}

func TestVerifyReceiptCmd_CleanReportRejectsSingleReceipt(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ar := receipt.ActionRecord{
		Version:    receipt.ActionRecordVersion,
		ActionID:   receipt.NewActionID(),
		ActionType: receipt.ActionRead,
		Timestamp:  time.Now().UTC(),
		Target:     "https://example.com/api",
		Verdict:    config.ActionAllow,
		Transport:  "fetch",
	}
	rcpt, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := receipt.Marshal(rcpt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := VerifyReceiptCmd()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{path, "--allow-unpinned", "--clean-report", filepath.Join(t.TempDir(), "report.json")})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--clean-report requires --chain or a JSONL receipt file") {
		t.Fatalf("Execute error = %v, want clean-report input rejection", err)
	}
}

func TestBuildCleanActionReportRejectsBadDeferPairs(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2026, 6, 17, 2, 30, 0, 0, time.UTC)
	deferRecord := receipt.ActionRecord{
		Version:       receipt.ActionRecordVersion,
		ActionID:      "defer-action",
		ActionType:    receipt.ActionWrite,
		Timestamp:     baseTime,
		Target:        "dangerous_tool",
		Verdict:       config.ActionDefer,
		Transport:     "mcp_stdio",
		Method:        "tools/call",
		DecisionPhase: receipt.DecisionPhaseDefer,
		DeferID:       "defer-1",
		Principal:     "operator",
		Actor:         "agent",
		SessionID:     "sess-1",
		PolicyHash:    "policy",
		ChainSeq:      1,
	}
	resolutionRecord := deferRecord
	resolutionRecord.ActionID = "resolution-action"
	resolutionRecord.ParentActionID = deferRecord.ActionID
	resolutionRecord.Verdict = config.ActionBlock
	resolutionRecord.DecisionPhase = receipt.DecisionPhaseResolution
	resolutionRecord.ResolutionSource = "approval"
	resolutionRecord.ChainSeq = 2
	result := receipt.ChainResult{
		Valid:        true,
		ReceiptCount: 2,
		FinalSeq:     2,
		RootHash:     "root",
		SignerKeys:   []string{"key"},
	}

	report, err := buildCleanActionReport("valid", []receipt.Receipt{
		{ActionRecord: deferRecord},
		{ActionRecord: resolutionRecord},
	}, result)
	if err != nil {
		t.Fatalf("buildCleanActionReport valid pair: %v", err)
	}
	if len(report.Actions) != 2 || report.Actions[1].ResolutionSource != "approval" {
		t.Fatalf("report actions = %+v", report.Actions)
	}

	tests := []struct {
		name     string
		records  []receipt.ActionRecord
		wantText string
	}{
		{
			name: "missing_defer_id",
			records: []receipt.ActionRecord{
				func() receipt.ActionRecord {
					r := deferRecord
					r.DeferID = ""
					return r
				}(),
			},
			wantText: "missing defer_id",
		},
		{
			name: "duplicate_defer_id",
			records: []receipt.ActionRecord{
				deferRecord,
				func() receipt.ActionRecord {
					r := deferRecord
					r.ActionID = "second-defer"
					r.ChainSeq = 2
					return r
				}(),
			},
			wantText: "duplicate defer_id",
		},
		{
			name: "resolution_missing_linkage",
			records: []receipt.ActionRecord{
				func() receipt.ActionRecord {
					r := resolutionRecord
					r.ParentActionID = ""
					return r
				}(),
			},
			wantText: "missing defer linkage",
		},
		{
			name:     "missing_resolution",
			records:  []receipt.ActionRecord{deferRecord},
			wantText: "has 0 resolution receipts",
		},
		{
			name: "parent_mismatch",
			records: []receipt.ActionRecord{
				deferRecord,
				func() receipt.ActionRecord {
					r := resolutionRecord
					r.ParentActionID = "other"
					return r
				}(),
			},
			wantText: "resolution parent mismatch",
		},
		{
			name: "resolution_before_defer",
			records: []receipt.ActionRecord{
				deferRecord,
				func() receipt.ActionRecord {
					r := resolutionRecord
					r.ChainSeq = 1
					return r
				}(),
			},
			wantText: "appears before defer receipt",
		},
		{
			name: "identity_changed",
			records: []receipt.ActionRecord{
				deferRecord,
				func() receipt.ActionRecord {
					r := resolutionRecord
					r.Actor = "other-agent"
					return r
				}(),
			},
			wantText: "resolution identity changed",
		},
		{
			name: "non_terminal_verdict",
			records: []receipt.ActionRecord{
				deferRecord,
				func() receipt.ActionRecord {
					r := resolutionRecord
					r.Verdict = config.ActionDefer
					return r
				}(),
			},
			wantText: "resolved to non-terminal verdict",
		},
		{
			name: "unknown_defer_resolution",
			records: []receipt.ActionRecord{
				func() receipt.ActionRecord {
					r := resolutionRecord
					r.DeferID = "unknown"
					return r
				}(),
			},
			wantText: "resolution for unknown defer",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			receipts := make([]receipt.Receipt, 0, len(tc.records))
			for _, record := range tc.records {
				receipts = append(receipts, receipt.Receipt{ActionRecord: record})
			}
			_, err := buildCleanActionReport(tc.name, receipts, result)
			if err == nil || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("buildCleanActionReport() error = %v, want %q", err, tc.wantText)
			}
		})
	}
}

func TestVerifyReceiptCmd_ChainDirAcrossRestart(t *testing.T) {
	t.Parallel()

	dir, pubKey := buildRestartChainDir(t, 2, 2)

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", hex.EncodeToString(pubKey)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CHAIN VALID") {
		t.Errorf("expected CHAIN VALID, got: %s", output)
	}
	if !strings.Contains(output, "Receipts:  6") {
		t.Errorf("expected 6 receipts, got: %s", output)
	}
}

func TestVerifyReceiptCmd_ChainEmpty(t *testing.T) {
	t.Parallel()

	// Write an empty JSONL file (no receipts).
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(emptyPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := VerifyReceiptCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{emptyPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for empty JSONL")
	}
}

func TestTranscriptRootCmd_NoKey(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 3)

	cmd := TranscriptRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{path})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --key not provided")
	}
	if !strings.Contains(err.Error(), "--key is required") {
		t.Errorf("expected --key required error, got: %v", err)
	}
}

func TestTranscriptRootCmd_Valid(t *testing.T) {
	t.Parallel()

	path, pub := buildChainJSONL(t, 4)
	keyHex := hex.EncodeToString(pub)

	cmd := TranscriptRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--key", keyHex, path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Transcript Root") {
		t.Errorf("expected Transcript Root header, got: %s", output)
	}
	if !strings.Contains(output, "Receipt count: 5") {
		t.Errorf("expected 5 receipts, got: %s", output)
	}
	if !strings.Contains(output, "Root hash:") {
		t.Errorf("expected root hash, got: %s", output)
	}
}

func TestTranscriptRootCmd_ChainDirAcrossRestart(t *testing.T) {
	t.Parallel()

	dir, pub := buildRestartChainDir(t, 2, 1)

	cmd := TranscriptRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--chain", dir, "--key", hex.EncodeToString(pub)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Transcript Root") {
		t.Errorf("expected Transcript Root header, got: %s", output)
	}
	if !strings.Contains(output, "Receipt count: 5") {
		t.Errorf("expected 5 receipts, got: %s", output)
	}
}

func TestTranscriptRootCmd_KeyFile(t *testing.T) {
	t.Parallel()

	path, pub := buildChainJSONL(t, 4)
	keyPath := filepath.Join(t.TempDir(), "pub.key")
	if err := os.WriteFile(keyPath, []byte(sigutil.EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}

	cmd := TranscriptRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--key", keyPath, path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !strings.Contains(buf.String(), "Transcript Root") {
		t.Errorf("expected Transcript Root header, got: %s", buf.String())
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

func TestVerifyChainFromFile_ValidChain(t *testing.T) {
	t.Parallel()

	path, pubKey := buildChainJSONL(t, 3)
	keyHex := hex.EncodeToString(pubKey)

	var buf bytes.Buffer
	err := verifyChainFromFile(&buf, path, []string{keyHex})
	if err != nil {
		t.Fatalf("verifyChainFromFile: %v", err)
	}
	if !strings.Contains(buf.String(), "CHAIN VALID") {
		t.Errorf("expected CHAIN VALID, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "Receipts:  4") {
		t.Errorf("expected 4 receipts, got: %s", buf.String())
	}
}

func TestVerifyChainFromFile_BadSignature(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 2)

	// Use a different key to force signature mismatch.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongKeyHex := hex.EncodeToString(otherPub)

	var buf bytes.Buffer
	err = verifyChainFromFile(&buf, path, []string{wrongKeyHex})
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
	if !strings.Contains(buf.String(), "CHAIN BROKEN") {
		t.Errorf("expected CHAIN BROKEN, got: %s", buf.String())
	}
}

func TestVerifyChainFromFile_EmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(emptyPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := verifyChainFromFile(&buf, emptyPath, nil)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if !strings.Contains(buf.String(), "No receipts found") {
		t.Errorf("expected 'No receipts found' in output, got: %s", buf.String())
	}
}

func TestVerifyChain_ValidReceiptsNoKey(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 4)
	receipts, err := receipt.ExtractReceipts(path)
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}

	var buf bytes.Buffer
	err = verifyChain(&buf, "test-chain", receipts, nil)
	if err == nil {
		t.Fatal("expected unpinned chain verification to fail closed")
	}
	if !strings.Contains(buf.String(), "CHAIN UNPINNED") {
		t.Errorf("expected CHAIN UNPINNED, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "Receipts:  5") {
		t.Errorf("expected 5 receipts, got: %s", buf.String())
	}

	buf.Reset()
	err = verifyChainWithOptions(&buf, "test-chain", receipts, nil, true)
	if err != nil {
		t.Fatalf("verifyChainWithOptions allow unpinned: %v", err)
	}
	if !strings.Contains(buf.String(), "CHAIN UNPINNED") {
		t.Errorf("expected CHAIN UNPINNED, got: %s", buf.String())
	}
}

func TestVerifyChain_EmptySlice(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := verifyChain(&buf, "empty-chain", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty receipt slice")
	}
	if !strings.Contains(buf.String(), "No receipts found") {
		t.Errorf("expected 'No receipts found' in output, got: %s", buf.String())
	}
}

func TestVerifyChainFromFile_NonexistentFile(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := verifyChainFromFile(&buf, "/nonexistent/path/receipt.jsonl", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "extracting receipts") {
		t.Errorf("expected 'extracting receipts' in error, got: %v", err)
	}
}

func TestVerifyChain_WrongKeyBreaksChain(t *testing.T) {
	t.Parallel()

	path, _ := buildChainJSONL(t, 3)
	receipts, err := receipt.ExtractReceipts(path)
	if err != nil {
		t.Fatalf("ExtractReceipts: %v", err)
	}

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongKeyHex := hex.EncodeToString(otherPub)

	var buf bytes.Buffer
	err = verifyChain(&buf, "wrong-key-chain", receipts, []string{wrongKeyHex})
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
	if !strings.Contains(buf.String(), "CHAIN BROKEN") {
		t.Errorf("expected CHAIN BROKEN, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "Broke at:") {
		t.Errorf("expected 'Broke at' detail, got: %s", buf.String())
	}
}

func TestResolveExpectedKeyHexesWrapsFailedKey(t *testing.T) {
	t.Parallel()

	_, err := resolveExpectedKeyHexes([]string{"not-a-key"})
	if err == nil {
		t.Fatal("expected invalid key to fail")
	}
	if !strings.Contains(err.Error(), `resolving --key "not-a-key"`) {
		t.Fatalf("expected failing key in error, got %v", err)
	}
}

func writeFleetReportFixture(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return writeFleetReportFixtureSigned(t, hex.EncodeToString(pub), pub, priv)
}

func writeFleetReportFixtureSigned(t *testing.T, keyID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (ed25519.PublicKey, string) {
	t.Helper()
	statement := fleetreceipt.Statement{
		Type: fleetreceipt.StatementType,
		Subject: []fleetreceipt.Subject{{
			Name:   "conductor-audit-batch:pipelab/dogfood/pl-1/audit-1",
			Digest: fleetreceipt.Digest{SHA256: testHexSHA256("envelope")},
		}},
		PredicateType: fleetreceipt.PredicateType,
		Predicate: fleetreceipt.Predicate{
			SchemaVersion:     1,
			ReportID:          "01934e1c-cd60-7abc-823a-d6f5e6f7a8b9",
			GeneratedAt:       "2026-06-13T12:00:00Z",
			OrgID:             "pipelab",
			FleetID:           "dogfood",
			ReportWindow:      fleetreceipt.TimeWindow{Start: "2026-06-13T11:00:00Z", End: "2026-06-13T12:00:00Z"},
			VerificationLevel: fleetreceipt.VerificationLevelL1,
			Conductor:         fleetreceipt.Conductor{ID: "conductor"},
			SourceBatches: []fleetreceipt.SourceBatch{{
				OrgID:           "pipelab",
				FleetID:         "dogfood",
				InstanceID:      "pl-1",
				BatchID:         "audit-1",
				SeqStart:        1,
				SeqEnd:          2,
				EventCount:      2,
				PayloadSHA256:   testHexSHA256("payload"),
				PayloadBytes:    512,
				EnvelopeHash:    testHexSHA256("envelope"),
				SegmentTailHash: testHexSHA256("tail"),
				EmittedAt:       "2026-06-13T12:00:00Z",
				ReceivedAt:      "2026-06-13T12:00:00Z",
				SignatureKeyIDs: []string{"audit-key"},
			}},
			Summary: fleetreceipt.Summary{
				TotalActions: 2,
				ByFollower:   map[string]uint64{"pl-1": 2},
				ByVerdict:    map[string]uint64{"allow": 1, "block": 1},
			},
			Completeness: fleetreceipt.Completeness{
				ObservedActions:        2,
				DroppedObservedActions: 0,
				MediatedActions:        2,
				MediatedFraction:       "1",
				Basis:                  "included_signed_audit_batches",
				Claim:                  "fraction of observed fleet action records in included signed audit batches that were mediated by Pipelock",
				NonClaim:               "does not prove no bypass occurred outside Pipelock, outside enrolled followers, or outside the report window",
			},
		},
	}
	env, err := fleetreceipt.SignStatement(statement, keyID, priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	data, err := fleetreceipt.MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "fleet-receipt.dsse.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return pub, path
}

func testHexSHA256(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

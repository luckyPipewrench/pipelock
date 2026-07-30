// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestReceiptRotationEndorseCmdCreatesVerifiedArtifact(t *testing.T) {
	dir := t.TempDir()
	pubA, privA := generateRotationTestKey(t)
	_, privB := generateRotationTestKey(t)
	emitClosedInto(t, dir, privA, 2, 0)

	priorPath := saveRotationTestKey(t, dir, "prior.key", privA)
	newPath := saveRotationTestKey(t, dir, "new.key", privB)
	outPath := filepath.Join(dir, "rotation.json")
	now := time.Date(2026, 7, 30, 15, 4, 5, 123, time.UTC)

	var out bytes.Buffer
	cmd := receiptRotationEndorseCmd(func() time.Time { return now })
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--chain", dir,
		"--session", "proxy",
		"--prior-key-file", priorPath,
		"--new-key-file", newPath,
		"--root-key", hex.EncodeToString(pubA),
		"--out", outPath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}

	endorsement, err := receipt.LoadRotationEndorsementFile(outPath)
	if err != nil {
		t.Fatalf("LoadRotationEndorsementFile: %v", err)
	}
	receipts, err := receipt.ExtractReceiptsFromSessionDir(dir, "proxy")
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	tail := receipts[len(receipts)-1]
	tailHash, err := receipt.ReceiptHash(tail)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	if endorsement.SessionID != "proxy" ||
		endorsement.PriorSignerKey != hex.EncodeToString(pubA) ||
		endorsement.PriorFinalSeq != tail.ActionRecord.ChainSeq ||
		endorsement.PriorTailHash != tailHash ||
		endorsement.RotatedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("endorsement does not match the verified tail: %#v", endorsement)
	}
	if endorsement.NewSignerKey != hex.EncodeToString(privB.Public().(ed25519.PublicKey)) {
		t.Fatalf("successor = %q, want new key", endorsement.NewSignerKey)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
	if !strings.Contains(out.String(), "Pipelock remains stopped") {
		t.Fatalf("operator restart warning missing:\n%s", out.String())
	}
}

func TestReceiptRotationEndorseCmdSupportsPreviouslyEndorsedChain(t *testing.T) {
	dir := t.TempDir()
	pubA, privA := generateRotationTestKey(t)
	_, privB := generateRotationTestKey(t)
	_, privC := generateRotationTestKey(t)

	emitClosedInto(t, dir, privA, 1, 0)
	receiptsA, err := receipt.ExtractReceiptsFromSessionDir(dir, "proxy")
	if err != nil {
		t.Fatalf("extract A: %v", err)
	}
	endorsementAB := signRotationTestEndorsement(t, receiptsA[len(receiptsA)-1], "proxy", privA, privB)
	endorsementABPath := saveRotationTestEndorsement(t, dir, "rotation-ab.json", endorsementAB)
	emitClosedInto(t, dir, privB, 1, 1)

	priorPath := saveRotationTestKey(t, dir, "prior-b.key", privB)
	reusedPath := saveRotationTestKey(t, dir, "reused-a.key", privA)
	reusedCmd := receiptRotationEndorseCmd(time.Now)
	reusedCmd.SilenceUsage = true
	reusedCmd.SetArgs([]string{
		"--chain", dir,
		"--prior-key-file", priorPath,
		"--new-key-file", reusedPath,
		"--root-key", hex.EncodeToString(pubA),
		"--rotation-endorsement", endorsementABPath,
		"--out", filepath.Join(dir, "rotation-ba.json"),
	})
	if err := reusedCmd.Execute(); err == nil || !strings.Contains(err.Error(), "retired keys must not be reinstated") {
		t.Fatalf("reused successor error = %v, want retired-key refusal", err)
	}

	newPath := saveRotationTestKey(t, dir, "new-c.key", privC)
	outPath := filepath.Join(dir, "rotation-bc.json")
	cmd := receiptRotationEndorseCmd(time.Now)
	cmd.SetArgs([]string{
		"--chain", dir,
		"--prior-key-file", priorPath,
		"--new-key-file", newPath,
		"--root-key", hex.EncodeToString(pubA),
		"--rotation-endorsement", endorsementABPath,
		"--out", outPath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute previously endorsed chain: %v", err)
	}
	if _, err := receipt.LoadRotationEndorsementFile(outPath); err != nil {
		t.Fatalf("new endorsement invalid: %v", err)
	}
}

func TestReceiptRotationEndorseCmdFailsClosed(t *testing.T) {
	t.Run("relative output path", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), "rotation.json")
		if err == nil || !strings.Contains(err.Error(), "--out must be absolute") {
			t.Fatalf("error = %v, want absolute-path refusal", err)
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "receipt chain is empty") {
			t.Fatalf("error = %v, want empty-chain refusal", err)
		}
	})

	t.Run("malformed chain", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte("{not-json}\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "extract receipt chain") {
			t.Fatalf("error = %v, want malformed-chain refusal", err)
		}
	})

	t.Run("open chain", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		rec, err := recorder.New(recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		}, nil, privA)
		if err != nil {
			t.Fatalf("recorder.New: %v", err)
		}
		t.Cleanup(func() { _ = rec.Close() })
		emitter := receipt.NewEmitter(receipt.EmitterConfig{
			Recorder: rec,
			PrivKey:  privA,
		})
		if err := emitter.EmitSessionOpen(); err != nil {
			t.Fatalf("EmitSessionOpen: %v", err)
		}
		if err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   "allow",
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    "https://api.vendor.example/open",
			SessionID: "agent-session",
		}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		if err := rec.Close(); err != nil {
			t.Fatalf("recorder.Close: %v", err)
		}

		err = executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "lacks a graceful shutdown seal") {
			t.Fatalf("error = %v, want open-chain refusal", err)
		}
	})

	t.Run("active recorder holds ceremony lock", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		rec, err := recorder.New(recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		}, nil, privA)
		if err != nil {
			t.Fatalf("recorder.New: %v", err)
		}
		t.Cleanup(func() { _ = rec.Close() })

		err = executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "requires a stopped recorder") {
			t.Fatalf("error = %v, want active-recorder refusal", err)
		}
	})

	t.Run("non-graceful close reason", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedIntoWithReason(t, dir, privA, 1, 0, "crash_recovery")

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "lacks a graceful shutdown seal") {
			t.Fatalf("error = %v, want non-graceful-close refusal", err)
		}
	})

	t.Run("wrong pinned root", func(t *testing.T) {
		dir := t.TempDir()
		_, privA := generateRotationTestKey(t)
		pubWrong, _ := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubWrong), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "not valid from the pinned root") {
			t.Fatalf("error = %v, want pinned-root refusal", err)
		}
	})

	t.Run("invalid pinned root", func(t *testing.T) {
		dir := t.TempDir()
		_, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, "not-a-public-key", filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "load --root-key") {
			t.Fatalf("error = %v, want invalid-root refusal", err)
		}
	})

	t.Run("empty pinned root", func(t *testing.T) {
		dir := t.TempDir()
		_, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, "", filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "at least one non-empty --root-key") {
			t.Fatalf("error = %v, want empty-root refusal", err)
		}
	})

	t.Run("invalid prior endorsement", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)
		priorPath := saveRotationTestKey(t, dir, "prior.json", privA)
		newPath := saveRotationTestKey(t, dir, "new.json", privB)

		cmd := receiptRotationEndorseCmd(time.Now)
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{
			"--chain", dir,
			"--prior-key-file", priorPath,
			"--new-key-file", newPath,
			"--root-key", hex.EncodeToString(pubA),
			"--rotation-endorsement", filepath.Join(dir, "missing-endorsement.json"),
			"--out", filepath.Join(dir, "rotation.json"),
		})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "load prior rotation endorsement") {
			t.Fatalf("error = %v, want prior-endorsement load refusal", err)
		}
	})

	t.Run("retiring key does not sign tail", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privWrong := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)

		err := executeRotationEndorseTestCmd(t, dir, privWrong, privB, hex.EncodeToString(pubA), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "retiring key does not sign") {
			t.Fatalf("error = %v, want retiring-key refusal", err)
		}
	})

	t.Run("same successor key", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)

		err := executeRotationEndorseTestCmd(t, dir, privA, privA, hex.EncodeToString(pubA), filepath.Join(dir, "rotation.json"))
		if err == nil || !strings.Contains(err.Error(), "successor key must differ") {
			t.Fatalf("error = %v, want same-key refusal", err)
		}
	})

	t.Run("wrong successor key purpose", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)
		priorPath := saveRotationTestKey(t, dir, "prior.key", privA)
		newPath := saveRotationJSONKey(t, dir, "new.json", privB, "roster-root")

		cmd := receiptRotationEndorseCmd(time.Now)
		cmd.SetArgs([]string{
			"--chain", dir,
			"--prior-key-file", priorPath,
			"--new-key-file", newPath,
			"--root-key", hex.EncodeToString(pubA),
			"--out", filepath.Join(dir, "rotation.json"),
		})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), `purpose mismatch: file="roster-root" expected="receipt-signing"`) {
			t.Fatalf("error = %v, want key-purpose refusal", err)
		}
	})

	t.Run("wrong retiring key purpose", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)
		priorPath := saveRotationJSONKey(t, dir, "prior.json", privA, "roster-root")
		newPath := saveRotationTestKey(t, dir, "new.json", privB)

		cmd := receiptRotationEndorseCmd(time.Now)
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{
			"--chain", dir,
			"--prior-key-file", priorPath,
			"--new-key-file", newPath,
			"--root-key", hex.EncodeToString(pubA),
			"--out", filepath.Join(dir, "rotation.json"),
		})
		if err := cmd.Execute(); err == nil ||
			!strings.Contains(err.Error(), `purpose mismatch: file="roster-root" expected="receipt-signing"`) {
			t.Fatalf("error = %v, want retiring-key purpose refusal", err)
		}
	})

	t.Run("legacy successor has no purpose binding", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)
		priorPath := saveRotationTestKey(t, dir, "prior.json", privA)
		newPath := filepath.Join(dir, "new-legacy.key")
		if err := domsigning.SavePrivateKey(privB, newPath); err != nil {
			t.Fatalf("SavePrivateKey: %v", err)
		}

		cmd := receiptRotationEndorseCmd(time.Now)
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{
			"--chain", dir,
			"--prior-key-file", priorPath,
			"--new-key-file", newPath,
			"--root-key", hex.EncodeToString(pubA),
			"--out", filepath.Join(dir, "rotation.json"),
		})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "purpose-bound JSON private key required") {
			t.Fatalf("error = %v, want strict successor-purpose refusal", err)
		}
	})

	t.Run("legacy retiring key remains migration compatible", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)
		priorPath := filepath.Join(dir, "prior-legacy.key")
		if err := domsigning.SavePrivateKey(privA, priorPath); err != nil {
			t.Fatalf("SavePrivateKey: %v", err)
		}
		newPath := saveRotationTestKey(t, dir, "new.json", privB)

		cmd := receiptRotationEndorseCmd(time.Now)
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{
			"--chain", dir,
			"--prior-key-file", priorPath,
			"--new-key-file", newPath,
			"--root-key", hex.EncodeToString(pubA),
			"--out", filepath.Join(dir, "rotation.json"),
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("legacy retiring key rejected: %v", err)
		}
	})

	t.Run("existing output", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)
		outPath := filepath.Join(dir, "rotation.json")
		if err := os.WriteFile(outPath, []byte("keep"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		err := executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), outPath)
		if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
			t.Fatalf("error = %v, want overwrite refusal", err)
		}
		root, openErr := os.OpenRoot(dir)
		if openErr != nil {
			t.Fatalf("OpenRoot: %v", openErr)
		}
		defer func() { _ = root.Close() }()
		data, readErr := root.ReadFile(filepath.Base(outPath))
		if readErr != nil || string(data) != "keep" {
			t.Fatalf("existing artifact changed: data=%q err=%v", data, readErr)
		}
	})

	t.Run("output directory missing", func(t *testing.T) {
		dir := t.TempDir()
		pubA, privA := generateRotationTestKey(t)
		_, privB := generateRotationTestKey(t)
		emitClosedInto(t, dir, privA, 1, 0)

		outPath := filepath.Join(dir, "missing", "rotation.json")
		err := executeRotationEndorseTestCmd(t, dir, privA, privB, hex.EncodeToString(pubA), outPath)
		if err == nil || !strings.Contains(err.Error(), "write rotation endorsement") {
			t.Fatalf("error = %v, want output-write refusal", err)
		}
	})
}

func TestConfirmRotationTailStableRejectsConcurrentAdvance(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateRotationTestKey(t)
	emitClosedInto(t, dir, priv, 1, 0)
	before, err := receipt.ExtractReceiptsFromSessionDir(dir, "proxy")
	if err != nil {
		t.Fatalf("extract initial chain: %v", err)
	}
	expectedTail := before[len(before)-1]

	emitClosedInto(t, dir, priv, 1, 1)
	err = confirmRotationTailStable(dir, "proxy", expectedTail)
	if err == nil || !strings.Contains(err.Error(), "chain changed during rotation preparation") {
		t.Fatalf("error = %v, want concurrent-advance refusal", err)
	}
}

func TestConfirmRotationTailStableReadFailures(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		err := confirmRotationTailStable(filepath.Join(t.TempDir(), "missing"), "proxy", receipt.Receipt{})
		if err == nil || !strings.Contains(err.Error(), "re-read receipt chain") {
			t.Fatalf("error = %v, want re-read failure", err)
		}
	})
	t.Run("empty chain", func(t *testing.T) {
		err := confirmRotationTailStable(t.TempDir(), "proxy", receipt.Receipt{})
		if err == nil || !strings.Contains(err.Error(), "chain disappeared") {
			t.Fatalf("error = %v, want empty-chain failure", err)
		}
	})
}

func TestSuccessorAppearsInPriorEndorsements(t *testing.T) {
	endorsements := []receipt.RotationEndorsement{{
		PriorSignerKey: "retired-a",
		NewSignerKey:   "retired-b",
	}}
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{name: "prior signer", key: "retired-a", want: true},
		{name: "endorsed signer", key: "retired-b", want: true},
		{name: "fresh signer", key: "fresh-c", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := successorAppearsInPriorEndorsements(tt.key, endorsements); got != tt.want {
				t.Fatalf("successorAppearsInPriorEndorsements(%q) = %t, want %t", tt.key, got, tt.want)
			}
		})
	}
}

func executeRotationEndorseTestCmd(
	t *testing.T,
	dir string,
	priorKey, newKey ed25519.PrivateKey,
	rootKey, outPath string,
) error {
	t.Helper()
	priorPath := saveRotationTestKey(t, dir, "prior-"+filepath.Base(outPath)+".key", priorKey)
	newPath := saveRotationTestKey(t, dir, "new-"+filepath.Base(outPath)+".key", newKey)
	cmd := receiptRotationEndorseCmd(time.Now)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--chain", dir,
		"--prior-key-file", priorPath,
		"--new-key-file", newPath,
		"--root-key", rootKey,
		"--out", outPath,
	})
	return cmd.Execute()
}

func generateRotationTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func emitClosedInto(t *testing.T, dir string, priv ed25519.PrivateKey, count, startIdx int) {
	t.Helper()
	emitClosedIntoWithReason(t, dir, priv, count, startIdx, "graceful_shutdown")
}

func emitClosedIntoWithReason(
	t *testing.T,
	dir string,
	priv ed25519.PrivateKey,
	count, startIdx int,
	closeReason string,
) {
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
			Target:    "https://api.vendor.example/" + strconv.Itoa(startIdx+i),
			SessionID: "agent-session",
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := emitter.EmitSessionClose(closeReason); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
}

func saveRotationTestKey(t *testing.T, dir, name string, key ed25519.PrivateKey) string {
	t.Helper()
	return saveRotationJSONKey(t, dir, name, key, domsigning.PurposeReceiptSigning.String())
}

func saveRotationJSONKey(
	t *testing.T,
	dir, name string,
	key ed25519.PrivateKey,
	purpose string,
) string {
	t.Helper()
	file := keyFile{
		SchemaVersion: keyFileSchemaVersion,
		Purpose:       purpose,
		KeyID:         "test-key",
		Public:        hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		Private:       hex.EncodeToString(key),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("Marshal key: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	return path
}

func signRotationTestEndorsement(
	t *testing.T,
	tail receipt.Receipt,
	sessionID string,
	priorKey, newKey ed25519.PrivateKey,
) receipt.RotationEndorsement {
	t.Helper()
	tailHash, err := receipt.ReceiptHash(tail)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	endorsement, err := receipt.SignRotationEndorsement(receipt.RotationEndorsement{
		SessionID:     sessionID,
		PriorFinalSeq: tail.ActionRecord.ChainSeq,
		PriorTailHash: tailHash,
		NewSignerKey:  hex.EncodeToString(newKey.Public().(ed25519.PublicKey)),
		RotatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}, priorKey)
	if err != nil {
		t.Fatalf("SignRotationEndorsement: %v", err)
	}
	return endorsement
}

func saveRotationTestEndorsement(
	t *testing.T,
	dir, name string,
	endorsement receipt.RotationEndorsement,
) string {
	t.Helper()
	data, err := json.Marshal(endorsement)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

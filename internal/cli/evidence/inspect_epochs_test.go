// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	legacyreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestInspectEpochsWritesDeterministicPinnedBoundaries(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dashboard"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-other-0.jsonl"), []byte("not selected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := writeInspectEpochFixture(t, dir, priv)

	var firstOut bytes.Buffer
	firstPath := filepath.Join(parent, "first.json")
	opts := inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: firstPath}
	if err := runInspectEpochs(inspectEpochsOutputCommand(&firstOut), opts); err != nil {
		t.Fatalf("first inspection: %v", err)
	}
	// #nosec G304 -- firstPath is the test's own temporary output.
	first, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	var document inspectEpochsDocument
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.RecorderEpochs) != 2 {
		t.Fatalf("epochs = %d, want 2", len(document.RecorderEpochs))
	}
	if document.ReceiptVerification.Status != "verified_per_epoch" || document.ReceiptVerification.V1Count != 0 || document.ReceiptVerification.V1ChainHead != "" {
		t.Fatalf("aggregate receipt proof overclaims independent epochs: %+v", document.ReceiptVerification)
	}
	for i, epoch := range document.RecorderEpochs {
		if epoch.Epoch != uint64(i) || epoch.StartSeq != 0 || epoch.EndSeq != 0 || epoch.StartHash == "" || epoch.EndHash != epoch.StartHash {
			t.Fatalf("epoch %d boundary = %+v", i, epoch)
		}
	}
	if len(document.SourceFiles) != 1 || document.SourceFiles[0].SHA256 != hex.EncodeToString(sha256Bytes(source)) {
		t.Fatalf("source files = %+v", document.SourceFiles)
	}
	artifactSum := sha256.Sum256(first)
	if !strings.HasPrefix(firstOut.String(), hex.EncodeToString(artifactSum[:])+"  ") {
		t.Fatalf("printed digest = %q", firstOut.String())
	}

	secondPath := filepath.Join(parent, "second.json")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeDir, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}
	opts.receiptDir = relativeDir
	opts.outFile = secondPath
	if err := runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), opts); err != nil {
		t.Fatalf("second inspection: %v", err)
	}
	// #nosec G304 -- secondPath is the test's own temporary output.
	second, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical boundary document changed across identical inspections")
	}
	info, err := os.Stat(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %v", info.Mode().Perm())
	}
}

func TestInspectEpochsFailsClosedBeforeWriting(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	// #nosec G304 -- path is the test's own temporary evidence fixture.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "boundaries.json")
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: out})
	if err == nil {
		t.Fatal("tampered source inspection succeeded")
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("failed inspection published output: %v", statErr)
	}

	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: filepath.Join(dir, "pin.json")})
	if err == nil || !strings.Contains(err.Error(), "outside the evidence directory") {
		t.Fatalf("in-tree output error = %v", err)
	}
	link := filepath.Join(parent, "recorder-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: filepath.Join(link, "pin.json")})
	if err == nil || !strings.Contains(err.Error(), "outside the evidence directory") {
		t.Fatalf("symlinked in-tree output error = %v", err)
	}
}

func TestInspectEpochsRefusesUnpinnedRawSidecar(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.raw.enc"), []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "boundaries.json")
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: out})
	if err == nil || !strings.Contains(err.Error(), "sidecar pinning is not implemented") {
		t.Fatalf("raw sidecar error = %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("raw sidecar refusal published output: %v", statErr)
	}
}

func TestInspectEpochsRefusesActiveRecorder(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	out := filepath.Join(parent, "boundaries.json")
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: out})
	if err == nil || !strings.Contains(err.Error(), "lock stopped evidence directory") {
		t.Fatalf("active recorder lock error = %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("active recorder refusal published output: %v", statErr)
	}
}

func TestInspectEpochsRejectsInvalidOperatorInputs(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: filepath.Join(parent, "pin.json")}
	tests := []struct {
		name string
		edit func(*inspectEpochsOptions)
		want string
	}{
		{name: "empty session", edit: func(o *inspectEpochsOptions) { o.sessionID = " " }, want: "--session is required"},
		{name: "empty output", edit: func(o *inspectEpochsOptions) { o.outFile = " " }, want: "--out is required"},
		{name: "missing receipt directory", edit: func(o *inspectEpochsOptions) { o.receiptDir = filepath.Join(parent, "missing") }, want: "no such file or directory"},
		{name: "missing location", edit: func(o *inspectEpochsOptions) { o.locationID = "missing" }, want: "resolve evidence location"},
		{name: "invalid public key", edit: func(o *inspectEpochsOptions) { o.publicKey = "bad" }, want: "load --key"},
		{name: "untrusted public key", edit: func(o *inspectEpochsOptions) { o.publicKey = hex.EncodeToString(otherPub) }, want: "verify epoch boundaries"},
		{name: "missing output parent", edit: func(o *inspectEpochsOptions) { o.outFile = filepath.Join(parent, "missing-parent", "pin.json") }, want: "resolve --out parent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := valid
			tc.edit(&opts)
			err := runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if _, statErr := os.Stat(valid.outFile); !os.IsNotExist(statErr) {
				t.Fatalf("refused input published output: %v", statErr)
			}
		})
	}

	if err := os.WriteFile(valid.outFile, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), valid)
	if err == nil || !strings.Contains(err.Error(), "create --out") {
		t.Fatalf("existing output error = %v", err)
	}
}

func TestInspectEpochsReportsDegradedEpochsAndSyncFailure(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	originalVerify := compactVerifyStream
	originalSync := inspectSyncDirectory
	t.Cleanup(func() {
		compactVerifyStream = originalVerify
		inspectSyncDirectory = originalSync
	})
	compactVerifyStream = func(recorder.EvidenceLocation, []string, string, ed25519.PublicKey, func(compactStreamFile, []byte, recorder.Entry) error) (compactStreamProof, error) {
		return compactStreamProof{v1Degraded: true, v1Epochs: []compactEpochProof{{Epoch: 0, V1Degraded: true}, {Epoch: 1}}}, nil
	}
	inspectSyncDirectory = func(*inspectOutput) error { return errors.New("injected directory sync") }
	out := filepath.Join(parent, "pin.json")
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: out})
	if err == nil || !strings.Contains(err.Error(), "sync --out parent") {
		t.Fatalf("sync error = %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("sync failure retained output: %v", statErr)
	}

	inspectSyncDirectory = originalSync
	degradedOut := filepath.Join(parent, "degraded.json")
	if err := runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: degradedOut}); err != nil {
		t.Fatalf("degraded inspection: %v", err)
	}
	raw, err := os.ReadFile(degradedOut) // #nosec G304 -- test-owned temporary output
	if err != nil {
		t.Fatal(err)
	}
	var document inspectEpochsDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.ReceiptVerification.Status != "degraded_per_epoch" {
		t.Fatalf("status = %q, want degraded_per_epoch", document.ReceiptVerification.Status)
	}
}

func TestInspectEpochsRejectsRenamedOutputParent(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "recorder")
	outputParent := filepath.Join(root, "output")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outputParent, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	originalSync := inspectSyncDirectory
	t.Cleanup(func() { inspectSyncDirectory = originalSync })
	movedParent := filepath.Join(root, "moved-output")
	inspectSyncDirectory = func(output *inspectOutput) error {
		if err := output.syncParent(); err != nil {
			return err
		}
		if err := os.Rename(outputParent, movedParent); err != nil {
			return err
		}
		return os.Mkdir(outputParent, 0o750)
	}
	out := filepath.Join(outputParent, "pin.json")
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: out})
	if err == nil || !strings.Contains(err.Error(), "--out parent changed") {
		t.Fatalf("renamed parent error = %v", err)
	}
	for _, path := range []string{out, filepath.Join(movedParent, "pin.json")} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("renamed parent retained output %s: %v", path, statErr)
		}
	}
}

func TestInspectEpochsRejectsDisappearedOutputParent(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "recorder")
	outputParent := filepath.Join(root, "output")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outputParent, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	originalSync := inspectSyncDirectory
	t.Cleanup(func() { inspectSyncDirectory = originalSync })
	movedParent := filepath.Join(root, "moved-output")
	inspectSyncDirectory = func(output *inspectOutput) error {
		if err := output.syncParent(); err != nil {
			return err
		}
		return os.Rename(outputParent, movedParent)
	}
	err = runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: filepath.Join(outputParent, "pin.json")})
	if err == nil || !strings.Contains(err.Error(), "verify --out parent identity") {
		t.Fatalf("disappeared parent error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(movedParent, "pin.json")); !os.IsNotExist(statErr) {
		t.Fatalf("disappeared parent retained output: %v", statErr)
	}
}

func TestInspectEpochSourceNamesRejectsUnsafeAndEmptyLocations(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing")
		_, err := inspectEpochSourceNames(recorder.EvidenceLocation{Root: missing, Dir: missing}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "list evidence directory") {
			t.Fatalf("missing directory error = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "evidence-proxy-0.jsonl")); err != nil {
			t.Fatal(err)
		}
		_, err := inspectEpochSourceNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "refuse symlink") {
			t.Fatalf("symlink error = %v", err)
		}
	})
	t.Run("empty session", func(t *testing.T) {
		dir := t.TempDir()
		_, err := inspectEpochSourceNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "has no evidence shards") {
			t.Fatalf("empty session error = %v", err)
		}
	})
	t.Run("directory entry overflow", func(t *testing.T) {
		dir := t.TempDir()
		for i := range maxCompactInputShards + 1 {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("evidence-proxy-%d.jsonl", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := inspectEpochSourceNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "inspection input limit") {
			t.Fatalf("overflow error = %v", err)
		}
	})
	t.Run("duplicate shard start", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"evidence-proxy-0.jsonl", "evidence-proxy-00.jsonl"} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := inspectEpochSourceNames(recorder.EvidenceLocation{Root: dir, Dir: dir}, "proxy")
		if err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("duplicate start error = %v", err)
		}
	})
}

func inspectEpochsOutputCommand(out *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	return cmd
}

func writeInspectEpochFixture(t *testing.T, dir string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	var source bytes.Buffer
	for epoch := range 2 {
		receipt := receiptForCompactV1(t, priv, 0, legacyreceipt.GenesisHash, fmt.Sprintf("inspect-epoch-%d", epoch))
		entry := recorder.Entry{Version: 1, Sequence: 0, Timestamp: time.Unix(int64(epoch+1), 0).UTC(), SessionID: "proxy", Type: "action_receipt", EventKind: "proxy_decision", Transport: "fetch", Summary: "legacy epoch", Detail: receipt, PrevHash: recorder.GenesisHash}
		entry.Hash = recorder.ComputeHash(entry)
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		source.Write(line)
		source.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), source.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return source.Bytes()
}

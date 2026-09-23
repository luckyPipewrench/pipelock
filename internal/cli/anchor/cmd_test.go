// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

func cliReceiptJSONL(t *testing.T) (path string, keyHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	prev := receipt.GenesisHash
	base := time.Date(2026, 6, 28, 13, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	for i := range 2 {
		ar := receipt.ActionRecord{
			Version:       receipt.ActionRecordVersion,
			ActionID:      receipt.NewActionID(),
			ActionType:    receipt.ActionRead,
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			Target:        "https://example.test/resource",
			Verdict:       config.ActionAllow,
			Transport:     "fetch",
			ChainPrevHash: prev,
			ChainSeq:      uint64(i),
			PolicyHash:    "policy-test",
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		line, err := receipt.Marshal(r)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		_, _ = buf.Write(line)
		_ = buf.WriteByte('\n')
		prev, err = receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
	}
	path = filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, hex.EncodeToString(pub)
}

func TestReceiptsCmdWritesLocalAnchorBundle(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T13:00:00Z")
	receiptsPath, keyHex := cliReceiptJSONL(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "anchor.jsonl")
	bundlePath := filepath.Join(filepath.Dir(receiptsPath), "bundle.json")

	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", logPath,
		"--log-id", "cli-test-log",
		"--out", bundlePath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "ANCHOR BUNDLE WRITTEN") {
		t.Fatalf("output missing success:\n%s", out.String())
	}
	bundle, err := anchorpkg.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if bundle.Proof.Backend != anchorpkg.LocalBackend || bundle.Proof.LogIndex != 0 {
		t.Fatalf("unexpected bundle proof: %+v", bundle.Proof)
	}
	markers, err := anchorpkg.LoadStateMarkers(filepath.Dir(receiptsPath))
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	if len(markers) != 1 ||
		markers[0].BundlePath != "bundle.json" ||
		markers[0].ReceiptCount != bundle.Checkpoint.ReceiptCount ||
		markers[0].SignerKey != keyHex {
		t.Fatalf("anchor markers = %+v, want enriched receipt-directory-relative marker", markers)
	}
	entries, err := anchorpkg.ReadLocalLog(logPath)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	if len(entries) != 1 || entries[0].LogID != "cli-test-log" {
		t.Fatalf("unexpected log entries: %+v", entries)
	}
}

func TestReceiptsCmdDoesNotWriteArtifactsWhenLocalSubmitFails(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	logParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(logParent, []byte("regular file"), 0o600); err != nil {
		t.Fatalf("WriteFile log parent: %v", err)
	}
	logPath := filepath.Join(logParent, "anchor.jsonl")
	bundlePath := filepath.Join(filepath.Dir(receiptsPath), "bundle.json")

	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", logPath,
		"--out", bundlePath,
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "create local anchor log lock directory") {
		t.Fatalf("Execute error = %v, want local submit failure", err)
	}
	if strings.Contains(out.String(), "ANCHOR BUNDLE WRITTEN") {
		t.Fatalf("success output after failed local submit: %q", out.String())
	}
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle after failed local submit = %v, want absent", err)
	}
	markers, err := anchorpkg.LoadStateMarkers(filepath.Dir(receiptsPath))
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	if len(markers) != 0 {
		t.Fatalf("state markers after failed local submit = %+v, want none", markers)
	}
}

func TestReceiptsCmdRefusesOutputAliasingKeyFile(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T13:00:00Z")
	receiptsPath, keyHex := cliReceiptJSONL(t)
	keyFile := filepath.Join(filepath.Dir(receiptsPath), "trusted.key")
	if err := os.WriteFile(keyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	before, err := os.ReadFile(filepath.Clean(keyFile))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyFile,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", keyFile,
	})
	err = cmd.Execute()
	after, readErr := os.ReadFile(filepath.Clean(keyFile))
	if readErr != nil {
		t.Fatalf("re-read key: %v", readErr)
	}
	if err == nil {
		t.Fatalf("anchor receipts succeeded writing --out over --key; stdout=%q", out.String())
	}
	if !bytes.Equal(before, after) {
		t.Fatal("trusted signer key file was overwritten")
	}
}

func TestReceiptsCmdRefusesOutputAliasingReceiptInput(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T13:00:00Z")
	receiptsPath, keyHex := cliReceiptJSONL(t)
	before, err := os.ReadFile(filepath.Clean(receiptsPath))
	if err != nil {
		t.Fatalf("read receipts: %v", err)
	}
	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", receiptsPath,
	})
	err = cmd.Execute()
	after, readErr := os.ReadFile(filepath.Clean(receiptsPath))
	if readErr != nil {
		t.Fatalf("re-read receipts: %v", readErr)
	}
	if err == nil {
		t.Fatalf("anchor receipts succeeded writing --out over the receipt input; stdout=%q", out.String())
	}
	if !strings.Contains(err.Error(), "--out must not name the receipt input") {
		t.Fatalf("anchor receipts error = %v, want receipt-input alias refusal", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("receipt input was overwritten")
	}
}

func TestReceiptsCmdRefusesOutAliasingLocalLog(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T13:00:00Z")
	receiptsPath, keyHex := cliReceiptJSONL(t)
	shared := filepath.Join(filepath.Dir(receiptsPath), "same.json")
	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", shared,
		"--out", shared,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("anchor receipts succeeded writing --out over --local-log; stdout=%q", out.String())
	}
	if !strings.Contains(err.Error(), "must not name") {
		t.Fatalf("anchor receipts error = %v, want --out/--local-log collision", err)
	}
}

func TestWriteAnchorStateMarkerRejectsCheckpointWithoutSigner(t *testing.T) {
	err := writeAnchorStateMarker(
		bundleOutput{receiptDir: t.TempDir(), markerPath: "bundle.json"},
		anchorpkg.Checkpoint{SessionID: "file", RootHash: strings.Repeat("a", 64), ReceiptCount: 1},
		anchorpkg.Proof{Backend: anchorpkg.LocalBackend},
		[]byte("{}\n"),
	)
	if err == nil || !strings.Contains(err.Error(), "no signer keys") {
		t.Fatalf("writeAnchorStateMarker err = %v, want missing signer rejection", err)
	}
}

func TestReceiptsCmdWritesRekorAnchorBundle(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	dir := t.TempDir()
	bundlePath := filepath.Join(filepath.Dir(receiptsPath), "bundle.json")
	rekorKey := writeRekorKey(t, dir)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/log/entries" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, err := json.Marshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		encodedBody := base64.StdEncoding.EncodeToString(raw)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"fake-uuid": map[string]any{
				"logID":          "fake-rekor-log",
				"logIndex":       3,
				"integratedTime": 1780000000,
				"body":           encodedBody,
				"verification": map[string]any{
					"inclusionProof": map[string]any{
						"rootHash":   strings.Repeat("a", 64),
						"logIndex":   3,
						"treeSize":   4,
						"hashes":     []string{},
						"checkpoint": "checkpoint",
					},
					"signedEntryTimestamp": "fake-set",
				},
			},
		})
	}))
	defer server.Close()

	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--backend", anchorpkg.RekorBackend,
		"--rekor-url", server.URL,
		"--rekor-key", rekorKey,
		"--yes-send-to-remote-log",
		"--out", bundlePath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	bundle, err := anchorpkg.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if bundle.Backend != anchorpkg.RekorBackend || bundle.Proof.Backend != anchorpkg.RekorBackend || bundle.Proof.Rekor == nil {
		t.Fatalf("unexpected Rekor bundle: %+v", bundle)
	}
	if bundle.Proof.LogID != "fake-rekor-log" || bundle.Proof.LogIndex != 3 || bundle.Proof.LogRootHash != strings.Repeat("a", 64) || bundle.Proof.EntryHash == "" {
		t.Fatalf("unexpected Rekor log metadata: %+v", bundle.Proof)
	}
	if bundle.Proof.Rekor.UUID != "fake-uuid" ||
		bundle.Proof.Rekor.URL != server.URL ||
		bundle.Proof.Rekor.Body == "" ||
		bundle.Proof.Rekor.PublicKey == "" ||
		bundle.Proof.Rekor.Signature == "" ||
		bundle.Proof.Rekor.IntegratedTime != 1780000000 ||
		bundle.Proof.Rekor.SignedEntryTimestamp != "fake-set" ||
		bundle.Proof.Rekor.InclusionProof == nil ||
		bundle.Proof.Rekor.InclusionProof.TreeSize != 4 {
		t.Fatalf("unexpected Rekor proof metadata: %+v", bundle.Proof.Rekor)
	}
	if !strings.Contains(out.String(), "Backend:       rekor") {
		t.Fatalf("output missing Rekor backend:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Rekor URL:     "+server.URL) {
		t.Fatalf("output missing Rekor URL:\n%s", out.String())
	}
}

func TestCmdRegistersReceiptsSubcommand(t *testing.T) {
	cmd := Cmd()
	if cmd.Use != "anchor" {
		t.Fatalf("Use = %q, want anchor", cmd.Use)
	}
	if _, _, err := cmd.Find([]string{"receipts"}); err != nil {
		t.Fatalf("Find receipts: %v", err)
	}
}

func TestReceiptsCmdRequiresLocalLogAndOutput(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	receiptDir := filepath.Dir(receiptsPath)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "local log",
			args: []string{receiptsPath, "--key", keyHex, "--out", filepath.Join(receiptDir, "bundle.json")},
			want: "--local-log is required",
		},
		{
			name: "output",
			args: []string{receiptsPath, "--key", keyHex, "--local-log", filepath.Join(t.TempDir(), "anchor.jsonl")},
			want: "--out is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := receiptsCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Execute err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReceiptsCmdRequiresRekorURL(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	dir := t.TempDir()
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	// Rekor backend with a key and the remote acknowledgement but NO --rekor-url
	// must fail closed rather than silently defaulting to the public log.
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--backend", anchorpkg.RekorBackend,
		"--rekor-key", writeRekorKey(t, dir),
		"--yes-send-to-remote-log",
		"--out", filepath.Join(filepath.Dir(receiptsPath), "bundle.json"),
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--rekor-url is required") {
		t.Fatalf("Execute err = %v, want Rekor URL error", err)
	}
}

func TestReceiptsCmdRequiresRekorKey(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--backend", anchorpkg.RekorBackend,
		"--rekor-url", "https://rekor.internal.example",
		"--out", filepath.Join(filepath.Dir(receiptsPath), "bundle.json"),
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--rekor-key is required") {
		t.Fatalf("Execute err = %v, want Rekor key error", err)
	}
}

func TestReceiptsCmdRequiresRekorRemoteAcknowledgement(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	dir := t.TempDir()
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--backend", anchorpkg.RekorBackend,
		"--rekor-url", "https://rekor.internal.example",
		"--rekor-key", writeRekorKey(t, dir),
		"--out", filepath.Join(filepath.Dir(receiptsPath), "bundle.json"),
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--yes-send-to-remote-log is required") {
		t.Fatalf("Execute err = %v, want Rekor acknowledgement error", err)
	}
}

func TestReceiptsCmdRequiresPinnedKey(t *testing.T) {
	receiptsPath, _ := cliReceiptJSONL(t)
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		receiptsPath,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", filepath.Join(filepath.Dir(receiptsPath), "bundle.json"),
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "at least one --key") {
		t.Fatalf("Execute err = %v, want pinned-key error", err)
	}
}

func TestReceiptsCmdRejectsBlankPinnedKey(t *testing.T) {
	for _, key := range []string{"", "  "} {
		t.Run("blank_"+strings.ReplaceAll(key, " ", "space"), func(t *testing.T) {
			receiptsPath, keyHex := cliReceiptJSONL(t)
			cmd := receiptsCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs([]string{
				receiptsPath,
				"--key", key,
				"--key", keyHex,
				"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
				"--out", filepath.Join(filepath.Dir(receiptsPath), "bundle.json"),
			})
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "public key is empty") {
				t.Fatalf("Execute err = %v, want blank-key error", err)
			}
		})
	}
}

func TestReceiptsCmdReturnsFallbackExtractionError(t *testing.T) {
	_, keyHex := cliReceiptJSONL(t)
	missingPath := filepath.Join(t.TempDir(), "missing.jsonl")
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		missingPath,
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", "bundle.json",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute err = nil, want missing evidence error")
	}
	if !strings.Contains(err.Error(), "reading raw receipts") {
		t.Fatalf("Execute err = %v, want fallback raw-receipt error", err)
	}
}

func TestReceiptsCmdRejectsOutsideBundleOutput(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	outside := filepath.Join(t.TempDir(), "bundle.json")
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", outside,
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "under the receipt directory") {
		t.Fatalf("Execute err = %v, want outside --out refusal", err)
	}
}

func TestResolveBundleOutputRejectsHostilePaths(t *testing.T) {
	receiptsPath, _ := cliReceiptJSONL(t)
	receiptDir := filepath.Dir(receiptsPath)

	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
		wantRel string
	}{
		{
			name: "output symlink",
			setup: func(t *testing.T) string {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation needs privileges on Windows")
				}
				target := filepath.Join(receiptDir, "target-bundle.json")
				if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
					t.Fatalf("WriteFile target: %v", err)
				}
				link := filepath.Join(receiptDir, "bundle-link.json")
				if err := os.Symlink(filepath.Base(target), link); err != nil {
					t.Fatalf("Symlink bundle: %v", err)
				}
				return link
			},
			wantErr: "must not be a symlink",
		},
		{
			name: "parent symlink",
			setup: func(t *testing.T) string {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation needs privileges on Windows")
				}
				outside := t.TempDir()
				link := filepath.Join(receiptDir, "linked-parent")
				if err := os.Symlink(outside, link); err != nil {
					t.Fatalf("Symlink parent: %v", err)
				}
				return filepath.Join(link, "bundle.json")
			},
			wantErr: "parent must not be a symlink",
		},
		{
			name: "absolute dotdot outside",
			setup: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(receiptDir, "..", "outside-bundle.json")
			},
			wantErr: "under the receipt directory",
		},
		{
			name: "receipt directory",
			setup: func(t *testing.T) string {
				t.Helper()
				return receiptDir
			},
			wantErr: "must name an anchor bundle file",
		},
		{
			name: "existing directory output",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := filepath.Join(receiptDir, "bundle-dir")
				if err := os.Mkdir(dir, 0o750); err != nil {
					t.Fatalf("Mkdir output dir: %v", err)
				}
				return dir
			},
			wantErr: "must be a regular file",
		},
		{
			name: "missing parent chain",
			setup: func(t *testing.T) string {
				t.Helper()
				return filepath.Join("nested", "new", "bundle.json")
			},
			wantRel: filepath.ToSlash(filepath.Join("nested", "new", "bundle.json")),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := resolveBundleOutput(receiptsPath, receiptsOptions{output: tc.setup(t)})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveBundleOutput err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveBundleOutput: %v", err)
			}
			if output.markerPath != tc.wantRel {
				t.Fatalf("markerPath = %q, want %q", output.markerPath, tc.wantRel)
			}
		})
	}
}

func writeRekorKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(dir, "rekor.key")
	if err := domsigning.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	return path
}

// TestReceiptsCmdRejectsEmptyRecorderEvidence proves two things in one pass:
// an empty (zero-entry) recorder JSONL file makes extractReceipts succeed
// through the primary ExtractReceiptsWithSessionID path with an empty
// session ID (which the command normalizes to "file"), and runReceipts then
// surfaces BuildCheckpoint's empty-receipt-chain rejection rather than
// anchoring nothing.
func TestReceiptsCmdRejectsEmptyRecorderEvidence(t *testing.T) {
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(emptyPath, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, keyHex := cliReceiptJSONL(t)
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		emptyPath,
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", "bundle.json",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "empty receipt chain") {
		t.Fatalf("Execute err = %v, want empty-receipt-chain rejection", err)
	}
}

// cliSessionActionEmits is how many Emit calls cliRecorderSessionDir makes.
// The extracted chain also carries the session-open receipt, so the bundle's
// checkpoint covers cliSessionActionEmits+1 receipts.
const cliSessionActionEmits = 2

// cliRecorderSessionDir writes a REAL recorder evidence directory, the shape
// ExtractReceiptsFromSessionDir actually reads, and returns it with the hex
// public key that verifies its receipts. The recorder fixes the evidence
// session ID to "proxy", which is also the anchor command's --session default.
func cliRecorderSessionDir(t *testing.T) (dir string, keyHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir = t.TempDir()
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
		ConfigHash: "policy-test",
		Principal:  "test-principal",
		Actor:      "test-actor",
	})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for range cliSessionActionEmits {
		if err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Target:    "https://example.test/resource",
			Verdict:   config.ActionAllow,
			Transport: "fetch",
			Method:    http.MethodGet,
			SessionID: "proxy",
			Agent:     "test-actor",
		}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder Close: %v", err)
	}
	return dir, hex.EncodeToString(pub)
}

func TestAnchorDirectoryResolvesRunSession(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: "policy-test", Session: session})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{dir, "--dir", "--key", hex.EncodeToString(pub), "--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"), "--out", "bundle.json"})
	if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), session) {
		t.Fatalf("anchor one run: %v\n%s", err, out.String())
	}
	if _, _, err := extractReceipts(dir, receiptsOptions{asDir: true, sessionID: "missing", sessionExplicit: false}); err == nil || !strings.Contains(err.Error(), "no receipt chains") {
		t.Fatalf("missing base must fail: %v", err)
	}
}

// TestReceiptsCmdAsDirExtractsFromSessionDirectory covers the --dir branch of
// extractReceipts, which reads a whole session directory rather than a single
// evidence file.
//
// It drives a REAL recorder session directory and asserts a bundle is actually
// produced. Asserting only that an unmatched session errors would pass against
// an implementation that returned no receipts for every --dir invocation, or
// never read the directory at all, so it would prove the branch was reachable
// without proving extraction works. The unmatched-session case is its own
// negative test below.
func TestReceiptsCmdAsDirExtractsFromSessionDirectory(t *testing.T) {
	dir, keyHex := cliRecorderSessionDir(t)
	bundlePath := filepath.Join(dir, "bundle.json")
	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		dir,
		"--dir",
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", "bundle.json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v, want a bundle built from the session directory", err)
	}
	if !strings.Contains(out.String(), "ANCHOR BUNDLE WRITTEN") {
		t.Fatalf("command output = %q, want the success announcement", out.String())
	}
	data, err := os.ReadFile(bundlePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading bundle: %v", err)
	}
	var bundle anchorpkg.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("parsing bundle: %v", err)
	}
	// The checkpoint has to describe the receipts that were in the directory.
	// A non-zero check would pass on any bundle at all, including one that
	// silently dropped an action during extraction, so pin the exact count:
	// every Emit plus the session-open receipt the chain starts with.
	if want := uint64(cliSessionActionEmits + 1); bundle.Checkpoint.ReceiptCount != want {
		t.Fatalf("bundle checkpoint receipt count = %d, want %d", bundle.Checkpoint.ReceiptCount, want)
	}
	if bundle.Checkpoint.SessionID != "proxy" {
		t.Fatalf("bundle checkpoint session = %q, want the recorder's session", bundle.Checkpoint.SessionID)
	}
}

// TestReceiptsCmdAsDirRejectsUnmatchedSession is the negative half: a session
// ID absent from the directory yields no receipts and no error from the
// extractor, so BuildCheckpoint is what rejects it.
func TestReceiptsCmdAsDirRejectsUnmatchedSession(t *testing.T) {
	dir, keyHex := cliRecorderSessionDir(t)
	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		dir,
		"--dir",
		"--session", "no-such-session",
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", "bundle.json",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "empty receipt chain") {
		t.Fatalf("Execute err = %v, want an empty-receipt-chain error for an unmatched session", err)
	}
	if strings.Contains(err.Error(), "reading raw receipts") {
		t.Fatalf("Execute err = %v, want a --dir-specific error, not the non---dir fallback path", err)
	}
}

// TestResolveBackendRejectsUnsupportedName covers resolveBackend's default
// case.
func TestResolveBackendRejectsUnsupportedName(t *testing.T) {
	_, err := resolveBackend(receiptsOptions{backend: "carrier-pigeon"})
	if err == nil || !strings.Contains(err.Error(), `unsupported anchor backend "carrier-pigeon"`) {
		t.Fatalf("resolveBackend err = %v, want unsupported-backend rejection", err)
	}
}

// TestResolveBackendRejectsUnreadableRekorKey covers resolveBackend's
// LoadRekorPrivateKey error branch: a rekor-key path that cannot be loaded
// as a signing key must fail closed rather than fall back to an unsigned or
// zero-value signer.
func TestResolveBackendRejectsUnreadableRekorKey(t *testing.T) {
	badKey := filepath.Join(t.TempDir(), "not-a-key.txt")
	if err := os.WriteFile(badKey, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := resolveBackend(receiptsOptions{
		backend:  anchorpkg.RekorBackend,
		rekorURL: "https://rekor.example",
		rekorKey: badKey,
		rekorYes: true,
	})
	if err == nil {
		t.Fatal("resolveBackend err = nil, want rekor key load failure")
	}
}

// TestValidateBundleOutputPathHostilePaths exercises the permission and
// structural failure branches of validateBundleOutputPath that
// TestResolveBundleOutputRejectsHostilePaths does not reach: a Lstat failure
// on the bundle path itself that is not "does not exist", a parent path
// component that exists but is not a directory, a parent that resolves (via
// an ancestor symlink) outside the receipt directory, and a Lstat failure on
// an ancestor while walking up to find an existing directory.
func TestValidateBundleOutputPathHostilePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission denial does not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses Unix permission checks")
	}

	t.Run("bundle path Lstat permission denied", func(t *testing.T) {
		receiptDir := t.TempDir()
		blocked := filepath.Join(receiptDir, "blocked")
		if err := os.Mkdir(blocked, 0o750); err != nil {
			t.Fatal(err)
		}
		bundlePath := filepath.Join(blocked, "bundle.json")
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o750) }) // #nosec G302 -- restoring a directory to the repo-standard 0750
		err := validateBundleOutputPath(receiptDir, bundlePath)
		if err == nil || !strings.Contains(err.Error(), "inspect --out") {
			t.Fatalf("validateBundleOutputPath err = %v, want inspect --out failure", err)
		}
	})

	t.Run("parent path is a regular file", func(t *testing.T) {
		// A non-directory ancestor makes the OS reject the whole traversal
		// with ENOTDIR at the first Lstat(bundlePath) call above, before
		// validateBundleOutputPath's own parent-walk loop ever runs its
		// "--out parent is not a directory" check: any component that
		// exists as a non-directory blocks path resolution at the deepest
		// point, not just at the immediate parent. This still proves the
		// fail-closed outcome, through the "inspect --out" branch instead.
		receiptDir := t.TempDir()
		notADir := filepath.Join(receiptDir, "not-a-dir")
		if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		bundlePath := filepath.Join(notADir, "bundle.json")
		err := validateBundleOutputPath(receiptDir, bundlePath)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("validateBundleOutputPath err = %v, want a not-a-directory rejection", err)
		}
	})

	t.Run("parent resolves outside receipt directory via ancestor symlink", func(t *testing.T) {
		receiptDir := t.TempDir()
		outside := t.TempDir()
		realParent := filepath.Join(outside, "realparent")
		if err := os.Mkdir(realParent, 0o750); err != nil {
			t.Fatal(err)
		}
		grandparentLink := filepath.Join(receiptDir, "gplink")
		if err := os.Symlink(outside, grandparentLink); err != nil {
			t.Fatal(err)
		}
		// The final path component (realparent) is a real directory, so
		// Lstat on the composite parent path sees a directory, not a
		// symlink; only EvalSymlinks reveals that it resolves outside
		// receiptDir through the grandparent link.
		parent := filepath.Join(grandparentLink, "realparent")
		bundlePath := filepath.Join(parent, "bundle.json")
		err := validateBundleOutputPath(receiptDir, bundlePath)
		if err == nil || !strings.Contains(err.Error(), "--out parent resolves outside the receipt directory") {
			t.Fatalf("validateBundleOutputPath err = %v, want parent-escape rejection", err)
		}
	})

	t.Run("bundle path Lstat permission denied under a blocked ancestor", func(t *testing.T) {
		// Named for what it actually covers. A permission-denied ancestor
		// blocks the OS traversal at the FIRST Lstat(bundlePath) call, so
		// this lands on "inspect --out" and never reaches the parent-walk
		// loop's own "inspect --out parent" branch. Creating bundlePath
		// first would not change that, because the later Lstat still
		// traverses the blocked directory.
		//
		// The parent-walk loop's independent Lstat failure paths (a
		// directory or permission demoted BETWEEN the two Lstat calls) are
		// TOCTOU-only and unreachable without a real race. Reaching them
		// would mean injecting an Lstat seam into production solely to be
		// testable, which buys a test rather than a guarantee, so they stay
		// uncovered and are named here instead of being implied covered.
		receiptDir := t.TempDir()
		blocked := filepath.Join(receiptDir, "blocked")
		if err := os.Mkdir(blocked, 0o750); err != nil {
			t.Fatal(err)
		}
		bundlePath := filepath.Join(blocked, "nested", "bundle.json")
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o750) }) // #nosec G302 -- restoring a directory to the repo-standard 0750
		err := validateBundleOutputPath(receiptDir, bundlePath)
		if err == nil || !strings.Contains(err.Error(), "inspect --out") {
			t.Fatalf("validateBundleOutputPath err = %v, want an inspect-failure rejection", err)
		}
		// "inspect --out" is a prefix of "inspect --out parent", so the
		// check above cannot tell the two branches apart on its own. Pin
		// the one this test actually reaches.
		if strings.Contains(err.Error(), "inspect --out parent") {
			t.Fatalf("validateBundleOutputPath err = %v, want the bundle-path inspect failure, not the parent-walk branch", err)
		}
	})
}

// TestResolveBundleOutputPropagatesMissingReceiptDirectory covers
// resolveBundleOutput's error passthrough from receiptDirectory: a target
// that does not exist must fail before any bundle path computation.
func TestResolveBundleOutputPropagatesMissingReceiptDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "receipts.jsonl")
	_, err := resolveBundleOutput(missing, receiptsOptions{output: "bundle.json"})
	if err == nil || !strings.Contains(err.Error(), "resolve receipt directory") {
		t.Fatalf("resolveBundleOutput err = %v, want receipt-directory resolution failure", err)
	}
}

// TestReceiptDirectoryRejectsFileWithAsDir covers receiptDirectory's
// not-a-directory rejection on the --dir path: asDir=true trusts the caller
// to have named a directory, and must still fail closed when it is
// actually a regular file rather than silently treating its parent as the
// session directory.
func TestReceiptDirectoryRejectsFileWithAsDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-dir.jsonl")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := receiptDirectory(path, true)
	if err == nil || !strings.Contains(err.Error(), "receipt directory is not a directory") {
		t.Fatalf("receiptDirectory err = %v, want not-a-directory rejection", err)
	}
}

// TestResolveTrustedKeysRejectsUnresolvableKey covers resolveTrustedKeys'
// LoadPublicKey error branch: a non-blank value that is neither valid
// inline key material nor an existing key file must fail closed rather than
// silently skip the malformed trust anchor.
func TestResolveTrustedKeysRejectsUnresolvableKey(t *testing.T) {
	_, err := resolveTrustedKeys([]string{"not-a-valid-hex-or-file-path"})
	if err == nil || !strings.Contains(err.Error(), `resolve --key "not-a-valid-hex-or-file-path"`) {
		t.Fatalf("resolveTrustedKeys err = %v, want key-resolution failure", err)
	}
}

// TestReceiptsCmdSurfacesBundleWriteFailure covers runReceipts' propagation
// of WriteBundleUnderDir's error: if the receipt directory itself cannot be
// written to (for example because an operator's filesystem mount is
// read-only), the command must fail with that write error rather than
// report success or panic after computing a valid checkpoint and proof.
func TestReceiptsCmdSurfacesBundleWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based write denial does not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses Unix permission checks")
	}
	receiptsPath, keyHex := cliReceiptJSONL(t)
	receiptDir := filepath.Dir(receiptsPath)
	if err := os.Chmod(receiptDir, 0o500); err != nil { // #nosec G302 -- deliberately denies writes to prove the write-failure path
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(receiptDir, 0o750) }) // #nosec G302 -- restoring a directory to the repo-standard 0750

	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", "bundle.json",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute err = nil, want a write failure under a read-only receipt directory")
	}
	// The success marker is written to the command's output writer, never
	// folded into the error, so the command output is the only place a
	// premature success announcement would show up.
	if strings.Contains(out.String(), "ANCHOR BUNDLE WRITTEN") {
		t.Fatalf("command output = %q, want no success announcement alongside a write failure", out.String())
	}
}

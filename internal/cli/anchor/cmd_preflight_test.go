// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
)

// countingRekor is a Rekor endpoint that answers every request with an error
// and counts how many arrived: the only thing these tests need to know is
// whether the CLI reached the log at all.
func countingRekor(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected submission", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func rekorAnchorArgs(receipts, keyHex, rekorKey, serverURL, out string) []string {
	return []string{
		receipts,
		"--key", keyHex,
		"--backend", anchorpkg.RekorBackend,
		"--rekor-url", serverURL,
		"--rekor-key", rekorKey,
		"--yes-send-to-remote-log",
		"--out", out,
	}
}

// A checkpoint that is already anchored must be refused before the Rekor
// submit. The old order submitted to the log first and failed on the local
// anchor state afterwards, leaving a public entry behind an error.
func TestReceiptsCmdRekorRefusesAlreadyAnchoredCheckpointBeforeSubmit(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	dir := t.TempDir()
	rekorKey := writeRekorKey(t, dir)
	logPath := filepath.Join(dir, "anchor.jsonl")

	first := receiptsCmd()
	first.SetOut(&bytes.Buffer{})
	first.SetArgs([]string{receiptsPath, "--key", keyHex, "--local-log", logPath, "--out", filepath.Join(filepath.Dir(receiptsPath), "first.json")})
	if err := first.Execute(); err != nil {
		t.Fatalf("first anchor: %v", err)
	}

	server, hits := countingRekor(t)
	second := receiptsCmd()
	second.SetOut(&bytes.Buffer{})
	second.SilenceUsage = true
	second.SilenceErrors = true
	secondOut := filepath.Join(filepath.Dir(receiptsPath), "second.json")
	second.SetArgs(rekorAnchorArgs(receiptsPath, keyHex, rekorKey, server.URL, secondOut))
	err := second.Execute()
	if err == nil || !strings.Contains(err.Error(), "already anchored") {
		t.Fatalf("Execute error = %v, want the already-anchored refusal", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the Rekor log received %d request(s) for a checkpoint the local state refuses", got)
	}
	if _, statErr := os.Stat(secondOut); !os.IsNotExist(statErr) {
		t.Fatalf("a refused anchor wrote a bundle: %v", statErr)
	}
}

// A conflicting local history is refused before the Rekor submit as well.
func TestReceiptsCmdRekorRefusesConflictingHistoryBeforeSubmit(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	dir := t.TempDir()
	rekorKey := writeRekorKey(t, dir)

	// Anchor once locally to learn the session ID and coverage this chain has,
	// then record a different root for the same coverage in a fresh directory.
	first := receiptsCmd()
	first.SetOut(&bytes.Buffer{})
	first.SetArgs([]string{receiptsPath, "--key", keyHex, "--local-log", filepath.Join(dir, "anchor.jsonl"), "--out", filepath.Join(filepath.Dir(receiptsPath), "first.json")})
	if err := first.Execute(); err != nil {
		t.Fatalf("first anchor: %v", err)
	}
	markers, err := anchorpkg.LoadStateMarkers(filepath.Dir(receiptsPath))
	if err != nil || len(markers) != 1 {
		t.Fatalf("LoadStateMarkers = %d markers, err %v", len(markers), err)
	}
	recorded := markers[0]

	data, err := os.ReadFile(filepath.Clean(receiptsPath))
	if err != nil {
		t.Fatalf("read receipts: %v", err)
	}
	freshDir := t.TempDir()
	freshReceipts := filepath.Join(freshDir, filepath.Base(receiptsPath))
	if err := os.WriteFile(freshReceipts, data, 0o600); err != nil {
		t.Fatalf("write receipts copy: %v", err)
	}
	otherRoot := sha256.Sum256([]byte("a different history"))
	forged := recorded
	forged.RootHash = hex.EncodeToString(otherRoot[:])
	forged.BundleSHA256 = hex.EncodeToString(otherRoot[:])
	forged.BundlePath = "forged.json"
	forged.AnchoredAt = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	if err := anchorpkg.WriteStateMarker(freshDir, forged); err != nil {
		t.Fatalf("record conflicting marker: %v", err)
	}

	server, hits := countingRekor(t)
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(rekorAnchorArgs(freshReceipts, keyHex, rekorKey, server.URL, filepath.Join(freshDir, "bundle.json")))
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("Execute error = %v, want the conflicting-history refusal", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the Rekor log received %d request(s) for a checkpoint that conflicts with local history", got)
	}
}

func TestReceiptsCmdRekorPreflightDamagedState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, string)
		want  string
	}{
		{"corrupt legacy", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), []byte("broken"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "legacy"},
		{"symlink latest with index", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "anchor-state.d"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("absent", filepath.Join(dir, "anchor-state.json")); err != nil {
				t.Fatal(err)
			}
		}, "regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receiptsPath, keyHex := cliReceiptJSONL(t)
			tc.setup(t, filepath.Dir(receiptsPath))
			rekorKey := writeRekorKey(t, t.TempDir())
			server, hits := countingRekor(t)
			cmd := receiptsCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(rekorAnchorArgs(receiptsPath, keyHex, rekorKey, server.URL, "bundle.json"))
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Execute = %v, want %q", err, tc.want)
			}
			if hits.Load() != 0 {
				t.Fatalf("Rekor received %d requests", hits.Load())
			}
		})
	}
}

func TestReceiptsCmdRekorFailedSubmitCanRetry(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	rekorKey := writeRekorKey(t, t.TempDir())
	server, hits := countingRekor(t)
	for attempt := 0; attempt < 2; attempt++ {
		cmd := receiptsCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetArgs(rekorAnchorArgs(receiptsPath, keyHex, rekorKey, server.URL, "bundle.json"))
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unexpected submission") {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("retry requests = %d, want 2", hits.Load())
	}
}

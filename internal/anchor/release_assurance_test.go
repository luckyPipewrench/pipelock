// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
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
)

// TestReleaseAssuranceAnchorLifecycleRecovery exercises the evidence that an
// operator keeps across a process restart: a producer creates receipts, a
// checkpoint is anchored, and the immutable marker is loaded back before the
// original bundle is verified again.
func TestReleaseAssuranceAnchorLifecycleRecovery(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-09-14T12:00:00Z")
	dir := t.TempDir()
	receipts, signerKey := testReceiptChain(t, 3)
	checkpoint, err := BuildCheckpoint("release-assurance", receipts, []string{signerKey})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}

	log := LocalLog{Path: filepath.Join(dir, "anchor.jsonl"), LogID: "release-assurance-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundlePath := "anchors/checkpoint.json"
	bundleData, err := WriteBundleUnderDir(dir, bundlePath, NewBundle(checkpoint, proof))
	if err != nil {
		t.Fatalf("WriteBundleUnderDir: %v", err)
	}
	sum := sha256.Sum256(bundleData)
	marker := StateMarker{
		SessionID:    checkpoint.SessionID,
		FinalSeq:     checkpoint.FinalSeq,
		RootHash:     checkpoint.RootHash,
		Backend:      proof.Backend,
		LogIndex:     proof.LogIndex,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: hex.EncodeToString(sum[:]),
		BundlePath:   bundlePath,
		ReceiptCount: checkpoint.ReceiptCount,
		SignerKey:    signerKey,
	}
	if err := WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}

	marker.Schema = stateMarkerSchema
	markers, err := LoadStateMarkers(dir)
	if err != nil {
		t.Fatalf("LoadStateMarkers after restart: %v", err)
	}
	if len(markers) != 1 || !StateMarkersEqual(markers[0], marker) {
		t.Fatalf("LoadStateMarkers = %+v, want persisted marker %+v", markers, marker)
	}
	loadedCheckpoint, err := LoadStateMarkerCheckpoint(dir, markers[0])
	if err != nil {
		t.Fatalf("LoadStateMarkerCheckpoint after restart: %v", err)
	}
	if !checkpointsEqual(loadedCheckpoint, checkpoint) {
		t.Fatalf("loaded checkpoint = %+v, want %+v", loadedCheckpoint, checkpoint)
	}
	loadedBundle, err := LoadBundle(filepath.Join(dir, bundlePath))
	if err != nil {
		t.Fatalf("LoadBundle after restart: %v", err)
	}
	report := VerifyBundle(loadedBundle, receipts, []string{signerKey}, log)
	if !report.Valid {
		t.Fatalf("VerifyBundle after restart = %+v", report)
	}

	// Positive control for the digest guard: a valid replacement bundle must
	// not be accepted merely because its path is still inside the receipt
	// directory.
	replacement := loadedBundle
	replacement.Limits = append([]string{"replacement limit"}, replacement.Limits...)
	if err := WriteBundle(filepath.Join(dir, bundlePath), replacement); err != nil {
		t.Fatalf("WriteBundle replacement: %v", err)
	}
	if _, err := LoadStateMarkerCheckpoint(dir, marker); err == nil || !strings.Contains(err.Error(), "bundle hash does not match") {
		t.Fatalf("LoadStateMarkerCheckpoint replacement error = %v, want digest rejection", err)
	}

	changedCheckpoint := loadedBundle
	changedCheckpoint.Checkpoint.EndTime = changedCheckpoint.Checkpoint.EndTime.Add(time.Second)
	if report := VerifyBundle(changedCheckpoint, receipts, []string{signerKey}, log); report.Valid || !strings.Contains(report.Error, "checkpoint does not match") {
		t.Fatalf("VerifyBundle changed checkpoint = %+v, want checkpoint rejection", report)
	}
}

func TestReleaseAssuranceAnchorFailureBoundaries(t *testing.T) {
	t.Run("bundle reader rejects unavailable targets", func(t *testing.T) {
		dir := t.TempDir()
		for _, path := range []string{filepath.Join(dir, "missing.json"), dir} {
			t.Run(filepath.Base(path), func(t *testing.T) {
				if _, err := LoadBundle(path); err == nil || !strings.Contains(err.Error(), "read anchor bundle") {
					t.Fatalf("LoadBundle(%q) error = %v, want read failure", path, err)
				}
			})
		}
	})

	t.Run("state marker identity cannot be incomplete", func(t *testing.T) {
		if _, err := StateMarkerPath(t.TempDir(), StateMarker{RootHash: strings.Repeat("a", 64)}); err == nil || !strings.Contains(err.Error(), "session_id is empty") {
			t.Fatalf("StateMarkerPath missing session error = %v", err)
		}
		if _, err := StateMarkerPath(t.TempDir(), StateMarker{SessionID: "release-assurance"}); err == nil || !strings.Contains(err.Error(), "root_hash is empty") {
			t.Fatalf("StateMarkerPath missing root error = %v", err)
		}
	})

	t.Run("local log creation fails closed", func(t *testing.T) {
		checkpoint := Checkpoint{SessionID: "release-assurance"}
		cases := []struct {
			name string
			path func(t *testing.T) string
			want string
		}{
			{
				name: "empty path",
				path: func(*testing.T) string { return "" },
				want: "path required",
			},
			{
				name: "lock parent is a file",
				path: func(t *testing.T) string {
					t.Helper()
					blocker := filepath.Join(t.TempDir(), "blocker")
					if err := os.WriteFile(blocker, []byte("blocker"), filePermissions); err != nil {
						t.Fatalf("WriteFile blocker: %v", err)
					}
					return filepath.Join(blocker, "anchor.jsonl")
				},
				want: "acquire local anchor log lock",
			},
			{
				name: "log path is a directory",
				path: func(t *testing.T) string {
					t.Helper()
					return t.TempDir()
				},
				want: "",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := (LocalLog{Path: tc.path(t)}).Submit(checkpoint)
				if err == nil || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
					t.Fatalf("Submit error = %v, want %q", err, tc.want)
				}
			})
		}
	})
}

// TestReleaseAssuranceRekorConflictResponseLimit ensures a duplicate submission
// cannot turn an oversized conflict response into a second request. The normal
// conflict recovery control is covered by TestRekorLogSubmitRecoversConflictByRetrievingExistingEntry.
func TestReleaseAssuranceRekorConflictResponseLimit(t *testing.T) {
	checkpoint, signer := securityRekorCheckpoint(t)
	const uuid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var getCalls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Location", server.URL+"/api/v1/log/entries/"+uuid)
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(strings.Repeat("x", rekorMaxResponseBytes+1)))
		case http.MethodGet:
			getCalls.Add(1)
			http.Error(w, "unexpected recovery request", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	_, err := (RekorLog{URL: server.URL, Signer: signer}).Submit(checkpoint)
	if err == nil || !strings.Contains(err.Error(), "read rekor response: exceeds") {
		t.Fatalf("Submit oversized conflict response error = %v, want size-limit rejection", err)
	}
	if calls := getCalls.Load(); calls != 0 {
		t.Fatalf("conflict recovery GET calls = %d, want 0 after rejected response", calls)
	}
}

func TestReleaseAssuranceMarkerCoverage(t *testing.T) {
	marker := StateMarker{FinalSeq: 4, ReceiptCount: 7}
	if got := stateMarkerCoverage(marker); got != marker.ReceiptCount {
		t.Fatalf("stateMarkerCoverage with receipt count = %d, want %d", got, marker.ReceiptCount)
	}
	marker.ReceiptCount = 0
	if got := stateMarkerCoverage(marker); got != marker.FinalSeq+1 {
		t.Fatalf("stateMarkerCoverage without receipt count = %d, want %d", got, marker.FinalSeq+1)
	}
}

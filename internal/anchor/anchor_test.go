// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

var errBackendVerify = errors.New("backend verification failed")

type failingBackend struct{}

func (failingBackend) Submit(Checkpoint) (Proof, error) {
	return Proof{}, errBackendVerify
}

func (failingBackend) Verify(Proof, Checkpoint) error {
	return errBackendVerify
}

func testReceiptChain(t *testing.T, n int) ([]receipt.Receipt, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	prev := receipt.GenesisHash
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	receipts := make([]receipt.Receipt, 0, n)
	for i := range n {
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
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		h, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash[%d]: %v", i, err)
		}
		prev = h
		receipts = append(receipts, r)
	}
	return receipts, hex.EncodeToString(pub)
}

func TestLocalLogBundleVerify(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, log)
	if !report.Valid {
		t.Fatalf("VerifyBundle invalid: %s", report.Error)
	}
	if report.RootHash != checkpoint.RootHash || report.Proof.EntryHash == "" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestBundleFileRoundTrip(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	path := filepath.Join(t.TempDir(), "nested", "bundle.json")
	bundle := NewBundle(checkpoint, proof)
	if err := WriteBundle(path, bundle); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	loaded, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if loaded.Backend != LocalBackend || !checkpointsEqual(loaded.Checkpoint, checkpoint) {
		t.Fatalf("loaded bundle = %+v", loaded)
	}
	if loaded.Version != bundle.Version {
		t.Fatalf("loaded.Version = %d, want %d", loaded.Version, bundle.Version)
	}
	if loaded.Proof != bundle.Proof {
		t.Fatalf("loaded.Proof = %+v, want %+v", loaded.Proof, bundle.Proof)
	}
	if !loaded.CreatedAt.Equal(bundle.CreatedAt) {
		t.Fatalf("loaded.CreatedAt = %s, want %s", loaded.CreatedAt, bundle.CreatedAt)
	}
	if len(loaded.Limits) != len(bundle.Limits) {
		t.Fatalf("loaded.Limits = %v, want %v", loaded.Limits, bundle.Limits)
	}
	for i := range bundle.Limits {
		if loaded.Limits[i] != bundle.Limits[i] {
			t.Fatalf("loaded.Limits[%d] = %q, want %q", i, loaded.Limits[i], bundle.Limits[i])
		}
	}
}

func TestWriteBundleRejectsBadFilesystemTargets(t *testing.T) {
	bundle := NewBundle(Checkpoint{SessionID: "proxy", FinalSeq: 1, RootHash: strings.Repeat("a", 64)}, Proof{Backend: LocalBackend})
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	if err := WriteBundle(filepath.Join(blocker, "bundle.json"), bundle); err == nil || !strings.Contains(err.Error(), "create anchor bundle directory") {
		t.Fatalf("WriteBundle through file parent err = %v, want create directory failure", err)
	}
	if err := WriteBundle(dir, bundle); err == nil || !strings.Contains(err.Error(), "write anchor bundle") {
		t.Fatalf("WriteBundle to directory err = %v, want write failure", err)
	}
}

func TestWriteBundleUnderDirWritesNestedBundle(t *testing.T) {
	root := t.TempDir()
	bundle := NewBundle(Checkpoint{SessionID: "proxy", FinalSeq: 1, RootHash: strings.Repeat("a", 64)}, Proof{Backend: LocalBackend})
	rel := filepath.Join("nested", "deeper", "bundle.json")

	if _, err := WriteBundleUnderDir(root, rel, bundle); err != nil {
		t.Fatalf("WriteBundleUnderDir: %v", err)
	}
	loaded, err := LoadBundle(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if loaded.Checkpoint.SessionID != bundle.Checkpoint.SessionID || loaded.Checkpoint.RootHash != bundle.Checkpoint.RootHash {
		t.Fatalf("loaded bundle = %+v, want %+v", loaded, bundle)
	}
}

func TestWriteBundleUnderDirRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	abs := filepath.Join(root, "bundle.json")
	bundle := NewBundle(Checkpoint{SessionID: "proxy", FinalSeq: 1, RootHash: strings.Repeat("a", 64)}, Proof{Backend: LocalBackend})
	for _, rel := range []string{abs, ".", "..", filepath.Join("..", "bundle.json")} {
		t.Run(rel, func(t *testing.T) {
			if _, err := WriteBundleUnderDir(root, rel, bundle); err == nil || !strings.Contains(err.Error(), "stay under receipt directory") {
				t.Fatalf("WriteBundleUnderDir(%q) err = %v, want escape rejection", rel, err)
			}
		})
	}
}

func TestWriteBundleUnderDirRejectsSymlinkComponents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	bundle := NewBundle(Checkpoint{SessionID: "proxy", FinalSeq: 1, RootHash: strings.Repeat("a", 64)}, Proof{Backend: LocalBackend})
	if _, err := WriteBundleUnderDir(root, filepath.Join("link", "bundle.json"), bundle); err == nil {
		t.Fatal("WriteBundleUnderDir accepted a symlinked parent")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("ReadDir outside: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlinked parent received bundle data: %v", entries)
	}
}

func TestWriteBundleUnderDirRejectsSymlinkRootAndFinalPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	bundle := NewBundle(Checkpoint{SessionID: "proxy", FinalSeq: 1, RootHash: strings.Repeat("a", 64)}, Proof{Backend: LocalBackend})

	t.Run("root", func(t *testing.T) {
		outside := t.TempDir()
		root := filepath.Join(t.TempDir(), "root-link")
		if err := os.Symlink(outside, root); err != nil {
			t.Fatalf("Symlink root: %v", err)
		}
		if _, err := WriteBundleUnderDir(root, "bundle.json", bundle); err == nil || !strings.Contains(err.Error(), "open anchor bundle directory") {
			t.Fatalf("WriteBundleUnderDir symlink root err = %v, want refusal", err)
		}
	})

	t.Run("final path", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside-bundle.json")
		if err := os.WriteFile(outside, []byte("do not overwrite"), 0o600); err != nil {
			t.Fatalf("WriteFile outside: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "bundle.json")); err != nil {
			t.Fatalf("Symlink final path: %v", err)
		}
		if _, err := WriteBundleUnderDir(root, "bundle.json", bundle); err == nil || !strings.Contains(err.Error(), "write anchor bundle") {
			t.Fatalf("WriteBundleUnderDir symlink final err = %v, want write refusal", err)
		}
		data, err := os.ReadFile(filepath.Clean(outside))
		if err != nil {
			t.Fatalf("ReadFile outside: %v", err)
		}
		if string(data) != "do not overwrite" {
			t.Fatalf("symlink target was overwritten: %q", data)
		}
	})
}

func TestWriteStateMarkerWritesCanonicalPrivateJSON(t *testing.T) {
	dir := t.TempDir()
	anchoredAt := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	marker := StateMarker{
		SessionID:    "proxy",
		FinalSeq:     17,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		LogIndex:     99,
		AnchoredAt:   anchoredAt,
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	}

	if err := WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}

	path, err := StateMarkerPath(dir, marker)
	if err != nil {
		t.Fatalf("StateMarkerPath: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat anchor-state: %v", err)
	}
	if got := info.Mode().Perm(); got != filePermissions {
		t.Fatalf("anchor-state permissions = %#o, want %#o", got, filePermissions)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "anchor-state.d", ".anchor-state-*.tmp"))
	if err != nil {
		t.Fatalf("Glob temp markers: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary marker files remained: %v", matches)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile anchor-state: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("anchor-state did not end with newline: %q", data)
	}
	var got StateMarker
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal anchor-state: %v", err)
	}
	if got.Schema != "pipelock.anchorstate.v1" ||
		got.SessionID != marker.SessionID ||
		got.FinalSeq != marker.FinalSeq ||
		got.RootHash != marker.RootHash ||
		got.Backend != marker.Backend ||
		got.LogIndex != marker.LogIndex ||
		!got.AnchoredAt.Equal(marker.AnchoredAt) ||
		got.BundleSHA256 != marker.BundleSHA256 ||
		got.BundlePath != marker.BundlePath {
		t.Fatalf("anchor-state marker = %+v, want fields from %+v with canonical schema", got, marker)
	}
}

func TestIsStateMarkerTempName(t *testing.T) {
	tests := map[string]bool{
		".anchor-state-1.tmp":                                true,
		".anchor-state-1234567890.tmp":                       true,
		".anchor-state-0123456789abcdef0123456789abcdef.tmp": true,
		".anchor-state-.tmp":                                 false,
		".anchor-state-12345678901.tmp":                      false,
		".anchor-state-0123456789abcdef0123456789abcdeg.tmp": false,
		".anchor-state-leftover.tmp":                         false,
		"anchor-state-123.tmp":                               false,
		".anchor-state-123.json":                             false,
	}
	for name, want := range tests {
		if got := IsStateMarkerTempName(name); got != want {
			t.Fatalf("IsStateMarkerTempName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLoadStateMarkersIgnoresWriterTempFiles(t *testing.T) {
	dir := t.TempDir()
	marker := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}
	if err := WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.d", ".anchor-state-123456789.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatalf("WriteFile temp marker: %v", err)
	}
	markers, err := LoadStateMarkers(dir)
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	if len(markers) != 1 || markers[0].SessionID != marker.SessionID {
		t.Fatalf("markers = %+v, want only the committed marker", markers)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.d", ".anchor-state-leftover.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatalf("WriteFile foreign temp: %v", err)
	}
	if _, err := LoadStateMarkers(dir); err == nil || !strings.Contains(err.Error(), "unexpected marker") {
		t.Fatalf("LoadStateMarkers foreign temp err = %v, want unexpected marker", err)
	}
}

func TestLoadStateMarkersDiscoversIndependentSessions(t *testing.T) {
	dir := t.TempDir()
	first := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "a-bundle.json",
	}
	second := StateMarker{
		SessionID:    "session-b",
		FinalSeq:     2,
		RootHash:     strings.Repeat("c", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("d", 64),
		BundlePath:   "b-bundle.json",
	}

	if err := WriteStateMarker(dir, first); err != nil {
		t.Fatalf("WriteStateMarker first: %v", err)
	}
	if err := WriteStateMarker(dir, second); err != nil {
		t.Fatalf("WriteStateMarker second: %v", err)
	}

	markers, err := LoadStateMarkers(dir)
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	got := map[string]StateMarker{}
	for _, marker := range markers {
		got[marker.SessionID] = marker
	}
	if len(got) != 2 || got[first.SessionID].RootHash != first.RootHash || got[second.SessionID].RootHash != second.RootHash {
		t.Fatalf("markers = %+v, want both independent sessions", markers)
	}
}

func TestLoadStateMarkersFailsClosedOnStrictIndexViolations(t *testing.T) {
	valid := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("Marshal valid marker: %v", err)
	}

	tests := []struct {
		name    string
		arrange func(t *testing.T, dir string)
		want    string
	}{
		{
			name: "directory entry",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(dir, stateMarkerIndexDir, "bad.json"), 0o750); err != nil {
					t.Fatalf("Mkdir bad marker dir: %v", err)
				}
			},
			want: "not a regular marker",
		},
		{
			name: "filename identity mismatch",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				indexDir := filepath.Join(dir, stateMarkerIndexDir)
				if err := os.MkdirAll(indexDir, 0o750); err != nil {
					t.Fatalf("Mkdir index: %v", err)
				}
				if err := os.WriteFile(filepath.Join(indexDir, "wrong-name.json"), append(validData, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile wrong marker: %v", err)
				}
			},
			want: "does not match marker identity",
		},
		{
			name: "duplicate legacy and indexed marker",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, legacyStateMarker), append(validData, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile legacy marker: %v", err)
				}
				if err := WriteStateMarker(dir, valid); err != nil {
					t.Fatalf("WriteStateMarker duplicate: %v", err)
				}
			},
			want: "duplicates",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.arrange(t, dir)
			if _, err := LoadStateMarkers(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadStateMarkers err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadStateMarkersReadsLegacySingleFile(t *testing.T) {
	dir := t.TempDir()
	legacy := StateMarker{
		Schema:       "pipelock.anchorstate.v1",
		SessionID:    "legacy-session",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "legacy-bundle.json",
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("Marshal legacy marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile legacy marker: %v", err)
	}

	markers, err := LoadStateMarkers(dir)
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	if len(markers) != 1 || markers[0].SessionID != legacy.SessionID {
		t.Fatalf("markers = %+v, want legacy marker", markers)
	}
}

func TestLoadStateMarkersFailsClosedOnCorruptIndex(t *testing.T) {
	dir := t.TempDir()
	marker := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "a-bundle.json",
	}
	if err := WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("WriteStateMarker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor-state.d", "bad.json"), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatalf("WriteFile corrupt marker: %v", err)
	}
	if _, err := LoadStateMarkers(dir); err == nil || !strings.Contains(err.Error(), "parse anchor-state marker") {
		t.Fatalf("LoadStateMarkers err = %v, want corrupt index failure", err)
	}
}

func TestLoadStateMarkersFailsClosedOnHostileFilesystemState(t *testing.T) {
	valid := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("Marshal valid marker: %v", err)
	}

	tests := []struct {
		name    string
		arrange func(t *testing.T, dir string)
		want    string
	}{
		{
			name: "legacy marker symlink",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation needs privileges on Windows")
				}
				target := filepath.Join(dir, "marker-target.json")
				if err := os.WriteFile(target, append(validData, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile target: %v", err)
				}
				if err := os.Symlink(filepath.Base(target), filepath.Join(dir, "anchor-state.json")); err != nil {
					t.Fatalf("Symlink marker: %v", err)
				}
			},
			want: "not a regular file",
		},
		{
			name: "index directory symlink",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation needs privileges on Windows")
				}
				outside := filepath.Join(t.TempDir(), "outside-index")
				if err := os.Mkdir(outside, 0o750); err != nil {
					t.Fatalf("Mkdir outside index: %v", err)
				}
				if err := os.Symlink(outside, filepath.Join(dir, "anchor-state.d")); err != nil {
					t.Fatalf("Symlink index: %v", err)
				}
			},
			want: "not a regular directory",
		},
		{
			name: "oversized legacy marker",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), make([]byte, maxStateMarkerBytes+1), 0o600); err != nil {
					t.Fatalf("WriteFile oversized marker: %v", err)
				}
			},
			want: "exceeds size limit",
		},
		{
			name: "empty required field",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				invalid := valid
				invalid.SessionID = " "
				data, err := json.Marshal(invalid)
				if err != nil {
					t.Fatalf("Marshal invalid marker: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), append(data, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile invalid marker: %v", err)
				}
			},
			want: "session_id is empty",
		},
		{
			name: "invalid digest field",
			arrange: func(t *testing.T, dir string) {
				t.Helper()
				invalid := valid
				invalid.BundleSHA256 = strings.Repeat("B", 64)
				data, err := json.Marshal(invalid)
				if err != nil {
					t.Fatalf("Marshal invalid marker: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dir, "anchor-state.json"), append(data, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile invalid marker: %v", err)
				}
			},
			want: "bundle_sha256 is invalid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.arrange(t, dir)
			if _, err := LoadStateMarkers(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadStateMarkers err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadStateMarkerFileRejectsMalformedFiles(t *testing.T) {
	valid := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("Marshal valid marker: %v", err)
	}

	tests := []struct {
		name    string
		setup   func(t *testing.T, path string)
		wantErr string
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation needs privileges on Windows")
				}
				target := filepath.Join(filepath.Dir(path), "target-marker.json")
				if err := os.WriteFile(target, append(validData, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile target: %v", err)
				}
				if err := os.Symlink(filepath.Base(target), path); err != nil {
					t.Fatalf("Symlink marker: %v", err)
				}
			},
			wantErr: "not a regular file",
		},
		{
			name: "non regular",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatalf("Mkdir marker path: %v", err)
				}
			},
			wantErr: "not a regular file",
		},
		{
			name: "oversized",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, make([]byte, maxStateMarkerBytes+1), 0o600); err != nil {
					t.Fatalf("WriteFile oversized marker: %v", err)
				}
			},
			wantErr: "exceeds size limit",
		},
		{
			name: "corrupt JSON",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(`{"schema":`), 0o600); err != nil {
					t.Fatalf("WriteFile corrupt marker: %v", err)
				}
			},
			wantErr: "parse anchor-state marker",
		},
		{
			name: "schema mismatch",
			setup: func(t *testing.T, path string) {
				t.Helper()
				invalid := valid
				invalid.Schema = "wrong-schema"
				data, err := json.Marshal(invalid)
				if err != nil {
					t.Fatalf("Marshal invalid marker: %v", err)
				}
				if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile invalid marker: %v", err)
				}
			},
			wantErr: "schema",
		},
		{
			name: "blank required field",
			setup: func(t *testing.T, path string) {
				t.Helper()
				invalid := valid
				invalid.BundlePath = " "
				data, err := json.Marshal(invalid)
				if err != nil {
					t.Fatalf("Marshal invalid marker: %v", err)
				}
				if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile invalid marker: %v", err)
				}
			},
			wantErr: "bundle_path is empty",
		},
		{
			name: "valid",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, append(validData, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile valid marker: %v", err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor-state.json")
			tc.setup(t, path)
			got, found, err := LoadStateMarkerFile(path)
			if tc.wantErr != "" {
				if err == nil || found || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadStateMarkerFile found=%v err=%v, want %q", found, err, tc.wantErr)
				}
				return
			}
			if err != nil || !found {
				t.Fatalf("LoadStateMarkerFile found=%v err=%v, want valid marker", found, err)
			}
			if got.SessionID != valid.SessionID || got.BundleSHA256 != valid.BundleSHA256 {
				t.Fatalf("LoadStateMarkerFile = %+v, want valid marker", got)
			}
		})
	}
}

func TestWriteStateMarkerRejectsBadFilesystemTarget(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	err := WriteStateMarker(filepath.Join(blocker, "child"), StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "create anchor-state directory") {
		t.Fatalf("WriteStateMarker err = %v, want create directory failure", err)
	}
}

func TestWriteStateMarkerRejectsSymlinkedIndexDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-index")
	if err := os.Mkdir(outside, 0o750); err != nil {
		t.Fatalf("Mkdir outside index: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "anchor-state.d")); err != nil {
		t.Fatalf("Symlink index: %v", err)
	}
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "not a regular directory") {
		t.Fatalf("WriteStateMarker err = %v, want symlinked index refusal", err)
	}
	entries, readErr := os.ReadDir(outside)
	if readErr != nil {
		t.Fatalf("ReadDir outside index: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("symlinked index received marker data: %v", entries)
	}
}

func TestWriteStateMarkerRejectsDirectoryAtFinalPath(t *testing.T) {
	dir := t.TempDir()
	marker := StateMarker{
		SessionID:    "proxy",
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   filepath.Join(dir, "bundle.json"),
	}
	path, err := StateMarkerPath(dir, marker)
	if err != nil {
		t.Fatalf("StateMarkerPath: %v", err)
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("Mkdir final path: %v", err)
	}
	err = WriteStateMarker(dir, marker)
	if err == nil || !strings.Contains(err.Error(), "rename anchor-state marker") {
		t.Fatalf("WriteStateMarker err = %v, want rename failure", err)
	}
	matches, globErr := filepath.Glob(filepath.Join(dir, "anchor-state.d", ".anchor-state-*.tmp"))
	if globErr != nil {
		t.Fatalf("Glob temp markers: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary marker files remained after rename failure: %v", matches)
	}
}

func TestLoadBundleRejectsStrictJSONViolations(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate": `{"version":1,"version":1}`,
		"unknown":   `{"version":1,"backend":"local","created_at":"2026-06-28T12:00:00Z","checkpoint":{},"proof":{},"limits":[],"extra":true}`,
		"trailing":  `{"version":1} {"version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := LoadBundle(path); err == nil {
				t.Fatal("LoadBundle err = nil, want strict JSON failure")
			}
		})
	}
}

func TestBuildCheckpointRejectsTrustErrors(t *testing.T) {
	if _, err := BuildCheckpoint("proxy", nil, []string{"key"}); err == nil || !strings.Contains(err.Error(), "empty receipt chain") {
		t.Fatalf("empty BuildCheckpoint err = %v", err)
	}
	receipts, _ := testReceiptChain(t, 1)
	if _, err := BuildCheckpoint("proxy", receipts, nil); err == nil || !strings.Contains(err.Error(), "trust anchor required") {
		t.Fatalf("missing trust BuildCheckpoint err = %v", err)
	}
}

func TestVerifyBundleDetectsReceiptRewrite(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	tampered := append([]receipt.Receipt(nil), receipts...)
	tampered[1].ActionRecord.Target = "https://example.test/rewritten"
	report := VerifyBundle(NewBundle(checkpoint, proof), tampered, []string{keyHex}, log)
	if report.Valid || !strings.Contains(report.Error, "invalid receipt chain") {
		t.Fatalf("tampered receipt report = %+v, want invalid chain", report)
	}
}

func TestVerifyBundleRejectsBackendMismatch(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := NewBundle(checkpoint, proof)
	bundle.Backend = "rekor-prod-transparency-log"

	report := VerifyBundle(bundle, receipts, []string{keyHex}, log)
	if report.Valid {
		t.Fatalf("forged backend label produced a valid report: %+v", report)
	}
	if report.Backend != "" {
		t.Fatalf("report.Backend = %q, want empty unverified backend", report.Backend)
	}
	if !strings.Contains(report.Error, "does not match proof backend") {
		t.Fatalf("report.Error = %q, want backend mismatch", report.Error)
	}
}

func TestVerifyBundleReportLimitsAreCanonical(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := NewBundle(checkpoint, proof)
	bundle.Limits = []string{"operator-independent witness PROVEN"}

	report := VerifyBundle(bundle, receipts, []string{keyHex}, log)
	if !report.Valid {
		t.Fatalf("VerifyBundle invalid: %s", report.Error)
	}
	if report.Backend != LocalBackend {
		t.Fatalf("report.Backend = %q, want %q", report.Backend, LocalBackend)
	}
	if len(report.Limits) != len(DefaultLimits) {
		t.Fatalf("report.Limits = %v, want DefaultLimits", report.Limits)
	}
	for i := range DefaultLimits {
		if report.Limits[i] != DefaultLimits[i] {
			t.Fatalf("report.Limits[%d] = %q, want %q", i, report.Limits[i], DefaultLimits[i])
		}
	}
}

func TestVerifyBundleRejectsInvalidBundleAndBackendStates(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundle := NewBundle(checkpoint, proof)

	badVersion := bundle
	badVersion.Version = 99
	if report := VerifyBundle(badVersion, receipts, []string{keyHex}, log); report.Valid || !strings.Contains(report.Error, "unsupported") {
		t.Fatalf("bad version report = %+v", report)
	}
	if report := VerifyBundle(bundle, receipts, []string{keyHex}, nil); report.Valid || !strings.Contains(report.Error, "backend required") {
		t.Fatalf("nil backend report = %+v", report)
	}
	rewrittenCheckpoint := bundle
	rewrittenCheckpoint.Checkpoint.RootHash = strings.Repeat("0", 64)
	if report := VerifyBundle(rewrittenCheckpoint, receipts, []string{keyHex}, log); report.Valid || !strings.Contains(report.Error, "checkpoint does not match") {
		t.Fatalf("checkpoint report = %+v", report)
	}
	if report := VerifyBundle(bundle, receipts, []string{keyHex}, failingBackend{}); report.Valid || !strings.Contains(report.Error, errBackendVerify.Error()) {
		t.Fatalf("backend report = %+v", report)
	}
}

func TestVerifyBundleDetectsLocalLogRewrite(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	entries[0].Checkpoint.RootHash = strings.Repeat("0", 64)
	data, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(log.Path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, log)
	if report.Valid || !strings.Contains(report.Error, "hash mismatch") {
		t.Fatalf("rewritten log report = %+v, want hash mismatch", report)
	}
}

func TestLocalLogVerifyRejectsBadProofs(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	proof, err := log.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	cases := []struct {
		name  string
		proof Proof
		want  string
	}{
		{name: "backend", proof: Proof{Backend: "rekor"}, want: "not"},
		{name: "log id", proof: Proof{Backend: LocalBackend, LogID: "other"}, want: "log_id"},
		{name: "index", proof: Proof{Backend: LocalBackend, LogID: "test-log", LogIndex: 99}, want: "outside local log length"},
		{name: "entry hash", proof: Proof{Backend: LocalBackend, LogID: "test-log", EntryHash: "bad", LogRootHash: proof.LogRootHash}, want: "entry_hash"},
		{name: "root hash", proof: Proof{Backend: LocalBackend, LogID: "test-log", EntryHash: proof.EntryHash, LogRootHash: "bad"}, want: "log_root_hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := log.Verify(tc.proof, checkpoint); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify err = %v, want %q", err, tc.want)
			}
		})
	}

	changed := checkpoint
	changed.RootHash = strings.Repeat("f", 64)
	if err := log.Verify(proof, changed); err == nil || !strings.Contains(err.Error(), "checkpoint does not match") {
		t.Fatalf("Verify err = %v, want checkpoint mismatch", err)
	}
}

func TestLocalLogSubmitRejectsMixedExistingLogID(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	for range 2 {
		if _, err := log.Submit(checkpoint); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	entries[1].LogID = "other-log"
	entries[1].Hash = localEntryHash(entries[1])
	writeLocalLogEntries(t, log.Path, entries)

	_, err = log.Submit(checkpoint)
	if err == nil || !strings.Contains(err.Error(), "log_id mismatch at index 1") {
		t.Fatalf("Submit err = %v, want mixed log_id rejection", err)
	}
}

func TestReadLocalLogRejectsCorruptEntries(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	if _, err := log.Submit(checkpoint); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}

	tests := map[string]func([]LocalLogEntry){
		"version": func(in []LocalLogEntry) { in[0].Version = 99 },
		"index":   func(in []LocalLogEntry) { in[0].Index = 3 },
		"prev":    func(in []LocalLogEntry) { in[0].PrevHash = "bad" },
		"hash":    func(in []LocalLogEntry) { in[0].Hash = "bad" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copyEntries := append([]LocalLogEntry(nil), entries...)
			mutate(copyEntries)
			path := filepath.Join(t.TempDir(), "anchor.jsonl")
			writeLocalLogEntries(t, path, copyEntries)
			if _, err := ReadLocalLog(path); err == nil {
				t.Fatal("ReadLocalLog err = nil, want corrupt entry failure")
			}
		})
	}
}

func TestLocalLogSubmitSerializesConcurrentAppends(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 3)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	log := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}

	const submits = 8
	var wg sync.WaitGroup
	errs := make(chan error, submits)
	for range submits {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := log.Submit(checkpoint)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	entries, err := ReadLocalLog(log.Path)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	if len(entries) != submits {
		t.Fatalf("len(entries) = %d, want %d", len(entries), submits)
	}
	for i, entry := range entries {
		if entry.Index != uint64(i) {
			t.Fatalf("entries[%d].Index = %d", i, entry.Index)
		}
	}
}

func TestLocalLogDefaults(t *testing.T) {
	if got := (LocalLog{}).logID(); got != DefaultLocalLogID {
		t.Fatalf("logID = %q, want %q", got, DefaultLocalLogID)
	}
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "")
	if got := nowString(); got == "" {
		t.Fatal("nowString returned empty timestamp")
	}
}

func writeLocalLogEntries(t *testing.T, path string, entries []LocalLogEntry) {
	t.Helper()
	var lines []byte
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		lines = append(lines, data...)
		lines = append(lines, '\n')
	}
	if err := os.WriteFile(path, lines, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestWriteStateMarkerRejectsMarkerWithoutIdentity(t *testing.T) {
	t.Parallel()
	err := WriteStateMarker(t.TempDir(), StateMarker{
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil || !strings.Contains(err.Error(), "session_id is empty") {
		t.Fatalf("WriteStateMarker err = %v, want session_id rejection", err)
	}
}

func TestWriteStateMarkerRejectsInvalidMarkerDigests(t *testing.T) {
	valid := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}
	tests := []struct {
		name   string
		mutate func(StateMarker) StateMarker
		want   string
	}{
		{
			name: "short root hash",
			mutate: func(marker StateMarker) StateMarker {
				marker.RootHash = "abc"
				return marker
			},
			want: "root_hash is invalid",
		},
		{
			name: "short bundle sha",
			mutate: func(marker StateMarker) StateMarker {
				marker.BundleSHA256 = "abc"
				return marker
			},
			want: "bundle_sha256 is invalid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := WriteStateMarker(t.TempDir(), tc.mutate(valid)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("WriteStateMarker err = %v, want %q", err, tc.want)
			}
		})
	}
}

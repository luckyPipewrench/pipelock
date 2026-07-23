// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

func TestLoadStateMarkerCheckpointRejectsInvalidBundleMaterial(t *testing.T) {
	dir := t.TempDir()
	_, keyHex := testReceiptChain(t, 2)
	checkpoint := Checkpoint{
		SessionID:    "proxy",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		ReceiptCount: 2,
		SignerKeys:   []string{keyHex},
	}
	bundleSeq := 0
	bundleDataByRel := make(map[string][]byte)
	writeBundle := func(t *testing.T, cp Checkpoint, proof Proof) StateMarker {
		t.Helper()
		bundleSeq++
		rel := "bundle-" + strconv.Itoa(bundleSeq) + ".json"
		data, err := WriteBundleUnderDir(dir, rel, NewBundle(cp, proof))
		if err != nil {
			t.Fatalf("WriteBundleUnderDir: %v", err)
		}
		bundleDataByRel[rel] = append([]byte(nil), data...)
		sum := sha256.Sum256(data)
		return StateMarker{
			Schema:       stateMarkerSchema,
			SessionID:    cp.SessionID,
			FinalSeq:     cp.FinalSeq,
			RootHash:     cp.RootHash,
			Backend:      proof.Backend,
			LogIndex:     proof.LogIndex,
			AnchoredAt:   time.Now().UTC(),
			BundleSHA256: hex.EncodeToString(sum[:]),
			BundlePath:   rel,
		}
	}
	baseProof := Proof{Backend: LocalBackend, LogIndex: 7}
	baseMarker := writeBundle(t, checkpoint, baseProof)

	tests := []struct {
		name   string
		marker StateMarker
		setup  func(t *testing.T, marker *StateMarker)
		want   string
	}{
		{
			name:   "symlinked bundle escapes receipt directory",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation requires privileges on Windows")
				}
				data := bundleDataByRel[baseMarker.BundlePath]
				outside := filepath.Join(t.TempDir(), "bundle.json")
				if err := os.WriteFile(outside, data, 0o600); err != nil {
					t.Fatalf("WriteFile outside bundle: %v", err)
				}
				marker.BundlePath = "linked-bundle.json"
				if err := os.Symlink(outside, filepath.Join(dir, marker.BundlePath)); err != nil {
					t.Fatalf("Symlink bundle: %v", err)
				}
			},
			want: "path escapes from parent",
		},
		{
			name:   "path escape",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				marker.BundlePath = "../bundle.json"
			},
			want: "must stay under receipt directory",
		},
		{
			name:   "missing bundle",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				marker.BundlePath = "missing.json"
			},
			want: "open anchor-state bundle",
		},
		{
			name:   "hash mismatch",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				marker.BundleSHA256 = strings.Repeat("b", 64)
			},
			want: "bundle hash does not match state marker",
		},
		{
			name:   "malformed bundle",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				data := []byte(`{"version":`)
				sum := sha256.Sum256(data)
				marker.BundlePath = "malformed.json"
				marker.BundleSHA256 = hex.EncodeToString(sum[:])
				if err := os.WriteFile(filepath.Join(dir, marker.BundlePath), data, 0o600); err != nil {
					t.Fatalf("WriteFile malformed bundle: %v", err)
				}
			},
			want: "parse anchor bundle",
		},
		{
			name:   "marker fields mismatch bundle",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				marker.FinalSeq++
			},
			want: "bundle does not match state marker",
		},
		{
			name:   "zero receipt count",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				cp := checkpoint
				cp.ReceiptCount = 0
				*marker = writeBundle(t, cp, baseProof)
			},
			want: "receipt_count is zero",
		},
		{
			name:   "missing signer keys",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				cp := checkpoint
				cp.SignerKeys = nil
				*marker = writeBundle(t, cp, baseProof)
			},
			want: "has no signer keys",
		},
		{
			name:   "invalid signer key",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				cp := checkpoint
				cp.SignerKeys = []string{strings.Repeat("A", 64)}
				*marker = writeBundle(t, cp, baseProof)
			},
			want: "signer key is invalid",
		},
		{
			name:   "receipt count mismatch",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				marker.ReceiptCount = checkpoint.ReceiptCount + 1
				marker.SignerKey = keyHex
			},
			want: "receipt_count does not match state marker",
		},
		{
			name:   "signer key mismatch",
			marker: baseMarker,
			setup: func(t *testing.T, marker *StateMarker) {
				t.Helper()
				marker.ReceiptCount = checkpoint.ReceiptCount
				marker.SignerKey = strings.Repeat("b", 64)
			},
			want: "signer_key does not match state marker",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			marker := tc.marker
			tc.setup(t, &marker)
			if _, err := LoadStateMarkerCheckpoint(dir, marker); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadStateMarkerCheckpoint err = %v, want %q", err, tc.want)
			}
		})
	}
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
		ReceiptCount: 18,
		SignerKey:    strings.Repeat("c", 64),
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
	pointerPath := filepath.Join(dir, legacyStateMarker)
	pointerInfo, err := os.Stat(pointerPath)
	if err != nil {
		t.Fatalf("Stat latest pointer: %v", err)
	}
	if got := pointerInfo.Mode().Perm(); got != filePermissions {
		t.Fatalf("latest pointer permissions = %#o, want %#o", got, filePermissions)
	}
	rootTemps, err := filepath.Glob(filepath.Join(dir, ".anchor-state-*.tmp"))
	if err != nil {
		t.Fatalf("Glob latest-pointer temp markers: %v", err)
	}
	if len(rootTemps) != 0 {
		t.Fatalf("temporary latest-pointer files remained: %v", rootTemps)
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
		got.BundlePath != marker.BundlePath ||
		got.ReceiptCount != marker.ReceiptCount ||
		got.SignerKey != marker.SignerKey {
		t.Fatalf("anchor-state marker = %+v, want fields from %+v with canonical schema", got, marker)
	}
	pointer, found, err := LoadStateMarkerFile(pointerPath)
	if err != nil || !found || !StateMarkersEqual(got, pointer) {
		t.Fatalf("latest pointer = (%+v, %v, %v), want indexed marker %+v", pointer, found, err, got)
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

func TestLoadStateMarkersTreatsMatchingLatestPointerAsIndexAlias(t *testing.T) {
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
	markers, err := LoadStateMarkers(dir)
	if err != nil {
		t.Fatalf("LoadStateMarkers: %v", err)
	}
	if len(markers) != 1 || markers[0].SessionID != marker.SessionID {
		t.Fatalf("LoadStateMarkers = %+v, want one marker without pointer duplication", markers)
	}
}

func TestLoadStateMarkersRejectsMutablePointerNotInIndex(t *testing.T) {
	dir := t.TempDir()
	indexed := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "indexed-bundle.json",
	}
	if err := WriteStateMarker(dir, indexed); err != nil {
		t.Fatalf("WriteStateMarker indexed: %v", err)
	}
	forgedPointer := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     2,
		RootHash:     strings.Repeat("c", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("d", 64),
		BundlePath:   "forged-pointer-bundle.json",
	}
	data, err := json.Marshal(forgedPointer)
	if err != nil {
		t.Fatalf("Marshal forged pointer: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyStateMarker), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile forged latest pointer: %v", err)
	}

	if _, err := LoadStateMarkers(dir); err == nil || !strings.Contains(err.Error(), "latest pointer does not match immutable marker history") {
		t.Fatalf("LoadStateMarkers err = %v, want latest-pointer mismatch", err)
	}
}

func TestWriteStateMarkerPreservesImmutableIdentity(t *testing.T) {
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
		t.Fatalf("WriteStateMarker first: %v", err)
	}
	if err := WriteStateMarker(dir, marker); err != nil {
		t.Fatalf("WriteStateMarker idempotent retry: %v", err)
	}
	conflict := marker
	conflict.BundlePath = "replacement.json"
	if err := WriteStateMarker(dir, conflict); err == nil || !strings.Contains(err.Error(), "different contents") {
		t.Fatalf("WriteStateMarker replacement err = %v, want immutable identity rejection", err)
	}
	path, err := StateMarkerPath(dir, marker)
	if err != nil {
		t.Fatalf("StateMarkerPath: %v", err)
	}
	got, found, err := LoadStateMarkerFile(path)
	if err != nil || !found || got.BundlePath != marker.BundlePath {
		t.Fatalf("immutable marker = (%+v, %v, %v), want original", got, found, err)
	}
}

func TestWriteStateMarkerLatestPointerKeepsHighestCoverage(t *testing.T) {
	dir := t.TempDir()
	higher := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     9,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "higher.json",
		ReceiptCount: 10,
		SignerKey:    strings.Repeat("c", 64),
	}
	if err := WriteStateMarker(dir, higher); err != nil {
		t.Fatalf("WriteStateMarker higher: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, legacyStateMarker)); err != nil {
		t.Fatalf("Remove latest pointer: %v", err)
	}
	lower := higher
	lower.FinalSeq = 7
	lower.RootHash = strings.Repeat("d", 64)
	lower.BundleSHA256 = strings.Repeat("e", 64)
	lower.BundlePath = "lower.json"
	lower.ReceiptCount = 8
	if err := WriteStateMarker(dir, lower); err != nil {
		t.Fatalf("WriteStateMarker lower: %v", err)
	}

	latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
	if err != nil || !found {
		t.Fatalf("LoadStateMarkerFile latest = (%+v, %v, %v)", latest, found, err)
	}
	higher.Schema = stateMarkerSchema
	if !StateMarkersEqual(latest, higher) {
		t.Fatalf("latest pointer = %+v, want higher coverage %+v", latest, higher)
	}
}

func TestWriteStateMarkerConcurrentPointerKeepsHighestCoverage(t *testing.T) {
	const writers = 64
	dir := t.TempDir()
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		coverage := uint64(i + 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rootHash := sha256.Sum256([]byte("concurrent-anchor-" + strconv.FormatUint(coverage, 10)))
			bundleHash := sha256.Sum256([]byte("concurrent-bundle-" + strconv.FormatUint(coverage, 10)))
			errs <- WriteStateMarker(dir, StateMarker{
				SessionID:    "session-a",
				FinalSeq:     coverage - 1,
				RootHash:     hex.EncodeToString(rootHash[:]),
				Backend:      LocalBackend,
				AnchoredAt:   time.Unix(1, 0).UTC(),
				BundleSHA256: hex.EncodeToString(bundleHash[:]),
				BundlePath:   "bundle-" + strconv.FormatUint(coverage, 10) + ".json",
				ReceiptCount: coverage,
				SignerKey:    strings.Repeat("c", 64),
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("WriteStateMarker concurrent: %v", err)
		}
	}
	latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
	if err != nil || !found {
		t.Fatalf("LoadStateMarkerFile latest = (%+v, %v, %v)", latest, found, err)
	}
	if latest.ReceiptCount != writers {
		t.Fatalf("latest receipt_count = %d, want highest concurrent coverage %d", latest.ReceiptCount, writers)
	}
}

func TestLoadIndexedStateMarkerRejectsHostileParent(t *testing.T) {
	marker := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}
	t.Run("missing index", func(t *testing.T) {
		if _, found, err := LoadIndexedStateMarker(t.TempDir(), marker); err != nil || found {
			t.Fatalf("LoadIndexedStateMarker found=%v err=%v, want absent", found, err)
		}
	})
	t.Run("valid index", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteStateMarker(dir, marker); err != nil {
			t.Fatalf("WriteStateMarker: %v", err)
		}
		got, found, err := LoadIndexedStateMarker(dir, marker)
		if err != nil || !found || got.RootHash != marker.RootHash {
			t.Fatalf("LoadIndexedStateMarker = (%+v, %v, %v), want marker", got, found, err)
		}
	})
	t.Run("symlinked index", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(dir, stateMarkerIndexDir)); err != nil {
			t.Fatalf("Symlink index: %v", err)
		}
		if _, found, err := LoadIndexedStateMarker(dir, marker); err == nil || found || !strings.Contains(err.Error(), "not a regular directory") {
			t.Fatalf("LoadIndexedStateMarker found=%v err=%v, want symlink rejection", found, err)
		}
	})
	t.Run("invalid marker identity", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, stateMarkerIndexDir), 0o750); err != nil {
			t.Fatalf("Mkdir index: %v", err)
		}
		if _, found, err := LoadIndexedStateMarker(dir, StateMarker{}); err == nil || found || !strings.Contains(err.Error(), "session_id is empty") {
			t.Fatalf("LoadIndexedStateMarker found=%v err=%v, want identity rejection", found, err)
		}
	})
	t.Run("wrong content at requested path", func(t *testing.T) {
		dir := t.TempDir()
		requested := marker
		requested.Schema = stateMarkerSchema
		wrong := requested
		wrong.FinalSeq++
		wrong.RootHash = strings.Repeat("c", 64)
		wrong.BundleSHA256 = strings.Repeat("d", 64)
		path, err := StateMarkerPath(dir, requested)
		if err != nil {
			t.Fatalf("StateMarkerPath requested: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("MkdirAll index: %v", err)
		}
		data, err := json.Marshal(wrong)
		if err != nil {
			t.Fatalf("Marshal wrong marker: %v", err)
		}
		if err := os.WriteFile(filepath.Clean(path), append(data, '\n'), 0o600); err != nil {
			t.Fatalf("WriteFile wrong marker: %v", err)
		}
		if _, found, err := LoadIndexedStateMarker(dir, requested); err == nil || found || !strings.Contains(err.Error(), "does not match requested marker identity") {
			t.Fatalf("LoadIndexedStateMarker found=%v err=%v, want identity mismatch", found, err)
		}
	})
	t.Run("symlinked marker entry", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation needs privileges on Windows")
		}
		dir := t.TempDir()
		requested := marker
		requested.Schema = stateMarkerSchema
		path, err := StateMarkerPath(dir, requested)
		if err != nil {
			t.Fatalf("StateMarkerPath requested: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("MkdirAll index: %v", err)
		}
		outside := filepath.Join(t.TempDir(), "outside-marker.json")
		data, err := json.Marshal(requested)
		if err != nil {
			t.Fatalf("Marshal requested marker: %v", err)
		}
		if err := os.WriteFile(outside, append(data, '\n'), 0o600); err != nil {
			t.Fatalf("WriteFile outside marker: %v", err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatalf("Symlink marker path: %v", err)
		}
		if _, found, err := LoadIndexedStateMarker(dir, requested); err == nil || found {
			t.Fatalf("LoadIndexedStateMarker found=%v err=%v, want no-follow refusal", found, err)
		}
	})
	t.Run("directory at marker entry", func(t *testing.T) {
		dir := t.TempDir()
		requested := marker
		requested.Schema = stateMarkerSchema
		path, err := StateMarkerPath(dir, requested)
		if err != nil {
			t.Fatalf("StateMarkerPath requested: %v", err)
		}
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("MkdirAll marker path: %v", err)
		}
		if _, found, err := LoadIndexedStateMarker(dir, requested); err == nil || found || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("LoadIndexedStateMarker found=%v err=%v, want regular-file refusal", found, err)
		}
	})
	t.Run("missing receipt directory", func(t *testing.T) {
		if _, err := LoadStateMarkers(filepath.Join(t.TempDir(), "missing")); err != nil {
			t.Fatalf("LoadStateMarkers missing root err = %v, want absent history", err)
		}
	})
	t.Run("invalid indexed marker name", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteStateMarker(dir, marker); err != nil {
			t.Fatalf("WriteStateMarker: %v", err)
		}
		index, err := openStateMarkerIndex(dir)
		if err != nil {
			t.Fatalf("openStateMarkerIndex: %v", err)
		}
		defer func() { _ = index.Close() }()
		if _, found, err := index.LoadStateMarker(filepath.Join("nested", "marker.json")); err == nil || found || !strings.Contains(err.Error(), "marker name") {
			t.Fatalf("LoadStateMarker invalid name found=%v err=%v, want name rejection", found, err)
		}
	})
}

func TestLoadStateMarkersResilientRecoveryCases(t *testing.T) {
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

	t.Run("missing index", func(t *testing.T) {
		markers, skipped, err := LoadStateMarkersResilient(t.TempDir())
		if err != nil || len(markers) != 0 || skipped != 0 {
			t.Fatalf("LoadStateMarkersResilient = (%+v, %d, %v), want empty", markers, skipped, err)
		}
	})
	t.Run("legacy marker", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, legacyStateMarker), append(validData, '\n'), 0o600); err != nil {
			t.Fatalf("WriteFile legacy marker: %v", err)
		}
		markers, skipped, err := LoadStateMarkersResilient(dir)
		if err != nil || len(markers) != 1 || skipped != 0 {
			t.Fatalf("LoadStateMarkersResilient = (%+v, %d, %v), want legacy marker", markers, skipped, err)
		}
	})
	t.Run("corrupt legacy marker", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, legacyStateMarker), []byte(`{"schema":`), 0o600); err != nil {
			t.Fatalf("WriteFile corrupt legacy marker: %v", err)
		}
		markers, skipped, err := LoadStateMarkersResilient(dir)
		if err != nil || len(markers) != 0 || skipped != 1 {
			t.Fatalf("LoadStateMarkersResilient = (%+v, %d, %v), want one skipped legacy marker", markers, skipped, err)
		}
	})
	t.Run("damaged index entries", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteStateMarker(dir, valid); err != nil {
			t.Fatalf("WriteStateMarker valid: %v", err)
		}
		indexDir := filepath.Join(dir, stateMarkerIndexDir)
		if err := os.WriteFile(filepath.Join(indexDir, ".anchor-state-123.tmp"), []byte("partial"), 0o600); err != nil {
			t.Fatalf("WriteFile temp marker: %v", err)
		}
		if err := os.Mkdir(filepath.Join(indexDir, "directory.json"), 0o750); err != nil {
			t.Fatalf("Mkdir marker entry: %v", err)
		}
		if err := os.WriteFile(filepath.Join(indexDir, "foreign.txt"), []byte("foreign"), 0o600); err != nil {
			t.Fatalf("WriteFile foreign entry: %v", err)
		}
		if err := os.Symlink(filepath.Join(indexDir, "foreign.txt"), filepath.Join(indexDir, "symlink.json")); err != nil {
			t.Fatalf("Symlink marker entry: %v", err)
		}
		if err := os.WriteFile(filepath.Join(indexDir, "corrupt.json"), []byte(`{"schema":`), 0o600); err != nil {
			t.Fatalf("WriteFile corrupt marker: %v", err)
		}
		if err := os.WriteFile(filepath.Join(indexDir, "wrong-name.json"), append(validData, '\n'), 0o600); err != nil {
			t.Fatalf("WriteFile wrong-name marker: %v", err)
		}

		markers, skipped, err := LoadStateMarkersResilient(dir)
		if err != nil || len(markers) != 1 || skipped != 5 {
			t.Fatalf("LoadStateMarkersResilient = (%+v, %d, %v), want one valid and five skipped", markers, skipped, err)
		}
	})
	t.Run("hostile index directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(dir, stateMarkerIndexDir)); err != nil {
			t.Fatalf("Symlink index: %v", err)
		}
		if _, _, err := LoadStateMarkersResilient(dir); err == nil || !strings.Contains(err.Error(), "not a regular directory") {
			t.Fatalf("LoadStateMarkersResilient err = %v, want hostile index rejection", err)
		}
	})
}

func TestWriteStateMarkerLatestPointerOrderingAndConflicts(t *testing.T) {
	newMarker := func(finalSeq uint64, rootByte, bundleByte string) StateMarker {
		return StateMarker{
			SessionID:    "session-a",
			FinalSeq:     finalSeq,
			RootHash:     strings.Repeat(rootByte, 64),
			Backend:      LocalBackend,
			AnchoredAt:   time.Now().UTC(),
			BundleSHA256: strings.Repeat(bundleByte, 64),
			BundlePath:   "bundle-" + rootByte + ".json",
		}
	}

	t.Run("higher pointer ignores later lower marker", func(t *testing.T) {
		dir := t.TempDir()
		higher := newMarker(9, "a", "b")
		if err := WriteStateMarker(dir, higher); err != nil {
			t.Fatalf("WriteStateMarker higher: %v", err)
		}
		if err := WriteStateMarker(dir, newMarker(7, "c", "d")); err != nil {
			t.Fatalf("WriteStateMarker lower: %v", err)
		}
		latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
		if err != nil || !found || latest.FinalSeq != higher.FinalSeq || latest.RootHash != higher.RootHash {
			t.Fatalf("latest marker = (%+v, %v, %v), want higher marker", latest, found, err)
		}
	})
	t.Run("higher marker replaces lower pointer", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteStateMarker(dir, newMarker(1, "a", "b")); err != nil {
			t.Fatalf("WriteStateMarker lower: %v", err)
		}
		higher := newMarker(2, "c", "d")
		if err := WriteStateMarker(dir, higher); err != nil {
			t.Fatalf("WriteStateMarker higher: %v", err)
		}
		latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
		if err != nil || !found || latest.RootHash != higher.RootHash {
			t.Fatalf("latest marker = (%+v, %v, %v), want replacement", latest, found, err)
		}
	})
	t.Run("equal coverage conflict", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteStateMarker(dir, newMarker(1, "a", "b")); err != nil {
			t.Fatalf("WriteStateMarker first: %v", err)
		}
		err := WriteStateMarker(dir, newMarker(1, "c", "d"))
		if err == nil || !strings.Contains(err.Error(), "conflicts with latest marker") {
			t.Fatalf("WriteStateMarker conflict err = %v, want latest conflict", err)
		}
	})
	t.Run("maximum legacy sequence does not overflow", func(t *testing.T) {
		marker := newMarker(math.MaxUint64, "a", "b")
		if got := stateMarkerCoverage(marker); got != math.MaxUint64 {
			t.Fatalf("stateMarkerCoverage = %d, want MaxUint64", got)
		}
	})
}

func TestUpdateLatestStateMarkerRejectsUnsafeRecovery(t *testing.T) {
	base := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	}

	t.Run("structural index failure", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(dir, stateMarkerIndexDir)); err != nil {
			t.Fatalf("Symlink index: %v", err)
		}
		if err := updateLatestStateMarker(dir, base, []byte("{}\n")); err == nil || !strings.Contains(err.Error(), "not a regular directory") {
			t.Fatalf("updateLatestStateMarker err = %v, want structural rejection", err)
		}
	})

	t.Run("equal coverage history conflict", func(t *testing.T) {
		dir := t.TempDir()
		indexDir := filepath.Join(dir, stateMarkerIndexDir)
		if err := os.Mkdir(indexDir, 0o750); err != nil {
			t.Fatalf("Mkdir index: %v", err)
		}
		for _, rootByte := range []string{"c", "d"} {
			marker := base
			marker.RootHash = strings.Repeat(rootByte, 64)
			marker.BundleSHA256 = strings.Repeat(rootByte, 64)
			path, err := StateMarkerPath(dir, marker)
			if err != nil {
				t.Fatalf("StateMarkerPath: %v", err)
			}
			data, err := json.Marshal(marker)
			if err != nil {
				t.Fatalf("Marshal marker: %v", err)
			}
			if err := os.WriteFile(filepath.Clean(path), append(data, '\n'), 0o600); err != nil {
				t.Fatalf("WriteFile marker: %v", err)
			}
		}
		if err := updateLatestStateMarker(dir, base, []byte("{}\n")); err == nil || !strings.Contains(err.Error(), "conflicts with history") {
			t.Fatalf("updateLatestStateMarker err = %v, want history conflict", err)
		}
	})
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

func TestWriteStateMarkerRejectsCorruptLegacyPointerBeforeMigration(t *testing.T) {
	dir := t.TempDir()
	// A corrupt legacy pointer with no index yet must not be silently overwritten
	// by a fresh index and pointer: that would erase the evidence it was damaged.
	corrupt := []byte(`{"schema":`)
	if err := os.WriteFile(filepath.Join(dir, legacyStateMarker), corrupt, filePermissions); err != nil {
		t.Fatalf("write corrupt legacy: %v", err)
	}
	err := WriteStateMarker(dir, StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
	})
	if err == nil {
		t.Fatal("WriteStateMarker err = nil, want fail-closed on a corrupt legacy pointer")
	}
	if got, _ := os.ReadFile(filepath.Clean(filepath.Join(dir, legacyStateMarker))); string(got) != string(corrupt) {
		t.Fatalf("legacy pointer = %q, want the corrupt file preserved, not overwritten", got)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, stateMarkerIndexDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("index dir stat err = %v, want no index created over a corrupt legacy pointer", statErr)
	}
}

func TestWriteStateMarkerMigratesLegacyPointerBeforeCreatingIndex(t *testing.T) {
	dir := t.TempDir()
	legacy := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    "session-a",
		FinalSeq:     9,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC().Add(-time.Minute),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "legacy-bundle.json",
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("Marshal legacy marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyStateMarker), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile legacy marker: %v", err)
	}
	lower := legacy
	lower.Schema = ""
	lower.FinalSeq = 7
	lower.RootHash = strings.Repeat("c", 64)
	lower.BundleSHA256 = strings.Repeat("d", 64)
	lower.BundlePath = "lower-bundle.json"
	if err := WriteStateMarker(dir, lower); err != nil {
		t.Fatalf("WriteStateMarker lower: %v", err)
	}

	markers, skipped, err := LoadStateMarkersResilient(dir)
	if err != nil || skipped != 0 || len(markers) != 2 {
		t.Fatalf("LoadStateMarkersResilient = (%+v, %d, %v), want migrated legacy plus lower marker", markers, skipped, err)
	}
	legacyPath, err := StateMarkerPath(dir, legacy)
	if err != nil {
		t.Fatalf("StateMarkerPath legacy: %v", err)
	}
	got, found, err := LoadStateMarkerFile(legacyPath)
	if err != nil || !found || !StateMarkersEqual(got, legacy) {
		t.Fatalf("migrated legacy marker = (%+v, %v, %v), want %+v", got, found, err, legacy)
	}
	latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
	if err != nil || !found || !StateMarkersEqual(latest, legacy) {
		t.Fatalf("latest pointer = (%+v, %v, %v), want higher legacy marker", latest, found, err)
	}
}

func TestWriteStateMarkerHydratesLegacyCoverageBeforePointerOrdering(t *testing.T) {
	dir := t.TempDir()
	legacyCheckpoint := Checkpoint{
		SessionID:    "session-a",
		FinalSeq:     2,
		RootHash:     strings.Repeat("a", 64),
		ReceiptCount: 100,
		SignerKeys:   []string{strings.Repeat("b", 64)},
	}
	legacyBundlePath := "legacy-rotated-bundle.json"
	bundleData, err := WriteBundleUnderDir(dir, legacyBundlePath, NewBundle(legacyCheckpoint, Proof{
		Backend:  LocalBackend,
		LogIndex: 9,
	}))
	if err != nil {
		t.Fatalf("WriteBundleUnderDir legacy: %v", err)
	}
	bundleSum := sha256.Sum256(bundleData)
	legacy := StateMarker{
		Schema:       stateMarkerSchema,
		SessionID:    legacyCheckpoint.SessionID,
		FinalSeq:     legacyCheckpoint.FinalSeq,
		RootHash:     legacyCheckpoint.RootHash,
		Backend:      LocalBackend,
		LogIndex:     9,
		AnchoredAt:   time.Now().UTC().Add(-time.Minute),
		BundleSHA256: hex.EncodeToString(bundleSum[:]),
		BundlePath:   legacyBundlePath,
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("Marshal legacy marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyStateMarker), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile legacy marker: %v", err)
	}
	lower := StateMarker{
		SessionID:    legacy.SessionID,
		FinalSeq:     4,
		RootHash:     strings.Repeat("c", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("d", 64),
		BundlePath:   "lower-bundle.json",
		ReceiptCount: 50,
		SignerKey:    strings.Repeat("e", 64),
	}
	if err := WriteStateMarker(dir, lower); err != nil {
		t.Fatalf("WriteStateMarker lower: %v", err)
	}

	latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
	if err != nil || !found {
		t.Fatalf("LoadStateMarkerFile latest = (%+v, %v, %v)", latest, found, err)
	}
	if latest.RootHash != legacy.RootHash || latest.ReceiptCount != legacyCheckpoint.ReceiptCount ||
		latest.SignerKey != legacyCheckpoint.SignerKeys[len(legacyCheckpoint.SignerKeys)-1] {
		t.Fatalf("latest pointer = %+v, want hydrated legacy coverage %d", latest, legacyCheckpoint.ReceiptCount)
	}
	indexed, found, err := LoadIndexedStateMarker(dir, latest)
	if err != nil || !found || !StateMarkersEqual(indexed, latest) {
		t.Fatalf("hydrated legacy index = (%+v, %v, %v), want exact pointer match", indexed, found, err)
	}
}

func TestWriteStateMarkerUsesNewLegacyBundleCoverageForPointerOrdering(t *testing.T) {
	dir := t.TempDir()
	lower := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     4,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC().Add(-time.Minute),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "lower-bundle.json",
		ReceiptCount: 50,
		SignerKey:    strings.Repeat("c", 64),
	}
	if err := WriteStateMarker(dir, lower); err != nil {
		t.Fatalf("WriteStateMarker lower: %v", err)
	}

	higherCheckpoint := Checkpoint{
		SessionID:    lower.SessionID,
		FinalSeq:     2,
		RootHash:     strings.Repeat("d", 64),
		ReceiptCount: 100,
		SignerKeys:   []string{strings.Repeat("e", 64)},
	}
	higherBundlePath := "higher-legacy-bundle.json"
	bundleData, err := WriteBundleUnderDir(dir, higherBundlePath, NewBundle(higherCheckpoint, Proof{
		Backend:  LocalBackend,
		LogIndex: 9,
	}))
	if err != nil {
		t.Fatalf("WriteBundleUnderDir higher: %v", err)
	}
	bundleSum := sha256.Sum256(bundleData)
	higher := StateMarker{
		SessionID:    higherCheckpoint.SessionID,
		FinalSeq:     higherCheckpoint.FinalSeq,
		RootHash:     higherCheckpoint.RootHash,
		Backend:      LocalBackend,
		LogIndex:     9,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: hex.EncodeToString(bundleSum[:]),
		BundlePath:   higherBundlePath,
	}
	if err := WriteStateMarker(dir, higher); err != nil {
		t.Fatalf("WriteStateMarker higher legacy marker: %v", err)
	}

	latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
	if err != nil || !found {
		t.Fatalf("LoadStateMarkerFile latest = (%+v, %v, %v)", latest, found, err)
	}
	if latest.RootHash != higher.RootHash {
		t.Fatalf("latest pointer root = %q, want higher legacy marker root %q", latest.RootHash, higher.RootHash)
	}
}

func TestWriteStateMarkerDoesNotPreserveUnbackedEnrichedPointer(t *testing.T) {
	dir := t.TempDir()
	poisoned := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC().Add(-time.Minute),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "missing-poisoned-bundle.json",
		ReceiptCount: 999,
		SignerKey:    strings.Repeat("c", 64),
	}
	if err := WriteStateMarker(dir, poisoned); err != nil {
		t.Fatalf("WriteStateMarker poisoned pointer: %v", err)
	}
	lower := StateMarker{
		SessionID:    poisoned.SessionID,
		FinalSeq:     10,
		RootHash:     strings.Repeat("d", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("e", 64),
		BundlePath:   "lower-but-backed-by-legacy-coverage.json",
	}
	if err := WriteStateMarker(dir, lower); err != nil {
		t.Fatalf("WriteStateMarker lower: %v", err)
	}

	latest, found, err := LoadStateMarkerFile(filepath.Join(dir, legacyStateMarker))
	if err != nil || !found {
		t.Fatalf("LoadStateMarkerFile latest = (%+v, %v, %v)", latest, found, err)
	}
	if latest.RootHash != lower.RootHash {
		t.Fatalf("latest pointer root = %q, want unverified enriched marker replaced by %q", latest.RootHash, lower.RootHash)
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
	if err == nil || !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("WriteStateMarker err = %v, want non-directory failure", err)
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
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("WriteStateMarker err = %v, want non-regular identity rejection", err)
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

func TestWriteStateMarkerRejectsInvalidOptionalCheckpointFields(t *testing.T) {
	valid := StateMarker{
		SessionID:    "session-a",
		FinalSeq:     1,
		RootHash:     strings.Repeat("a", 64),
		Backend:      LocalBackend,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: strings.Repeat("b", 64),
		BundlePath:   "bundle.json",
		ReceiptCount: 2,
		SignerKey:    strings.Repeat("c", 64),
	}
	tests := []struct {
		name   string
		mutate func(StateMarker) StateMarker
		want   string
	}{
		{
			name: "receipt count only",
			mutate: func(marker StateMarker) StateMarker {
				marker.SignerKey = ""
				return marker
			},
			want: "must both be present or absent",
		},
		{
			name: "signer key only",
			mutate: func(marker StateMarker) StateMarker {
				marker.ReceiptCount = 0
				return marker
			},
			want: "must both be present or absent",
		},
		{
			name: "invalid signer key",
			mutate: func(marker StateMarker) StateMarker {
				marker.SignerKey = "not-a-key"
				return marker
			},
			want: "signer_key is invalid",
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

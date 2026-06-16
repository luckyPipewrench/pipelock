//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// newOfflineStoreDir builds a policy-bundle store directory laid out the way
// `conductor serve` lays it out (<dir>/bundles, <dir>/stream-heads) and returns
// the policy-bundles dir to pass to the offline functions.
func newOfflineStoreDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	pb := filepath.Join(root, "policy-bundles")
	for _, sub := range []string{bundlesDirName, streamHeadsDirName} {
		if err := os.MkdirAll(filepath.Join(pb, sub), bundleStoreDirMode); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	return pb
}

// seedGraftStore writes a valid v1->v2->v3->v6 stream plus a DISCONNECTED graft
// record (its own root, version 5, shares no ancestor with the head) and a
// rollback marker. The graft is a genuine fatal orphan that bricks startup and
// that the offline repair is allowed to remove. Returns the graft hash + a
// reachable head hash for assertions.
func seedGraftStore(t *testing.T, pb string, signer testSigner) (graftHash, headHash string) {
	t.Helper()
	recs := buildForkRecords(t, signer)
	bundlesDir := filepath.Join(pb, bundlesDirName)
	headsDir := filepath.Join(pb, streamHeadsDirName)
	for _, v := range []uint64{1, 2, 3, 6} {
		writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
	}
	graft := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-offline-graft",
		version:      5,
		previousHash: "",
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - offline-graft.example.com\n",
	})
	graftHash = writeForkRecord(t, bundlesDir, graft, testNow.Add(5*time.Minute))
	writeForkRollbackMarker(t, headsDir, PublishedBundle{
		Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
	}, testNow.Add(time.Hour))
	return graftHash, recs[6].hash
}

func TestInspectOfflineStoreFindsGraftOrphan(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	graftHash, headHash := seedGraftStore(t, pb, signer)

	report, err := InspectOfflineStore(pb)
	if err != nil {
		t.Fatalf("InspectOfflineStore() error = %v", err)
	}
	if len(report.Streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(report.Streams))
	}
	if report.Streams[0].HeadBundleHash != headHash {
		t.Fatalf("head hash = %s, want %s", report.Streams[0].HeadBundleHash, headHash)
	}
	if len(report.Orphans) != 1 || report.Orphans[0].BundleHash != graftHash {
		t.Fatalf("orphans = %+v, want exactly the graft %s", report.Orphans, graftHash)
	}
	// Inspect is read-only: the graft file must still be present.
	if _, err := os.Stat(filepath.Join(pb, bundlesDirName, graftHash+".json")); err != nil {
		t.Fatalf("inspect removed a file (not read-only): %v", err)
	}
}

func TestInspectOfflineStoreCleanStoreHasNoOrphans(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	recs := buildForkRecords(t, signer)
	bundlesDir := filepath.Join(pb, bundlesDirName)
	headsDir := filepath.Join(pb, streamHeadsDirName)
	// The abandoned-fork incident shape: tolerated, not orphaned.
	for _, v := range []uint64{1, 2, 3, 4, 5, 6} {
		writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
	}
	writeForkRollbackMarker(t, headsDir, PublishedBundle{
		Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
	}, testNow.Add(time.Hour))

	report, err := InspectOfflineStore(pb)
	if err != nil {
		t.Fatalf("InspectOfflineStore() error = %v", err)
	}
	if len(report.Orphans) != 0 {
		t.Fatalf("orphans = %+v, want none (abandoned fork siblings are tolerated history)", report.Orphans)
	}
}

func TestInspectOfflineStoreAppliesActiveRollbackMarkerToHead(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	recs := buildForkRecords(t, signer)
	bundlesDir := filepath.Join(pb, bundlesDirName)
	headsDir := filepath.Join(pb, streamHeadsDirName)
	for _, v := range []uint64{1, 2, 3, 4} {
		writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
	}
	writeForkRollbackMarker(t, headsDir, PublishedBundle{
		Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
	}, testNow.Add(time.Hour))

	report, err := InspectOfflineStore(pb)
	if err != nil {
		t.Fatalf("InspectOfflineStore() error = %v", err)
	}
	if len(report.Streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(report.Streams))
	}
	stream := report.Streams[0]
	if stream.HeadBundleHash != recs[3].hash || stream.HeadVersion != 3 {
		t.Fatalf("offline head version=%d hash=%s, want rollback target v3 %s",
			stream.HeadVersion, stream.HeadBundleHash, recs[3].hash)
	}
	if stream.MaxVersion != 4 {
		t.Fatalf("max version = %d, want 4", stream.MaxVersion)
	}
	if len(report.Orphans) != 0 {
		t.Fatalf("orphans = %+v, want none (superseded v4 is rollback-covered)", report.Orphans)
	}
}

func TestRepairOfflineStoreDryRunChangesNothing(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	graftHash, _ := seedGraftStore(t, pb, signer)

	result, err := RepairOfflineStore(pb, "", false, testNow)
	if err != nil {
		t.Fatalf("RepairOfflineStore(dry run) error = %v", err)
	}
	if !result.DryRun {
		t.Fatal("RepairOfflineStore(confirm=false) DryRun=false, want true")
	}
	if len(result.Removed) != 1 || result.Removed[0].BundleHash != graftHash {
		t.Fatalf("dry run removed = %+v, want the graft listed (not deleted)", result.Removed)
	}
	if _, err := os.Stat(filepath.Join(pb, bundlesDirName, graftHash+".json")); err != nil {
		t.Fatalf("dry run deleted the file: %v", err)
	}
}

func TestRepairOfflineStoreConfirmRemovesOnlyOrphanAndBacksUp(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	graftHash, headHash := seedGraftStore(t, pb, signer)
	bundlesDir := filepath.Join(pb, bundlesDirName)

	// Snapshot reachable records before repair; none may be removed.
	before, err := os.ReadDir(bundlesDir)
	if err != nil {
		t.Fatalf("ReadDir(before) error = %v", err)
	}
	if len(before) == 0 {
		t.Fatal("no bundle records seeded")
	}

	result, err := RepairOfflineStore(pb, "", true, testNow)
	if err != nil {
		t.Fatalf("RepairOfflineStore(confirm) error = %v", err)
	}
	if result.DryRun {
		t.Fatal("RepairOfflineStore(confirm=true) DryRun=true, want false")
	}
	if len(result.Removed) != 1 || result.Removed[0].BundleHash != graftHash {
		t.Fatalf("removed = %+v, want exactly the graft %s", result.Removed, graftHash)
	}

	// The graft file is gone.
	if _, err := os.Stat(filepath.Join(bundlesDir, graftHash+".json")); !os.IsNotExist(err) {
		t.Fatalf("graft record still present after repair: err=%v", err)
	}
	// The head record (reachable) is untouched.
	if _, err := os.Stat(filepath.Join(bundlesDir, headHash+".json")); err != nil {
		t.Fatalf("repair removed a reachable record: %v", err)
	}
	// A backup of the removed record exists and parses back to the same hash.
	backupPath := filepath.Join(result.BackupDir, graftHash+".json")
	backup, err := readBundleRecord(backupPath)
	if err != nil {
		t.Fatalf("read backup %s: %v", backupPath, err)
	}
	if backup.BundleHash != graftHash {
		t.Fatalf("backup hash = %s, want %s", backup.BundleHash, graftHash)
	}
	// stream-heads/ is untouched: the rollback marker survives.
	headFiles, err := os.ReadDir(filepath.Join(pb, streamHeadsDirName))
	if err != nil {
		t.Fatalf("ReadDir(stream-heads) error = %v", err)
	}
	if len(headFiles) != 1 {
		t.Fatalf("stream-head markers = %d, want 1 (repair must not touch markers)", len(headFiles))
	}

	// The proof: after repair the store opens cleanly through the real load path.
	store, err := OpenFileBundleStore(pb)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(after repair) error = %v, want clean load", err)
	}
	if h := store.streams[result.Removed[0].StreamKey]; h.Bundle.Version != 6 {
		t.Fatalf("post-repair head version = %d, want 6", h.Bundle.Version)
	}
}

func TestRepairOfflineStoreLeavesAuditStoreUntouched(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	graftHash, _ := seedGraftStore(t, pb, signer)

	// Simulate the sibling audit store that lives under <storage-dir>, NOT under
	// policy-bundles. Offline repair must never reach outside policy-bundles.
	storageRoot := filepath.Dir(pb)
	auditPath := filepath.Join(storageRoot, "audit.db")
	if err := os.WriteFile(auditPath, []byte("audit-data"), bundleRecordFileMode); err != nil {
		t.Fatalf("write fake audit.db: %v", err)
	}

	if _, err := RepairOfflineStore(pb, "", true, testNow); err != nil {
		t.Fatalf("RepairOfflineStore() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil || string(data) != "audit-data" {
		t.Fatalf("audit.db changed or removed: data=%q err=%v", string(data), err)
	}
	_ = graftHash
}

func TestRepairOfflineStoreCustomBackupDir(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	graftHash, _ := seedGraftStore(t, pb, signer)
	backupDir := filepath.Join(t.TempDir(), "custom-backup")

	result, err := RepairOfflineStore(pb, backupDir, true, testNow)
	if err != nil {
		t.Fatalf("RepairOfflineStore(custom backup) error = %v", err)
	}
	if result.BackupDir != filepath.Clean(backupDir) {
		t.Fatalf("backup dir = %s, want %s", result.BackupDir, backupDir)
	}
	if _, err := os.Stat(filepath.Join(backupDir, graftHash+".json")); err != nil {
		t.Fatalf("backup not written to custom dir: %v", err)
	}
}

func TestRepairOfflineStoreDoesNotRemoveManualReviewSibling(t *testing.T) {
	// A sibling whose own ancestry chain is corrupt (points at a missing parent)
	// is flagged for manual review and must NOT be auto-removed by repair.
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	recs := buildForkRecords(t, signer)
	bundlesDir := filepath.Join(pb, bundlesDirName)
	headsDir := filepath.Join(pb, streamHeadsDirName)
	for _, v := range []uint64{1, 2, 3, 6} {
		writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
	}
	// Sibling v5 chaining from a v4 hash that is never written -> corrupt chain.
	badSibling := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-offline-badsibling",
		version:      5,
		previousHash: recs[4].hash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - badsibling.example.com\n",
	})
	badHash := writeForkRecord(t, bundlesDir, badSibling, testNow.Add(5*time.Minute))
	writeForkRollbackMarker(t, headsDir, PublishedBundle{
		Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
	}, testNow.Add(time.Hour))

	report, err := InspectOfflineStore(pb)
	if err != nil {
		t.Fatalf("InspectOfflineStore() error = %v", err)
	}
	if len(report.Orphans) != 1 || report.Orphans[0].BundleHash != badHash {
		t.Fatalf("orphans = %+v, want the bad sibling flagged", report.Orphans)
	}

	result, err := RepairOfflineStore(pb, "", true, testNow)
	if err != nil {
		t.Fatalf("RepairOfflineStore() error = %v", err)
	}
	if len(result.Removed) != 0 {
		t.Fatalf("repair removed %+v, want none (manual-review sibling must be preserved)", result.Removed)
	}
	if _, err := os.Stat(filepath.Join(bundlesDir, badHash+".json")); err != nil {
		t.Fatalf("repair removed the manual-review sibling: %v", err)
	}
}

func TestRepairOfflineStoreDoesNotRemoveDuplicateIDVersion(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	bundlesDir := filepath.Join(pb, bundlesDirName)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:         "bundle-offline-dup-v1",
		version:    1,
		audience:   audience,
		configYAML: "mode: strict\napi_allowlist:\n  - dup-v1.example.com\n",
	})
	v1Hash := writeForkRecord(t, bundlesDir, v1, testNow)
	v2a := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-offline-dup-v2",
		version:      2,
		previousHash: v1Hash,
		audience:     audience,
		configYAML:   "mode: strict\napi_allowlist:\n  - dup-v2a.example.com\n",
	})
	v2b := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-offline-dup-v2",
		version:      2,
		previousHash: v1Hash,
		audience:     audience,
		configYAML:   "mode: strict\napi_allowlist:\n  - dup-v2b.example.com\n",
	})
	v2aHash := writeForkRecord(t, bundlesDir, v2a, testNow.Add(time.Minute))
	v2bHash := writeForkRecord(t, bundlesDir, v2b, testNow.Add(2*time.Minute))

	report, err := InspectOfflineStore(pb)
	if err != nil {
		t.Fatalf("InspectOfflineStore() error = %v", err)
	}
	if len(report.UnreadableRecords) != 1 {
		t.Fatalf("unreadable records = %+v, want one duplicate bundle_id/version record", report.UnreadableRecords)
	}
	if len(report.Orphans) != 0 {
		t.Fatalf("orphans = %+v, want none for ambiguous duplicate bundle_id/version corruption", report.Orphans)
	}

	result, err := RepairOfflineStore(pb, "", true, testNow)
	if err != nil {
		t.Fatalf("RepairOfflineStore() error = %v", err)
	}
	if len(result.Removed) != 0 {
		t.Fatalf("repair removed %+v, want none for duplicate bundle_id/version", result.Removed)
	}
	for _, hash := range []string{v2aHash, v2bHash} {
		if _, err := os.Stat(filepath.Join(bundlesDir, hash+".json")); err != nil {
			t.Fatalf("repair removed duplicate record %s: %v", hash, err)
		}
	}
}

func TestInspectOfflineStoreReportsUnreadableRecord(t *testing.T) {
	pb := newOfflineStoreDir(t)
	signer := newTestSigner(t)
	recs := buildForkRecords(t, signer)
	bundlesDir := filepath.Join(pb, bundlesDirName)
	for _, v := range []uint64{1, 2, 3} {
		writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
	}
	// A garbage .json file that fails to parse.
	if err := os.WriteFile(filepath.Join(bundlesDir, "garbage.json"), []byte("{not json"), bundleRecordFileMode); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	report, err := InspectOfflineStore(pb)
	if err != nil {
		t.Fatalf("InspectOfflineStore() error = %v", err)
	}
	if len(report.UnreadableRecords) != 1 || report.UnreadableRecords[0].FileName != "garbage.json" {
		t.Fatalf("unreadable = %+v, want garbage.json reported", report.UnreadableRecords)
	}
	// A garbage file is reported, not classified as a removable orphan, and repair
	// must not delete it.
	result, err := RepairOfflineStore(pb, "", true, testNow)
	if err != nil {
		t.Fatalf("RepairOfflineStore() error = %v", err)
	}
	if len(result.Removed) != 0 {
		t.Fatalf("repair removed %+v, want none (garbage file is not a classified orphan)", result.Removed)
	}
	if _, err := os.Stat(filepath.Join(bundlesDir, "garbage.json")); err != nil {
		t.Fatalf("repair removed the garbage file: %v", err)
	}
}

func TestInspectOfflineStoreRejectsMissingDir(t *testing.T) {
	if _, err := InspectOfflineStore(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("InspectOfflineStore(missing dir) error = nil, want error")
	}
}

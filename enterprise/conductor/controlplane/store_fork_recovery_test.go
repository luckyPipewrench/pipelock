//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// writeForkRecord writes a signed bundle directly to the store's bundles dir,
// bypassing the forward-publish authorization gate. This is the only way to
// recreate the abandoned-fork on-disk topology that repeated rollback+publish
// cycles leave behind (multiple siblings chaining from a shared ancestor below
// the live head). It returns the bundle hash.
func writeForkRecord(t *testing.T, dir string, bundle conductor.PolicyBundle, at time.Time) string {
	t.Helper()
	hash, err := bundle.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	sk, err := streamKey(bundle)
	if err != nil {
		t.Fatalf("streamKey() error = %v", err)
	}
	if err := writeBundleRecord(dir, PublishedBundle{
		Bundle:      bundle,
		BundleHash:  hash,
		StreamKey:   sk,
		PublishedAt: at,
	}); err != nil {
		t.Fatalf("writeBundleRecord() error = %v", err)
	}
	return hash
}

// forkMarkerSupersededVersion is the superseded version every fork-recovery
// scenario uses: the rollback target is v3 and the marker records that v4 was the
// head when the rollback was applied, so the marker covers v3+v4 only and leaves
// the abandoned v5 sibling uncovered (the exact incident shape).
const forkMarkerSupersededVersion = 4

// writeForkRollbackMarker writes a durable rollback marker for the stream that
// target describes, mirroring what ApplyRollbackHead persists. The superseded
// version is fixed at forkMarkerSupersededVersion across all fork-recovery
// scenarios (see the const doc).
func writeForkRollbackMarker(t *testing.T, dir string, target PublishedBundle, at time.Time) {
	t.Helper()
	marker := streamHeadRecord{
		Version:           streamHeadRecordVersion,
		StreamKey:         target.StreamKey,
		TargetBundleID:    target.Bundle.BundleID,
		TargetVersion:     target.Bundle.Version,
		TargetBundleHash:  target.BundleHash,
		SupersededVersion: forkMarkerSupersededVersion,
		AppliedAt:         at,
	}
	if err := writeStreamHeadRecord(dir, marker); err != nil {
		t.Fatalf("writeStreamHeadRecord() error = %v", err)
	}
}

// forkChain builds a linear v1->v2->v3 chain plus the fork siblings v4/v5/v6 all
// chaining from v3, returning the records keyed by version. It does NOT write
// them; callers choose what lands on disk to drive each scenario.
type forkRecord struct {
	bundle conductor.PolicyBundle
	hash   string
	stream string
}

func buildForkRecords(t *testing.T, signer testSigner) map[uint64]forkRecord {
	t.Helper()
	aud := conductor.Audience{InstanceIDs: []string{"*"}}
	records := map[uint64]forkRecord{}
	mk := func(version uint64, prev string, yaml string) forkRecord {
		b := signedControlBundle(t, signer, bundleSpec{
			id:           "bundle-fork-v" + itoa(version),
			version:      version,
			previousHash: prev,
			audience:     aud,
			configYAML:   yaml,
		})
		h, err := b.CanonicalHash()
		if err != nil {
			t.Fatalf("CanonicalHash(v%d) error = %v", version, err)
		}
		sk, err := streamKey(b)
		if err != nil {
			t.Fatalf("streamKey(v%d) error = %v", version, err)
		}
		return forkRecord{bundle: b, hash: h, stream: sk}
	}
	v1 := mk(1, "", "mode: strict\napi_allowlist:\n  - v1.example.com\n")
	v2 := mk(2, v1.hash, "mode: strict\napi_allowlist:\n  - v2.example.com\n")
	v3 := mk(3, v2.hash, "mode: strict\napi_allowlist:\n  - v3.example.com\n")
	records[1] = v1
	records[2] = v2
	records[3] = v3
	// v4, v5, v6 all chain from v3 (the rollback point), the abandoned-fork shape.
	records[4] = mk(4, v3.hash, "mode: strict\napi_allowlist:\n  - v4.example.com\n")
	records[5] = mk(5, v3.hash, "mode: strict\napi_allowlist:\n  - v5.example.com\n")
	records[6] = mk(6, v3.hash, "mode: strict\napi_allowlist:\n  - v6.example.com\n")
	return records
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// TestFileBundleStoreToleratesAbandonedForkSiblingOnLoad is the regression for the
// exact prod incident: a stream with v1->v2->v3, then v4/v5/v6 all chaining from
// v3, the effective head at v6, and a durable rollback marker recording only
// superseded_version=4. Before the fix, v5 (off the v6 chain and uncovered by the
// superseded=4 marker) was a fatal uncovered orphan that bricked startup. After
// the fix the store loads, selects v6 as head, and survives a reopen.
func TestFileBundleStoreToleratesAbandonedForkSiblingOnLoad(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	recs := buildForkRecords(t, signer)

	for _, v := range []uint64{1, 2, 3, 4, 5, 6} {
		writeForkRecord(t, store.bundlesDir, recs[v].bundle, testNow)
	}
	// Durable rollback marker: target v3, superseded version 4 (covers v3, v4 only).
	writeForkRollbackMarker(t, store.streamHeadsDir, PublishedBundle{
		Bundle:     recs[3].bundle,
		BundleHash: recs[3].hash,
		StreamKey:  recs[3].stream,
	}, testNow.Add(time.Hour))

	reopened, err := OpenFileBundleStore(store.dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(abandoned fork) error = %v, want nil (tolerated historical sibling)", err)
	}
	head, ok := reopened.streams[recs[6].stream]
	if !ok {
		t.Fatal("reopened store has no head for the fork stream")
	}
	if head.Bundle.Version != 6 || head.BundleHash != recs[6].hash {
		t.Fatalf("reopened head version=%d hash=%s, want v6 %s", head.Bundle.Version, head.BundleHash, recs[6].hash)
	}

	// Restart survival: reopen the just-loaded store directory a second time.
	again, err := OpenFileBundleStore(reopened.dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(reopen again) error = %v, want nil", err)
	}
	if h := again.streams[recs[6].stream]; h.Bundle.Version != 6 {
		t.Fatalf("second reopen head version=%d, want 6", h.Bundle.Version)
	}
}

// TestFileBundleStoreForkSiblingGenuineCorruptionStaysFatal proves the toleration
// predicate does NOT weaken genuine-corruption detection. Each case constructs a
// stream with a rollback marker (so the toleration path is reachable) plus a record
// that must still be rejected.
func TestFileBundleStoreForkSiblingGenuineCorruptionStaysFatal(t *testing.T) {
	signer := newTestSigner(t)

	tests := []struct {
		name string
		// build writes records + marker to the given dirs and returns nothing; the
		// test asserts the subsequent OpenFileBundleStore fails with ErrInvalidStoreRecord.
		build func(t *testing.T, bundlesDir, headsDir string, recs map[uint64]forkRecord)
	}{
		{
			name: "missing previous_bundle_hash in sibling chain",
			build: func(t *testing.T, bundlesDir, headsDir string, recs map[uint64]forkRecord) {
				// Head chain v1->v2->v3->v6 present, but v5 chains from a v4 that is
				// NOT written. v5's previous_bundle_hash points at the missing v4.
				v5FromV4 := signedControlBundle(t, signer, bundleSpec{
					id:           "bundle-fork-v5-missingprev",
					version:      5,
					previousHash: recs[4].hash, // v4 deliberately not written
					audience:     conductor.Audience{InstanceIDs: []string{"*"}},
					configYAML:   "mode: strict\napi_allowlist:\n  - v5mp.example.com\n",
				})
				for _, v := range []uint64{1, 2, 3, 6} {
					writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
				}
				writeForkRecord(t, bundlesDir, v5FromV4, testNow.Add(5*time.Minute))
				writeForkRollbackMarker(t, headsDir, PublishedBundle{
					Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
				}, testNow.Add(time.Hour))
			},
		},
		{
			name: "sibling ancestor belongs to different stream",
			build: func(t *testing.T, bundlesDir, headsDir string, recs map[uint64]forkRecord) {
				// A sibling whose previous_bundle_hash points at a record in a DIFFERENT
				// stream (different audience -> different stream key).
				crossParent := signedControlBundle(t, signer, bundleSpec{
					id:         "bundle-fork-crossparent",
					version:    2,
					audience:   conductor.Audience{Labels: map[string]string{"ring": "canary"}},
					configYAML: "mode: strict\napi_allowlist:\n  - cross.example.com\n",
				})
				crossHash := writeForkRecord(t, bundlesDir, crossParent, testNow)
				sibling := signedControlBundle(t, signer, bundleSpec{
					id:           "bundle-fork-v5-crossstream",
					version:      5,
					previousHash: crossHash,
					audience:     conductor.Audience{InstanceIDs: []string{"*"}},
					configYAML:   "mode: strict\napi_allowlist:\n  - v5cs.example.com\n",
				})
				for _, v := range []uint64{1, 2, 3, 6} {
					writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
				}
				writeForkRecord(t, bundlesDir, sibling, testNow.Add(5*time.Minute))
				writeForkRollbackMarker(t, headsDir, PublishedBundle{
					Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
				}, testNow.Add(time.Hour))
			},
		},
		{
			name: "sibling version does not strictly decrease toward ancestor",
			build: func(t *testing.T, bundlesDir, headsDir string, recs map[uint64]forkRecord) {
				// A sibling at version 5 whose previous_bundle_hash points at v6
				// (version 6): the chain does not decrease, which is corruption.
				badOrder := signedControlBundle(t, signer, bundleSpec{
					id:           "bundle-fork-v5-badorder",
					version:      5,
					previousHash: recs[6].hash, // ancestor version (6) >= record version (5)
					audience:     conductor.Audience{InstanceIDs: []string{"*"}},
					configYAML:   "mode: strict\napi_allowlist:\n  - v5bo.example.com\n",
				})
				for _, v := range []uint64{1, 2, 3, 6} {
					writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
				}
				writeForkRecord(t, bundlesDir, badOrder, testNow.Add(5*time.Minute))
				writeForkRollbackMarker(t, headsDir, PublishedBundle{
					Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
				}, testNow.Add(time.Hour))
			},
		},
		{
			name: "disconnected graft sibling shares no ancestor with head",
			build: func(t *testing.T, bundlesDir, headsDir string, recs map[uint64]forkRecord) {
				// A sibling whose chain roots at its own previous_bundle_hash="" record
				// that is NOT on the head chain: a parallel root in the same stream.
				graftRoot := signedControlBundle(t, signer, bundleSpec{
					id:         "bundle-fork-graft-root",
					version:    1,
					audience:   conductor.Audience{InstanceIDs: []string{"*"}},
					configYAML: "mode: strict\napi_allowlist:\n  - graftroot.example.com\n",
				})
				// Same stream (same audience) but a separate root: this collides on
				// bundle_id/version uniqueness? No -- different id and version 1 already
				// taken by recs[1]. Use version 5 with empty prev so it is its own root.
				graft := signedControlBundle(t, signer, bundleSpec{
					id:           "bundle-fork-graft",
					version:      5,
					previousHash: "",
					audience:     conductor.Audience{InstanceIDs: []string{"*"}},
					configYAML:   "mode: strict\napi_allowlist:\n  - graft.example.com\n",
				})
				_ = graftRoot
				for _, v := range []uint64{1, 2, 3, 6} {
					writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
				}
				writeForkRecord(t, bundlesDir, graft, testNow.Add(5*time.Minute))
				writeForkRollbackMarker(t, headsDir, PublishedBundle{
					Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
				}, testNow.Add(time.Hour))
			},
		},
		{
			name: "off-chain sibling with no rollback marker on stream",
			build: func(t *testing.T, bundlesDir, headsDir string, recs map[uint64]forkRecord) {
				// v5 forks legitimately from v3, but NO rollback marker exists. Without
				// the marker the sibling cannot be a byproduct of authorized rollback, so
				// it must remain fatal (a graft on a stream that never rolled back).
				for _, v := range []uint64{1, 2, 3, 5, 6} {
					writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
				}
				// No marker written.
			},
		},
		{
			name: "off-chain sibling at or above head version",
			build: func(t *testing.T, bundlesDir, headsDir string, recs map[uint64]forkRecord) {
				// Two version-6 records both chaining from v3: one becomes head, the
				// other is an off-chain sibling AT the head version -- a real two-heads
				// conflict, not historical supersession. Marker present.
				sixB := signedControlBundle(t, signer, bundleSpec{
					id:           "bundle-fork-v6b",
					version:      6,
					previousHash: recs[3].hash,
					audience:     conductor.Audience{InstanceIDs: []string{"*"}},
					configYAML:   "mode: strict\napi_allowlist:\n  - v6b.example.com\n",
				})
				for _, v := range []uint64{1, 2, 3, 6} {
					writeForkRecord(t, bundlesDir, recs[v].bundle, testNow)
				}
				writeForkRecord(t, bundlesDir, sixB, testNow.Add(7*time.Minute))
				writeForkRollbackMarker(t, headsDir, PublishedBundle{
					Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
				}, testNow.Add(time.Hour))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := OpenFileBundleStore(t.TempDir())
			if err != nil {
				t.Fatalf("OpenFileBundleStore() error = %v", err)
			}
			recs := buildForkRecords(t, signer)
			tc.build(t, store.bundlesDir, store.streamHeadsDir, recs)
			if _, err := OpenFileBundleStore(store.dir); !errors.Is(err, ErrInvalidStoreRecord) {
				t.Fatalf("OpenFileBundleStore(%s) error = %v, want ErrInvalidStoreRecord", tc.name, err)
			}
		})
	}
}

// TestFileBundleStoreForkSiblingDoesNotMaskMissingHeadAncestor proves the head
// chain is still validated independently: a broken head chain is fatal regardless
// of the fork-sibling toleration path.
func TestFileBundleStoreForkSiblingDoesNotMaskBrokenHead(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	recs := buildForkRecords(t, signer)
	// Write v6 (head, chains from v3) and v3/v2 but OMIT v1: v3's chain references a
	// missing v2->v1? No -- omit v2 so v3's previous_bundle_hash (v2) is missing.
	for _, v := range []uint64{3, 6} {
		writeForkRecord(t, store.bundlesDir, recs[v].bundle, testNow)
	}
	writeForkRollbackMarker(t, store.streamHeadsDir, PublishedBundle{
		Bundle: recs[3].bundle, BundleHash: recs[3].hash, StreamKey: recs[3].stream,
	}, testNow.Add(time.Hour))
	if _, err := OpenFileBundleStore(store.dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(broken head chain) error = %v, want ErrInvalidStoreRecord", err)
	}
}

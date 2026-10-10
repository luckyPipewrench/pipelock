// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// Keep the old materialized extractor and BuildCheckpoint as the compatibility
// oracle. The production implementation must not call either of them.
func materializedAutoAnchorTestWalk(dir, sessionID string, consume func(receipt.Receipt) error) error {
	receipts, err := receipt.ExtractReceiptsFromSessionDir(dir, sessionID)
	if err != nil {
		return err
	}
	return walkAutoAnchorTestReceipts(receipts)(dir, sessionID, consume)
}

func TestAutoAnchorStreamingCheckpointBytes(t *testing.T) {
	for _, size := range []int{1, 17, 205} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			rig := newAutoAnchorTestRig(t)
			for range size {
				emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/action")
			}
			assertStreamingCheckpointOracle(t, rig.monitor, rig.emitter.SignerKeyHex(), 1)
		})
	}
	t.Run("rotation", func(t *testing.T) {
		rec, emitter, _, cfg, m, logs, receipts := newRotatedAutoAnchorChain(t)
		monitor := newAutoAnchorMonitor(rec, m, func() *receipt.Emitter { return emitter }, func() *config.Config { return cfg }, logs)
		var boundary uint64
		for _, r := range receipts {
			if r.ActionRecord.KeyTransition != nil {
				break
			}
			boundary++
		}
		if boundary == uint64(len(receipts)) {
			t.Fatal("rotation boundary is missing")
		}
		for _, prefix := range []uint64{1, boundary, uint64(len(receipts))} {
			assertStreamingCheckpointOracle(t, monitor, emitter.SignerKeyHex(), prefix)
		}
	})
}

func assertStreamingCheckpointOracle(t *testing.T, monitor *autoAnchorMonitor, headKey string, prefixCount uint64) {
	t.Helper()
	receipts, err := receipt.ExtractReceiptsFromSessionDir(monitor.recorder.Dir(), monitor.sessionID)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := autoAnchorTrustedKeys(receipts, headKey)
	if err != nil {
		t.Fatal(err)
	}
	want, err := anchorpkg.BuildCheckpoint(monitor.sessionID, receipts, keys)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix, err := anchorpkg.BuildCheckpoint(monitor.sessionID, receipts[:prefixCount], keys)
	if err != nil {
		t.Fatal(err)
	}
	got, prefix, err := monitor.buildCheckpoint(headKey, prefixCount)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]anchorpkg.Checkpoint{{got, want}, {prefix, wantPrefix}} {
		gotBytes, err := json.Marshal(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		wantBytes, err := json.Marshal(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Fatalf("checkpoint bytes differ:\ngot  %s\nwant %s", gotBytes, wantBytes)
		}
	}
}

func TestAutoAnchorStreamingTamperedMiddle(t *testing.T) {
	rig := newAutoAnchorTestRig(t)
	for range 17 {
		emitAutoAnchorReceipt(t, rig.emitter, "https://api.vendor.example/action")
	}
	receipts, err := receipt.ExtractReceiptsFromSessionDir(rig.recorder.Dir(), rig.monitor.sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rig.monitor.buildCheckpoint(rig.emitter.SignerKeyHex(), 1); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	receipts[len(receipts)/2].ActionRecord.Target = "https://api.vendor.example/changed"
	rig.monitor.walkFn = walkAutoAnchorTestReceipts(receipts)
	backend := &countingAnchorBackend{}
	rig.monitor.backendFn = func(config.FlightRecorderAnchor) (anchorpkg.Backend, error) { return backend, nil }
	rig.monitor.runPass()
	if backend.submits.Load() != 0 {
		t.Fatal("tampered middle reached anchor backend")
	}
	assertAutoAnchorStats(t, rig.metrics, 1, 0, 1, "signature")
	// Seed rebuild must reject a corrupt suffix even when the prefix matches.
	if _, _, err := rig.monitor.buildCheckpoint(rig.emitter.SignerKeyHex(), 1); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("seed walk accepted corrupt suffix: %v", err)
	}
}

func TestAutoAnchorStreamingMemoryBound(t *testing.T) {
	// Do not parallelize: GC and heap accounting are process-wide. Measure live
	// heap after GC at fixed intervals, not TotalAlloc (streaming still allocates
	// transient parsing/signature buffers per receipt). Larger receipt payloads
	// keep the retained chain above 4 MiB without thousands of signatures. The
	// old extractor is a positive control for both the measurement and fixture.
	const size = 512
	const liveHeapLimit = uint64(4 << 20)
	rig := newAutoAnchorTestRig(t)
	target := "https://api.vendor.example/" + strings.Repeat("x", 16<<10)
	for range size {
		emitAutoAnchorReceipt(t, rig.emitter, target)
	}
	productionWalk := rig.monitor.walkFn
	measure := func(walk func(string, string, func(receipt.Receipt) error) error, prefix uint64) uint64 {
		runtime.GC()
		var base runtime.MemStats
		runtime.ReadMemStats(&base)
		var peak uint64
		count := 0
		rig.monitor.walkFn = func(dir, sessionID string, consume func(receipt.Receipt) error) error {
			return walk(dir, sessionID, func(r receipt.Receipt) error {
				count++
				if count%512 == 0 || count == size+1 {
					runtime.GC()
					var sample runtime.MemStats
					runtime.ReadMemStats(&sample)
					if sample.HeapAlloc > base.HeapAlloc {
						peak = max(peak, sample.HeapAlloc-base.HeapAlloc)
					}
				}
				return consume(r)
			})
		}
		checkpoint, _, err := rig.monitor.buildCheckpoint(rig.emitter.SignerKeyHex(), prefix)
		if err != nil {
			t.Fatal(err)
		}
		if count != size+1 || checkpoint.ReceiptCount != size+1 {
			t.Fatalf("walked %d receipts, checkpoint count %d", count, checkpoint.ReceiptCount)
		}
		return peak
	}
	oldPeak := measure(materializedAutoAnchorTestWalk, 0)
	newPeak := measure(productionWalk, 0)
	seedPeak := measure(productionWalk, size/2)
	t.Logf("receipts=%d materialized_peak=%d streaming_peak=%d seed_peak=%d limit=%d bytes", size+1, oldPeak, newPeak, seedPeak, liveHeapLimit)
	if oldPeak <= liveHeapLimit {
		t.Fatal("measurement failed to detect materialized chain")
	}
	if newPeak > liveHeapLimit || seedPeak > liveHeapLimit {
		t.Fatalf("streaming live heap exceeds %d bytes: anchor=%d seed=%d", liveHeapLimit, newPeak, seedPeak)
	}
}

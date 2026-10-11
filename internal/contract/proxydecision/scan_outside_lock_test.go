// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxydecision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// gatedScanRecorder delegates to a real recorder and holds every content scan
// until released, counting how many are in progress at once.
type gatedScanRecorder struct {
	*recorder.Recorder
	inScan  atomic.Int32
	release chan struct{}
}

func (g *gatedScanRecorder) ScanReceiptContent(ctx context.Context, p *receiptcontent.Producer, detail []byte) (receiptcontent.Report, *recorder.ContentScan, error) {
	g.inScan.Add(1)
	<-g.release
	return g.Recorder.ScanReceiptContent(ctx, p, detail)
}

// The content scan runs outside the emitter lock: a slow scan must not hold
// every other decision behind it. Two decisions are both inside their scans
// before either is released; with the scan under the lock the second could
// never get there.
func TestEmitScansContentOutsideTheEmitterLock(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	gated := &gatedScanRecorder{Recorder: rec, release: make(chan struct{})}
	em, _, _ := newTestEmitter(t, gated, nil)

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- em.EmitDurable(validDecision())
		}()
	}
	released := false
	defer func() {
		if !released {
			close(gated.release)
		}
		wg.Wait()
	}()
	testwait.For(t, 10*time.Second, func() bool { return gated.inScan.Load() >= 2 },
		"second decision never reached its content scan; the scan runs under the emitter lock")
	close(gated.release)
	released = true
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	if seq := em.chainSeq; seq != 2 {
		t.Fatalf("chain advanced to %d, want 2", seq)
	}
}

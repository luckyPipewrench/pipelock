// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func newDeferredTestEmitter(t *testing.T, onReceipt func(*Receipt)) (*Emitter, *recorder.Recorder) {
	t.Helper()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	t.Cleanup(func() { _ = rec.Close() })
	e := NewEmitter(EmitterConfig{
		Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor, OnReceipt: onReceipt,
	})
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}
	return e, rec
}

// gateSync blocks every recorder sync until released. Cleanup releases it
// before the recorder closes, so a failing assertion fails instead of hanging
// in Close's drain.
func gateSync(t *testing.T, rec *recorder.Recorder, onEnter func()) func() {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	releaseFn := func() { once.Do(func() { close(release) }) }
	rec.SetSyncForTest(func(f *os.File) error {
		if onEnter != nil {
			onEnter()
		}
		<-release
		return f.Sync()
	})
	t.Cleanup(releaseFn)
	return releaseFn
}

func deferredTestOpts(target string) EmitOpts {
	return EmitOpts{ActionID: NewActionID(), Target: target, Verdict: config.ActionAllow, Transport: testTransport, Method: http.MethodGet}
}

func waitSignal(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

// A durable receipt's sync wait happens outside the chain lock: while one
// receipt's sync is blocked, another receipt can still be appended.
func TestEmitDurableConfirmsOutsideChainLock(t *testing.T) {
	e, rec := newDeferredTestEmitter(t, nil)
	entered := make(chan struct{})
	var once sync.Once
	releaseFn := gateSync(t, rec, func() { once.Do(func() { close(entered) }) })
	first := make(chan error, 1)
	go func() { first <- e.EmitDurable(deferredTestOpts("https://api.vendor.example/first")) }()
	waitSignal(t, entered, "first sync")

	second := make(chan error, 1)
	go func() { second <- e.EmitDurable(deferredTestOpts("https://api.vendor.example/second")) }()
	testwait.For(t, 10*time.Second, func() bool {
		snap, _ := e.HealthSnapshot()
		return snap.ChainSeq == 2
	}, "second receipt was not appended while the first sync was outstanding; the wait is under the chain lock")
	select {
	case err := <-first:
		t.Fatalf("first returned before its sync completed: %v", err)
	default:
	}
	releaseFn()
	for i, ch := range []chan error{first, second} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("emit %d: %v", i, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("emit %d did not complete", i)
		}
	}
}

// Observers see receipts in chain order and only after durability, even
// when later receipts confirm first.
func TestEmitDurableObserverOrderAndDurability(t *testing.T) {
	var mu sync.Mutex
	var seen []uint64
	e, rec := newDeferredTestEmitter(t, func(r *Receipt) {
		mu.Lock()
		seen = append(seen, r.ActionRecord.ChainSeq)
		mu.Unlock()
	})
	releaseFn := gateSync(t, rec, nil)

	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) { errs <- e.EmitDurable(deferredTestOpts(fmt.Sprintf("https://api.vendor.example/%d", i))) }(i)
	}
	testwait.For(t, 10*time.Second, func() bool {
		snap, _ := e.HealthSnapshot()
		return snap.ChainSeq == n
	}, "receipts were not appended concurrently")
	mu.Lock()
	early := len(seen)
	mu.Unlock()
	if early != 0 {
		t.Fatalf("observer saw %d receipts before any sync completed", early)
	}
	releaseFn()
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != n {
		t.Fatalf("observer saw %d receipts, want %d", len(seen), n)
	}
	for i, seq := range seen {
		if seq != uint64(i) {
			t.Fatalf("observer order = %v, want chain order", seen)
		}
	}
}

// A non-durable receipt appended behind a durable receipt that is still
// confirming is not reported, to the caller or the observer, ahead of it.
func TestEmitBehindUnconfirmedDurableKeepsChainOrder(t *testing.T) {
	var mu sync.Mutex
	var seen []uint64
	e, rec := newDeferredTestEmitter(t, func(r *Receipt) {
		mu.Lock()
		seen = append(seen, r.ActionRecord.ChainSeq)
		mu.Unlock()
	})
	entered := make(chan struct{})
	var once sync.Once
	releaseFn := gateSync(t, rec, func() { once.Do(func() { close(entered) }) })
	durable := make(chan error, 1)
	go func() { durable <- e.EmitDurable(deferredTestOpts("https://api.vendor.example/durable")) }()
	waitSignal(t, entered, "durable sync")

	plain := make(chan error, 1)
	go func() { plain <- e.Emit(deferredTestOpts("https://api.vendor.example/plain")) }()
	testwait.For(t, 10*time.Second, func() bool {
		snap, _ := e.HealthSnapshot()
		return snap.ChainSeq == 2
	}, "plain receipt was not appended")
	select {
	case err := <-plain:
		t.Fatalf("plain receipt returned ahead of the unconfirmed durable receipt before it: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	mu.Lock()
	early := append([]uint64(nil), seen...)
	mu.Unlock()
	if len(early) != 0 {
		t.Fatalf("observer saw %v before the durable receipt confirmed", early)
	}
	releaseFn()
	if err := <-durable; err != nil {
		t.Fatal(err)
	}
	if err := <-plain; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != 0 || seen[1] != 1 {
		t.Fatalf("observer order = %v, want [0 1]", seen)
	}
}

// A lifecycle record (transcript root) waits for every outstanding durable
// confirmation instead of sealing a chain with unconfirmed receipts.
func TestTranscriptRootDrainsOutstandingConfirmations(t *testing.T) {
	e, rec := newDeferredTestEmitter(t, nil)
	entered := make(chan struct{})
	var once sync.Once
	releaseFn := gateSync(t, rec, func() { once.Do(func() { close(entered) }) })
	emitted := make(chan error, 1)
	go func() { emitted <- e.EmitDurable(deferredTestOpts("https://api.vendor.example/one")) }()
	waitSignal(t, entered, "receipt sync")

	rooted := make(chan error, 1)
	go func() { rooted <- e.EmitTranscriptRoot(e.Session()) }()
	select {
	case err := <-rooted:
		t.Fatalf("transcript root completed while a receipt was unconfirmed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseFn()
	if err := <-emitted; err != nil {
		t.Fatal(err)
	}
	if err := <-rooted; err != nil {
		t.Fatalf("transcript root: %v", err)
	}
}

// A failed sync fails every receipt in that batch and every later one; none
// is reported as success, and the stream stays failed.
func TestEmitDurableSyncFailureFailsBatchAndLaterReceipts(t *testing.T) {
	var observed atomic.Int32
	e, rec := newDeferredTestEmitter(t, func(*Receipt) { observed.Add(1) })
	entered := make(chan struct{})
	release := make(chan struct{})
	var once, releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFn)
	rec.SetSyncForTest(func(*os.File) error {
		once.Do(func() { close(entered) })
		<-release
		return errors.New("injected sync failure")
	})
	const n = 8
	errs := make(chan error, n)
	go func() { errs <- e.EmitDurable(deferredTestOpts("https://api.vendor.example/leader")) }()
	waitSignal(t, entered, "leader sync")
	for i := 1; i < n; i++ {
		go func(i int) { errs <- e.EmitDurable(deferredTestOpts(fmt.Sprintf("https://api.vendor.example/%d", i))) }(i)
	}
	testwait.For(t, 10*time.Second, func() bool {
		snap, _ := e.HealthSnapshot()
		return snap.ChainSeq == n
	}, "followers were not appended behind the syncing leader")
	releaseFn()
	var storage, inherited int
	for i := 0; i < n; i++ {
		err := <-errs
		switch {
		case err == nil:
			t.Fatal("a receipt behind a failed sync reported success")
		case errors.Is(err, recorder.ErrDurability):
			storage++
		case errors.Is(err, recorder.ErrDurabilityInherited):
			inherited++
		default:
			t.Fatalf("unexpected error %v", err)
		}
	}
	if storage != 1 || inherited != n-1 {
		t.Fatalf("storage=%d inherited=%d, want 1 and %d", storage, inherited, n-1)
	}
	if got := e.DurabilityBlocks(); got != 1 {
		t.Fatalf("durability blocks = %d, want 1 (fsync/block quiescence invariant)", got)
	}
	if observed.Load() != 0 {
		t.Fatalf("observer saw %d unconfirmed receipts", observed.Load())
	}
	if err := e.EmitDurable(deferredTestOpts("https://api.vendor.example/after")); !errors.Is(err, recorder.ErrDurabilityInherited) {
		t.Fatalf("later receipt = %v, want ErrDurabilityInherited", err)
	}
}

// The paired native AEL sync failing fails the request and quarantines the
// emitter, even though the receipt itself confirmed.
func TestEmitDurableAELSyncFailureFailsRequest(t *testing.T) {
	e, _ := newDeferredTestEmitter(t, nil)
	emitSessionOpenForTest(t, e)
	if e.nativeAEL == nil || !e.nativeAEL.Opened() {
		t.Skip("native AEL not opened for this emitter")
	}
	e.nativeAEL.SetSyncForTest(func(*os.File) error { return errors.New("injected AEL sync failure") })
	err := e.EmitDurable(deferredTestOpts("https://api.vendor.example/pair"))
	if err == nil {
		t.Fatal("request succeeded with an unconfirmed AEL pair")
	}
	if e.HealthError() == nil {
		t.Fatal("emitter not quarantined after an AEL pair failure")
	}
	if err := e.EmitDurable(deferredTestOpts("https://api.vendor.example/next")); err == nil {
		t.Fatal("quarantined emitter accepted another receipt")
	}
}

// Backpressure: no more than maxInflightDurableEmits receipts wait for
// confirmation at once; the rest wait before taking the chain lock.
func TestEmitDurableInflightIsBounded(t *testing.T) {
	e, rec := newDeferredTestEmitter(t, nil)
	releaseFn := gateSync(t, rec, nil)
	n := maxInflightDurableEmits + 32
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) { errs <- e.EmitDurable(deferredTestOpts(fmt.Sprintf("https://api.vendor.example/%d", i))) }(i)
	}
	testwait.For(t, 20*time.Second, func() bool {
		snap, _ := e.HealthSnapshot()
		return snap.ChainSeq >= uint64(maxInflightDurableEmits) && len(e.inflight) == cap(e.inflight)
	}, "receipts did not fill the in-flight bound %d", maxInflightDurableEmits)
	// Every slot is held by a receipt waiting on the gated sync, so the
	// remaining emitters are parked on the slot channel and cannot append.
	if snap, _ := e.HealthSnapshot(); snap.ChainSeq != uint64(maxInflightDurableEmits) || cap(e.inflight) != maxInflightDurableEmits {
		t.Fatalf("appended %d with confirmations blocked, bound is %d", snap.ChainSeq, maxInflightDurableEmits)
	}
	releaseFn()
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// A receipt queued behind a durable receipt whose confirmation fails is not
// reported as success and is not observed, whether the recorder sync or the
// paired native AEL sync failed.
func TestEmitBehindFailedDurableFails(t *testing.T) {
	for _, failAEL := range []bool{false, true} {
		t.Run(fmt.Sprintf("ael=%v", failAEL), func(t *testing.T) {
			var observed atomic.Int32
			e, rec := newDeferredTestEmitter(t, func(*Receipt) { observed.Add(1) })
			emitSessionOpenForTest(t, e)
			entered := make(chan struct{})
			release := make(chan struct{})
			var once, releaseOnce sync.Once
			releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(releaseFn)
			hold := func(*os.File) error {
				once.Do(func() { close(entered) })
				<-release
				return errors.New("injected sync failure")
			}
			if failAEL {
				if e.nativeAEL == nil {
					t.Skip("native AEL not configured")
				}
				e.nativeAEL.SetSyncForTest(hold)
			} else {
				rec.SetSyncForTest(hold)
			}
			durable := make(chan error, 1)
			go func() { durable <- e.EmitDurable(deferredTestOpts("https://api.vendor.example/durable")) }()
			waitSignal(t, entered, "durable sync")
			before := observed.Load()
			plain := make(chan error, 1)
			go func() { plain <- e.Emit(deferredTestOpts("https://api.vendor.example/plain")) }()
			testwait.For(t, 10*time.Second, func() bool {
				snap, _ := e.HealthSnapshot()
				return snap.ChainSeq >= 3
			}, "plain receipt was not appended")
			releaseFn()
			if err := <-durable; err == nil {
				t.Fatal("durable receipt succeeded despite the injected sync failure")
			}
			err := <-plain
			if !errors.Is(err, recorder.ErrDurabilityInherited) || errors.Is(err, recorder.ErrDurability) {
				t.Fatalf("plain receipt behind a failed durable receipt = %v, want ErrDurabilityInherited only", err)
			}
			if got := observed.Load(); got != before {
				t.Fatalf("observer saw %d receipts after the failure, want none", got-before)
			}
		})
	}
}

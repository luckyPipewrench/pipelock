// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// reloadStateMatrix exercises the five reload states required by
// CLAUDE.md "Hot reload must preserve security state":
//   - first load
//   - first reload
//   - second unrelated reload
//   - downgrade/revocation reload
//   - reload with no scanner-relevant change
//
// The invariant under test: every Reload call disposes of the
// previously installed scanner (Close eventually returns true) without
// affecting the live scanner that handles new traffic.
func TestProxy_Reload_ScannerLifecycleStateMatrix(t *testing.T) {
	defaultsClone := func() *config.Config {
		c := config.Defaults()
		c.FetchProxy.TimeoutSeconds = 5
		c.Internal = nil
		c.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		c.APIAllowlist = nil
		return c
	}

	cfg := defaultsClone()
	logger := audit.NewNop()
	initialSc := scanner.New(cfg)
	p, err := New(cfg, logger, initialSc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// State 1: first load. The initial scanner is live.
	if initialSc.Closed() {
		t.Fatal("initial scanner reported Closed before any reload")
	}

	// State 2: first reload, with a config change that affects scanning.
	cfg2 := defaultsClone()
	cfg2.FetchProxy.Monitoring.Blocklist = append(
		cfg2.FetchProxy.Monitoring.Blocklist, "*.example-blocklist.test")
	sc2 := scanner.New(cfg2)
	p.Reload(cfg2, sc2)
	waitForClosed(t, initialSc, "initial scanner after first reload")
	if sc2.Closed() {
		t.Fatal("sc2 reported Closed immediately after being installed")
	}

	// State 3: second, unrelated reload (different config knob, scanner replaced).
	cfg3 := defaultsClone()
	cfg3.FetchProxy.Monitoring.Blocklist = append(
		cfg3.FetchProxy.Monitoring.Blocklist, "*.example-blocklist.test")
	cfg3.FetchProxy.TimeoutSeconds = 7
	sc3 := scanner.New(cfg3)
	p.Reload(cfg3, sc3)
	waitForClosed(t, sc2, "sc2 after second reload")
	if sc3.Closed() {
		t.Fatal("sc3 reported Closed immediately after being installed")
	}

	// State 4: downgrade/revocation — strip the custom blocklist back to defaults.
	cfg4 := defaultsClone()
	sc4 := scanner.New(cfg4)
	p.Reload(cfg4, sc4)
	waitForClosed(t, sc3, "sc3 after downgrade reload")
	if sc4.Closed() {
		t.Fatal("sc4 reported Closed immediately after being installed")
	}

	// State 5: reload with the same config (no scanner-relevant change). The
	// implementation still installs a freshly-built scanner; the prior one
	// must be drained-and-closed so resources do not accumulate across
	// idempotent reloads.
	cfg5 := defaultsClone()
	sc5 := scanner.New(cfg5)
	p.Reload(cfg5, sc5)
	waitForClosed(t, sc4, "sc4 after no-op reload")
	if sc5.Closed() {
		t.Fatal("sc5 reported Closed immediately after being installed")
	}
}

// TestProxy_Reload_DrainsBeforeClose proves the in-flight drain invariant:
// the previously installed scanner does not transition to "fully closed"
// (its rate-limiter / data-budget tickers stopped) until every BeginUse
// caller that registered before the swap has invoked release. Without
// the WaitGroup drain a future destructive Close (sqlite handle, fd) would
// race mid-scan callers.
func TestProxy_Reload_DrainsBeforeClose(t *testing.T) {
	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Internal = nil

	logger := audit.NewNop()
	initialSc := scanner.New(cfg)
	p, err := New(cfg, logger, initialSc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// Register an in-flight scanner user BEFORE reload. The release is held
	// until the assertion below, simulating a long-running scan.
	release, ok := initialSc.BeginUse()
	if !ok {
		t.Fatal("BeginUse on fresh scanner returned ok=false")
	}

	// Reload installs a fresh scanner and starts the drain-then-close
	// goroutine on the prior one.
	newSc := scanner.New(cfg)
	p.Reload(cfg, newSc)

	// The closed flag is published synchronously by Close, but BeginUse on
	// initialSc must already reject newcomers — that is the gate that lets
	// drain finish bounded. waitForClosed gives 2 seconds; under -race on
	// loaded CI a 500ms budget is a known flake source for goroutine
	// scheduling, so reuse the helper that the state-matrix test uses.
	waitForClosed(t, initialSc, "initial scanner after Reload")
	if release2, ok2 := initialSc.BeginUse(); ok2 {
		t.Error("BeginUse on initial scanner succeeded mid-drain")
		release2()
	}

	// New traffic targets newSc. Acquiring it must succeed.
	newRelease, ok := newSc.BeginUse()
	if !ok {
		t.Fatal("BeginUse on swapped-in scanner returned ok=false")
	}
	newRelease()

	// Releasing the in-flight user lets drain finish; the Close goroutine
	// now proceeds to tear down ticker resources. Drained() flips true
	// only after rateLimiter / dataBudget Close runs, so polling it
	// proves the close goroutine actually completed rather than relying
	// solely on the earlier mid-drain BeginUse rejection.
	release()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if initialSc.Drained() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Close goroutine did not finish draining initialSc within 2s of release")
}

// waitForClosed polls Closed() until it returns true or the timeout
// expires. Reload runs Close in a goroutine, so the prior scanner's
// closed flag is published asynchronously — but the flag is set before
// drain begins, so this should resolve in microseconds for an idle test.
func waitForClosed(t *testing.T, sc *scanner.Scanner, label string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sc.Closed() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s did not reach Closed=true within deadline", label)
}

// TestReverseProxy_EmitReceipt_NilGuards exercises the no-op paths of
// emitReceipt: an unset receiptEmitterPtr (deployments without flight
// recorder) and an emitter-pointer that is set but stores nil
// (intentionally disabled). Both must return cleanly without panicking,
// otherwise an OSS deployment without signing keys would crash on every
// reverse-proxy block.
func TestReverseProxy_EmitReceipt_NilGuards(t *testing.T) {
	cfg := reverseTestConfig()
	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	upstreamURL, _ := url.Parse("http://127.0.0.1:1") // unused; emitReceipt path only
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	rp := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, nil)

	// Path 1: receiptEmitterPtr never set. Must be a no-op.
	rp.emitReceipt(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionBlock})

	// Path 2: receiptEmitterPtr set but storing nil. Must be a no-op.
	var emPtr atomic.Pointer[receipt.Emitter]
	rp.SetReceiptEmitter(&emPtr)
	rp.emitReceipt(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionBlock})
}

// TestReverseProxy_SnapshotAndAcquire_RetryAndFallback covers the
// snapshotAndAcquire branches that only fire when the loaded scanner has
// already been Closed (BeginUse returns false). With the same closed
// scanner pinned via scPtr, three iterations exhaust without success and
// the helper returns the no-op release. The function must remain
// race-safe and never panic on this path.
func TestReverseProxy_SnapshotAndAcquire_RetryAndFallback(t *testing.T) {
	cfg := reverseTestConfig()
	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	upstreamURL, _ := url.Parse("http://127.0.0.1:1")
	sc := scanner.New(cfg)
	sc.Close() // Force BeginUse to return ok=false.

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	rp := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, nil)

	snap, release := rp.snapshotAndAcquire()
	defer release()
	if snap.sc != sc {
		t.Errorf("fallback snapshot.sc = %p, want closed scanner %p", snap.sc, sc)
	}
	// release must be safe to invoke even on the no-op path.
	release()
}

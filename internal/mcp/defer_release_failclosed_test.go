// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestDeferredHTTPReleaseGateEvaluationErrorFailsClosed: a release-time
// upstream gate that cannot be evaluated denies the held call.
func TestDeferredHTTPReleaseGateEvaluationErrorFailsClosed(t *testing.T) {
	active := mcpLiveLockLoader(t, contractruntime.ModeLive, mcpToolRule("r-allow", nil))
	var locked atomic.Bool
	run := startHTTPDeferRun(t, deferKillTestController(), func(o *MCPProxyOpts) {
		sc := o.Scanner
		o.Scanner = nil
		o.ScannerFn = func() *scanner.Scanner {
			if locked.Load() {
				return nil
			}
			return sc
		}
		o.ContractLoaderFn = func() *contractruntime.Loader {
			if locked.Load() {
				return active
			}
			return nil
		}
		o.ContractAgent = mcpLiveLockAgent
		o.ContractServer = mcpLiveLockServer
	})
	held := run.manager.Snapshot()[0]
	locked.Store(true)
	if err := run.manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := run.calls.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
	if out := run.stdout.String(); !strings.Contains(out, "contract upstream evaluation failed") {
		t.Fatalf("missing gate evaluation denial: %s", out)
	}
	assertTerminalJournal(t, run.manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceUpstreamContract)
	run.stop(t)
}

// TestDeferredHTTPReleaseGateKillSwitchVerdict: when the release-time gate
// itself reports the kill switch, the call is cancelled as a kill-switch
// denial, not a contract denial.
func TestDeferredHTTPReleaseGateKillSwitchVerdict(t *testing.T) {
	active := mcpLiveLockLoader(t, contractruntime.ModeLive, mcpToolRule("r-allow", nil))
	ks := deferKillTestController()
	var locked atomic.Bool
	run := startHTTPDeferRun(t, ks, func(o *MCPProxyOpts) {
		o.ContractLoaderFn = func() *contractruntime.Loader {
			if !locked.Load() {
				return nil
			}
			// Activate after the manager's precheck passed, while the
			// gate is being evaluated.
			ks.SetAPI(true)
			return active
		}
		o.ContractAgent = mcpLiveLockAgent
		o.ContractServer = mcpLiveLockServer
	})
	held := run.manager.Snapshot()[0]
	locked.Store(true)
	if err := run.manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := run.calls.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
	if out := run.stdout.String(); !strings.Contains(out, `"code":-32004`) {
		t.Fatalf("missing kill-switch denial: %s", out)
	}
	assertSingleKillSwitchResolution(t, run.receipts.snapshot())
	assertTerminalJournal(t, run.manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceKillSwitch)
	run.stop(t)
}

// TestDeferredHTTPReleaseReceiptFailureFailsClosed: an allowed release whose
// resolution receipt cannot be written is not sent.
func TestDeferredHTTPReleaseReceiptFailureFailsClosed(t *testing.T) {
	emitter, rec, _, _ := newReceiptTestHarness(t)
	run := startHTTPDeferRun(t, deferKillTestController(), func(o *MCPProxyOpts) {
		o.ReceiptEmitter = emitter
	})
	held := run.manager.Snapshot()[0]
	if err := rec.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}
	if err := run.manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := run.calls.Load(); got != 0 {
		t.Fatalf("upstream requests = %d, want 0", got)
	}
	if out := run.stdout.String(); !strings.Contains(out, "receipt emission failed") {
		t.Fatalf("missing receipt failure denial: %s", out)
	}
	run.stop(t)
}

// TestKillSwitchActivationNotBlockedByStalledDeferredSendStdio: a deferred
// stdio release stalled inside the sink write does not delay kill-switch
// activation, and new calls are denied while it stays stalled.
func TestKillSwitchActivationNotBlockedByStalledDeferredSendStdio(t *testing.T) {
	sc := testInputScanner(t)
	manager := newDeferKillManager(t)
	emitter, _, _, _ := newReceiptTestHarness(t)
	policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
	policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	ks := deferKillTestController()
	inputR, inputW := io.Pipe()
	var upstream, logBuf syncBuffer
	gate := &claimGateWriter{started: make(chan struct{}), release: make(chan struct{}), dst: &upstream}
	blocked := make(chan BlockedRequest, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardScannedInput(transport.NewStdioReader(inputR), transport.NewStdioWriter(gate), &logBuf,
			config.ActionWarn, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{
				Scanner: sc, PolicyCfg: policyCfg, DeferManager: manager, ReceiptEmitter: emitter,
				Transport: deferred.SurfaceMCPStdio, KillSwitch: ks,
			})
	}()
	if _, err := inputW.Write([]byte(deferKillTestCall)); err != nil {
		t.Fatalf("write input: %v", err)
	}
	testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "deferred stdio hold")
	held := manager.Snapshot()[0]
	resolved := make(chan error, 1)
	go func() { resolved <- manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval) }()
	<-gate.started // the release is now stalled inside the sink write

	activated := make(chan struct{})
	go func() {
		ks.SetAPI(true)
		close(activated)
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	select {
	case <-activated:
	case <-deadline.C:
		close(gate.release)
		t.Fatal("kill-switch activation blocked behind a stalled deferred send")
	}
	if !ks.IsActive() || ks.DeferredInFlight() != 1 {
		t.Fatalf("active=%v in-flight=%d, want active with 1 in flight", ks.IsActive(), ks.DeferredInFlight())
	}
	next := strings.Replace(deferKillTestCall, `"id":1`, `"id":2`, 1)
	if _, err := inputW.Write([]byte(next)); err != nil {
		t.Fatalf("write second call: %v", err)
	}
	select {
	case rec := <-blocked:
		if rec.ErrorCode != -32004 || string(rec.ID) != "2" {
			t.Fatalf("second call record = id %s code %d, want id 2 code -32004", rec.ID, rec.ErrorCode)
		}
	case <-deadline.C:
		close(gate.release)
		t.Fatal("new call was not denied while a deferred send was stalled")
	}
	close(gate.release)
	if err := <-resolved; err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	<-done
}

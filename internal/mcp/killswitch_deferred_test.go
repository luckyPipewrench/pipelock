// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// fastKillPoll shortens the held-call kill poll for the duration of a test.
func fastKillPoll(t *testing.T) {
	t.Helper()
	prev := deferKillSwitchPollInterval
	deferKillSwitchPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { deferKillSwitchPollInterval = prev })
}

// killSource arms one kill-switch activation source. The sentinel file is the
// one with no event of its own, so it is the case that needs the poll.
type killSource struct {
	name string
	ctl  func(t *testing.T) (*killswitch.Controller, func())
}

func killSources() []killSource {
	return []killSource{
		{"sentinel_file", func(t *testing.T) (*killswitch.Controller, func()) {
			path := filepath.Join(t.TempDir(), "kill")
			cfg := config.Defaults()
			cfg.KillSwitch.SentinelFile = path
			cfg.KillSwitch.Message = deferKillTestMessage
			return killswitch.New(cfg), func() {
				if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
					t.Fatalf("create sentinel: %v", err)
				}
			}
		}},
		{"api", func(*testing.T) (*killswitch.Controller, func()) {
			ks := deferKillTestController()
			return ks, func() { ks.SetAPI(true) }
		}},
	}
}

// TestDeferredStdioKillSwitchCancelsHeldCallWithoutAnotherMessage pins that a
// kill is acted on while a call is held, not only when the next message arrives
// or the resolver finishes. Before the watcher a held call sat through the kill
// until its resolver, approval or timeout ended it.
func TestDeferredStdioKillSwitchCancelsHeldCallWithoutAnotherMessage(t *testing.T) {
	for _, src := range killSources() {
		t.Run(src.name, func(t *testing.T) {
			fastKillPoll(t)
			ks, arm := src.ctl(t)
			manager := newDeferKillManager(t)
			receipts := &resolutionReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, receipts.observe)
			policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
			policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
			inputR, inputW := io.Pipe()
			var upstream, logBuf syncBuffer
			blocked := make(chan BlockedRequest, 4)
			done := make(chan struct{})
			go func() {
				defer close(done)
				ForwardScannedInput(transport.NewStdioReader(inputR), transport.NewStdioWriter(&upstream), &logBuf,
					config.ActionWarn, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{
						Scanner: testInputScanner(t), PolicyCfg: policyCfg, DeferManager: manager,
						ReceiptEmitter: emitter, Transport: deferred.SurfaceMCPStdio, KillSwitch: ks,
					})
			}()
			if _, err := inputW.Write([]byte(deferKillTestCall)); err != nil {
				t.Fatalf("write input: %v", err)
			}
			testwait.For(t, 5*time.Second, func() bool { return manager.HeldCount() == 1 }, "deferred stdio hold")
			held := manager.Snapshot()[0]

			// Allow direction: nothing is active, so the hold must stay held
			// across several polls.
			window := time.NewTimer(15 * deferKillSwitchPollInterval)
			recheck := time.NewTicker(deferKillSwitchPollInterval)
		quiet:
			for {
				select {
				case <-window.C:
					break quiet
				case <-recheck.C:
					if got := manager.HeldCount(); got != 1 {
						t.Fatalf("hold cancelled with no kill active: held = %d", got)
					}
				}
			}
			recheck.Stop()
			if got := manager.HeldCount(); got != 1 {
				t.Fatalf("hold cancelled with no kill active: held = %d", got)
			}

			arm()
			testwait.For(t, 5*time.Second, func() bool { return manager.HeldCount() == 0 }, "held call cancelled by the kill switch")

			select {
			case rec := <-blocked:
				if rec.ErrorCode != -32004 {
					t.Fatalf("blocked record code = %d, want -32004", rec.ErrorCode)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled call produced no client error")
			}
			if got := upstream.String(); got != "" {
				t.Fatalf("cancelled call reached upstream: %s", got)
			}
			assertSingleKillSwitchResolution(t, receipts.snapshot())
			assertTerminalJournal(t, manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceKillSwitch)
			if err := inputW.Close(); err != nil {
				t.Fatalf("close input: %v", err)
			}
			<-done
		})
	}
}

// TestDeferredHTTPKillSwitchCancelsHeldCallWithoutAnotherMessage is the same
// contract on the stdio-to-HTTP bridge.
func TestDeferredHTTPKillSwitchCancelsHeldCallWithoutAnotherMessage(t *testing.T) {
	for _, src := range killSources() {
		t.Run(src.name, func(t *testing.T) {
			fastKillPoll(t)
			ks, arm := src.ctl(t)
			run := startHTTPDeferRun(t, ks, nil)
			held := run.manager.Snapshot()[0]
			arm()
			testwait.For(t, 5*time.Second, func() bool { return run.manager.HeldCount() == 0 }, "held call cancelled by the kill switch")
			testwait.For(t, 5*time.Second, func() bool { return strings.Contains(run.stdout.String(), `"code":-32004`) }, "client kill error")
			if got := run.calls.Load(); got != 0 {
				t.Fatalf("upstream requests = %d, want 0", got)
			}
			assertSingleKillSwitchResolution(t, run.receipts.snapshot())
			assertTerminalJournal(t, run.manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceKillSwitch)
			run.stop(t)
		})
	}
}

// allReceipts collects every action receipt a test emitter records.
type allReceipts struct {
	mu   sync.Mutex
	recs []receipt.ActionRecord
}

func (a *allReceipts) observe(rc *receipt.Receipt) {
	if rc == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recs = append(a.recs, rc.ActionRecord)
}

func (a *allReceipts) snapshot() []receipt.ActionRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]receipt.ActionRecord(nil), a.recs...)
}

// TestStdioKillSwitchDenialOfPlainCallIsReceipted pins that a tool call the
// kill switch refuses leaves a signed block receipt, like every other MCP block.
// Previously the receipt chain showed the earlier allowed call and then nothing,
// although the client had been refused.
func TestStdioKillSwitchDenialOfPlainCallIsReceipted(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantReceipt bool
		wantTarget  string
	}{
		{"plain tools/call", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"x"}}}`, true, "read_file"},
		{"tools/list is not a tool call", `{"jsonrpc":"2.0","id":8,"method":"tools/list"}`, false, ""},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := deferKillTestController()
			ks.SetAPI(true)
			got := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, got.observe)
			inputR, inputW := io.Pipe()
			var upstream, logBuf syncBuffer
			blocked := make(chan BlockedRequest, 4)
			done := make(chan struct{})
			go func() {
				defer close(done)
				ForwardScannedInput(transport.NewStdioReader(inputR), transport.NewStdioWriter(&upstream), &logBuf,
					config.ActionWarn, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{
						Scanner: testInputScanner(t), ReceiptEmitter: emitter,
						Transport: deferred.SurfaceMCPStdio, KillSwitch: ks,
					})
			}()
			if _, err := inputW.Write([]byte(tt.line + "\n")); err != nil {
				t.Fatalf("write input: %v", err)
			}
			if err := inputW.Close(); err != nil {
				t.Fatalf("close input: %v", err)
			}
			<-done
			if upstream.String() != "" {
				t.Fatalf("killed message reached upstream: %s", upstream.String())
			}
			recs := got.snapshot()
			if !tt.wantReceipt {
				if len(recs) != 0 {
					t.Fatalf("receipts = %+v, want none", recs)
				}
				return
			}
			if len(recs) != 1 {
				t.Fatalf("receipts = %d, want exactly one kill-switch block", len(recs))
			}
			rec := recs[0]
			if rec.Verdict != config.ActionBlock || rec.Layer != mcpReceiptLayerKillSwitch || rec.Target != tt.wantTarget {
				t.Fatalf("receipt = verdict %q layer %q target %q, want block %q %q",
					rec.Verdict, rec.Layer, rec.Target, mcpReceiptLayerKillSwitch, tt.wantTarget)
			}
		})
	}
}

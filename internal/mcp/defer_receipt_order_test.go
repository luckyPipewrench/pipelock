// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// breakDeferJournal replaces the journal file with a directory, so the next
// append fails the way a removed or re-permissioned journal does in production.
func breakDeferJournal(t *testing.T, m *deferred.Manager) {
	t.Helper()
	path := filepath.Clean(m.JournalPath())
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatalf("move journal aside: %v", err)
	}
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("replace journal with a directory: %v", err)
	}
}

// requireNoAllowResolution fails when the signed chain holds an allow
// resolution receipt: an allow is the evidence that a held call was released,
// and for a call that was never sent it must not exist.
func requireNoAllowResolution(t *testing.T, recs []receipt.ActionRecord) {
	t.Helper()
	for _, r := range recs {
		if r.Verdict == config.ActionAllow {
			t.Fatalf("chain holds an allow resolution receipt for a call that was not sent: %+v", recs)
		}
	}
}

// TestDeferredReleaseReceiptFollowsJournal pins the order of a released call's
// evidence. The allow resolution receipt is written only after the journal
// accepted the allow, so a journal that cannot be written leaves the chain with
// the block alone, never an allow followed by a block for a call that was never
// sent.
//
// The healthy row is the positive control: the allow receipt still exists and
// the call is sent.
func TestDeferredReleaseReceiptFollowsJournal(t *testing.T) {
	tests := []struct {
		name          string
		breakJournal  bool
		wantDecision  string
		wantSent      bool
		wantResolutns []string // verdicts of resolution receipts, in order
	}{
		{"journal healthy", false, config.ActionAllow, true, []string{config.ActionAllow}},
		{"journal cannot be written", true, config.ActionBlock, false, []string{config.ActionBlock}},
	}

	t.Run("stdio", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
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
							ReceiptEmitter: emitter, RequireReceipts: true,
							Transport: deferred.SurfaceMCPStdio, KillSwitch: deferKillTestController(),
						})
				}()
				if _, err := inputW.Write([]byte(deferKillTestCall)); err != nil {
					t.Fatalf("write input: %v", err)
				}
				testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "deferred stdio hold")
				held := manager.Snapshot()[0]
				if tt.breakJournal {
					breakDeferJournal(t, manager)
				}
				got, err := manager.ResolveApprovalResult(held.DeferID, config.ActionAllow, deferred.SourceOperator)
				if err != nil {
					t.Fatalf("ResolveApprovalResult: %v", err)
				}
				if got != tt.wantDecision {
					t.Fatalf("reported decision = %q, want %q", got, tt.wantDecision)
				}
				if sent := strings.Contains(upstream.String(), "send_tool"); sent != tt.wantSent {
					t.Fatalf("call sent upstream = %v, want %v", sent, tt.wantSent)
				}
				requireResolutionVerdicts(t, receipts.snapshot(), tt.wantResolutns)
				if !tt.wantSent {
					requireNoAllowResolution(t, receipts.snapshot())
				}
				if err := inputW.Close(); err != nil {
					t.Fatalf("close input: %v", err)
				}
				<-done
			})
		}
	})

	t.Run("http bridge", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				run := startHTTPDeferRun(t, deferKillTestController(), func(o *MCPProxyOpts) {
					o.RequireReceipts = true
				})
				held := run.manager.Snapshot()[0]
				if tt.breakJournal {
					breakDeferJournal(t, run.manager)
				}
				got, err := run.manager.ResolveApprovalResult(held.DeferID, config.ActionAllow, deferred.SourceOperator)
				if err != nil {
					t.Fatalf("ResolveApprovalResult: %v", err)
				}
				if got != tt.wantDecision {
					t.Fatalf("reported decision = %q, want %q", got, tt.wantDecision)
				}
				wantCalls := int32(0)
				if tt.wantSent {
					wantCalls = 1
				}
				if calls := run.calls.Load(); calls != wantCalls {
					t.Fatalf("upstream requests = %d, want %d", calls, wantCalls)
				}
				requireResolutionVerdicts(t, run.receipts.snapshot(), tt.wantResolutns)
				if !tt.wantSent {
					requireNoAllowResolution(t, run.receipts.snapshot())
				}
				run.stop(t)
			})
		}
	})
}

func requireResolutionVerdicts(t *testing.T, recs []receipt.ActionRecord, want []string) {
	t.Helper()
	got := make([]string, 0, len(recs))
	for _, r := range recs {
		got = append(got, r.Verdict)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("resolution receipt verdicts = %v, want %v", got, want)
	}
}

// TestReceiptWritableProbe pins the Prepare-time probe: it closes an allow only
// when a required receipt has no usable emitter, and never when receipts are
// not required.
func TestReceiptWritableProbe(t *testing.T) {
	emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, nil)
	unhealthy, _, _, _ := newReceiptTestHarnessWithObserver(t, nil)
	unhealthy.MarkUnhealthy(io.ErrClosedPipe)

	tests := []struct {
		name string
		opts MCPProxyOpts
		want bool
	}{
		{"required, healthy emitter", MCPProxyOpts{ReceiptEmitter: emitter, RequireReceipts: true}, true},
		{"required, no emitter", MCPProxyOpts{RequireReceipts: true}, false},
		{"required, unhealthy emitter", MCPProxyOpts{ReceiptEmitter: unhealthy, RequireReceipts: true}, false},
		{"not required, no emitter", MCPProxyOpts{}, true},
		{"not required, unhealthy emitter", MCPProxyOpts{ReceiptEmitter: unhealthy}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := receiptWritable(tt.opts); got != tt.want {
				t.Fatalf("receiptWritable = %v, want %v", got, tt.want)
			}
			res := (&deferredReceiptSettlement{}).probeAllow(tt.opts, deferred.Resolution{FinalDecision: config.ActionAllow, ResolutionSource: deferred.SourceOperator})
			wantDecision := config.ActionAllow
			if !tt.want {
				wantDecision = config.ActionBlock
			}
			if res.FinalDecision != wantDecision {
				t.Fatalf("probeAllow decision = %q, want %q", res.FinalDecision, wantDecision)
			}
			if !tt.want && (res.ResolutionSource != deferred.SourceCancel || res.Reason != deferred.ReasonReceiptNotWritten) {
				t.Fatalf("closed allow = %s/%q, want cancel/%q", res.ResolutionSource, res.Reason, deferred.ReasonReceiptNotWritten)
			}
		})
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	deferKillTestMessage = "test deny-all active"
	deferKillTestCall    = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{}}}` + "\n"
)

// resolutionReceipts collects resolution-phase receipts after they are
// durably recorded.
type resolutionReceipts struct {
	mu   sync.Mutex
	recs []receipt.ActionRecord
}

func (r *resolutionReceipts) observe(rc *receipt.Receipt) {
	if rc == nil || rc.ActionRecord.DecisionPhase != receipt.DecisionPhaseResolution {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rc.ActionRecord)
}

func (r *resolutionReceipts) snapshot() []receipt.ActionRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]receipt.ActionRecord(nil), r.recs...)
}

func assertSingleKillSwitchResolution(t *testing.T, recs []receipt.ActionRecord) {
	t.Helper()
	if len(recs) != 1 {
		t.Fatalf("resolution receipts = %d, want exactly one kill-switch block", len(recs))
	}
	rec := recs[0]
	if rec.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want %q", rec.Verdict, config.ActionBlock)
	}
	if rec.ResolutionSource != deferred.SourceKillSwitch {
		t.Fatalf("resolution_source = %q, want %q", rec.ResolutionSource, deferred.SourceKillSwitch)
	}
	if rec.Layer != mcpReceiptLayerKillSwitch {
		t.Fatalf("layer = %q, want %q", rec.Layer, mcpReceiptLayerKillSwitch)
	}
	if rec.Pattern != deferredKillSwitchReason {
		t.Fatalf("pattern = %q, want %q", rec.Pattern, deferredKillSwitchReason)
	}
}

func assertSingleAllowResolution(t *testing.T, recs []receipt.ActionRecord) {
	t.Helper()
	if len(recs) != 1 || recs[0].Verdict != config.ActionAllow {
		t.Fatalf("resolution receipts = %+v, want exactly one allow", recs)
	}
}

func deferKillTestController() *killswitch.Controller {
	cfg := config.Defaults()
	cfg.KillSwitch.Message = deferKillTestMessage
	return killswitch.New(cfg)
}

// deferKillScenario drives one ordering of kill activation against approval.
// arm runs after the hold exists and before approval; sink runs inside the
// release path after Manager.Resolve claimed the hold and immediately before
// the release-boundary kill-switch claim.
type deferKillScenario struct {
	name        string
	arm         func(ks *killswitch.Controller, m *deferred.Manager)
	sink        func(t *testing.T, ks *killswitch.Controller, m *deferred.Manager)
	wantResolve error
	wantBlocked bool
}

func activateAndResolveAll(ks *killswitch.Controller, m *deferred.Manager) {
	ks.SetAPI(true)
	m.ResolveAll(config.ActionBlock, deferred.SourceKillSwitch)
}

func deferKillScenarios() []deferKillScenario {
	return []deferKillScenario{
		{
			name:        "kill_before_approval",
			arm:         func(ks *killswitch.Controller, _ *deferred.Manager) { ks.SetAPI(true) },
			wantBlocked: true,
		},
		{
			name:        "kill_after_manager_claim",
			sink:        func(_ *testing.T, ks *killswitch.Controller, _ *deferred.Manager) { ks.SetAPI(true) },
			wantBlocked: true,
		},
		{
			name: "resolve_all_in_claimed_window",
			sink: func(t *testing.T, ks *killswitch.Controller, m *deferred.Manager) {
				if n := len(m.Snapshot()); n != 0 {
					t.Errorf("claimed hold still visible to ResolveAll: %d", n)
				}
				activateAndResolveAll(ks, m)
			},
			wantBlocked: true,
		},
		{
			name:        "resolve_all_before_approval",
			arm:         activateAndResolveAll,
			wantResolve: deferred.ErrNotFound,
			wantBlocked: true,
		},
		{
			name: "kill_off_forwards",
		},
	}
}

func newDeferKillManager(t *testing.T) *deferred.Manager {
	t.Helper()
	return deferred.NewManager(deferred.Config{
		Enabled: true, Timeout: time.Minute, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096,
		JournalPath: filepath.Join(t.TempDir(), "defer-journal.jsonl"),
	})
}

// assertTerminalJournal checks the manager journal records the outcome that
// actually happened, not the allow the resolver asked for.
func assertTerminalJournal(t *testing.T, m *deferred.Manager, deferID, wantState, wantSource string) {
	t.Helper()
	assertTerminalJournalSequence(t, m, deferID, wantState+"/"+wantSource)
}

// assertTerminalJournalSequence checks the terminal journal entries for one
// hold, in order, as state/source pairs. More than one entry is legitimate only
// when an accepted allow was then closed because its required receipt could not
// be written: the journal keeps both the allow it accepted and the block that
// followed.
func assertTerminalJournalSequence(t *testing.T, m *deferred.Manager, deferID string, want ...string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(m.JournalPath()))
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var terminal []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var entry struct {
			DeferID string `json:"defer_id"`
			State   string `json:"state"`
			Source  string `json:"source"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse journal line %q: %v", line, err)
		}
		if entry.DeferID == deferID && entry.State != deferred.StateHeld {
			terminal = append(terminal, entry.State+"/"+entry.Source)
		}
	}
	if strings.Join(terminal, " ") != strings.Join(want, " ") {
		t.Fatalf("journal terminal entries = %v, want exactly %v", terminal, want)
	}
}

func TestDeferredStdioReleaseKillSwitchOrdering(t *testing.T) {
	for _, tc := range deferKillScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			sc := testInputScanner(t)
			manager := newDeferKillManager(t)
			receipts := &resolutionReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, receipts.observe)
			policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
			policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
			ks := deferKillTestController()
			var sinkHook func()
			if tc.sink != nil {
				sinkHook = func() { tc.sink(t, ks, manager) }
			}
			inputR, inputW := io.Pipe()
			var upstream, logBuf syncBuffer
			blocked := make(chan BlockedRequest, 4)
			done := make(chan struct{})
			go func() {
				defer close(done)
				ForwardScannedInput(transport.NewStdioReader(inputR), transport.NewStdioWriter(&upstream), &logBuf,
					config.ActionWarn, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{
						Scanner: sc, PolicyCfg: policyCfg, DeferManager: manager, ReceiptEmitter: emitter,
						Transport: deferred.SurfaceMCPStdio, KillSwitch: ks,
						beforeDeferredSinkClaim: sinkHook,
					})
			}()
			if _, err := inputW.Write([]byte(deferKillTestCall)); err != nil {
				t.Fatalf("write input: %v", err)
			}
			testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "deferred stdio hold")
			held := manager.Snapshot()[0]
			if tc.arm != nil {
				tc.arm(ks, manager)
			}
			// Resolve invokes the release callback synchronously, so every
			// side effect below has happened when it returns.
			if err := manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); !errors.Is(err, tc.wantResolve) {
				t.Fatalf("resolve err = %v, want %v", err, tc.wantResolve)
			}
			if tc.wantBlocked {
				if got := upstream.String(); got != "" {
					t.Fatalf("cancelled call reached stdio upstream: %s", got)
				}
				select {
				case rec := <-blocked:
					if rec.ErrorCode != -32004 || rec.ErrorMessage != deferKillTestMessage {
						t.Fatalf("blocked record = %d %q, want -32004 %q", rec.ErrorCode, rec.ErrorMessage, deferKillTestMessage)
					}
				default:
					t.Fatal("cancelled call produced no blocked record")
				}
				if n := len(blocked); n != 0 {
					t.Fatalf("extra blocked records: %d", n)
				}
				assertSingleKillSwitchResolution(t, receipts.snapshot())
				assertTerminalJournal(t, manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceKillSwitch)
			} else {
				if got := upstream.String(); !strings.Contains(got, "send_tool") {
					t.Fatalf("approved call did not reach stdio upstream: %q", got)
				}
				if n := len(blocked); n != 0 {
					t.Fatalf("approved call was blocked: %d records", n)
				}
				assertSingleAllowResolution(t, receipts.snapshot())
				assertTerminalJournal(t, manager, held.DeferID, deferred.StateResolvedAllow, deferred.SourceApproval)
			}
			if err := inputW.Close(); err != nil {
				t.Fatalf("close input: %v", err)
			}
			<-done
		})
	}
}

// countingUpstream is an MCP HTTP upstream bound through net.ListenConfig on
// an ephemeral port that counts every request it receives.
func countingUpstream(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &calls
}

type httpDeferRun struct {
	manager  *deferred.Manager
	receipts *resolutionReceipts
	stdout   *syncBuffer
	calls    *atomic.Int32
	inputW   *io.PipeWriter
	cancel   context.CancelFunc
	done     chan error
}

func startHTTPDeferRun(t *testing.T, ks *killswitch.Controller, mutate func(*MCPProxyOpts)) *httpDeferRun {
	t.Helper()
	srv, calls := countingUpstream(t)
	run := &httpDeferRun{
		manager:  newDeferKillManager(t),
		receipts: &resolutionReceipts{},
		stdout:   &syncBuffer{},
		calls:    calls,
		done:     make(chan error, 1),
	}
	emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, run.receipts.observe)
	policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
	policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	opts := MCPProxyOpts{
		Scanner: testInputScanner(t), PolicyCfg: policyCfg, DeferManager: run.manager,
		ReceiptEmitter: emitter, KillSwitch: ks,
	}
	if mutate != nil {
		mutate(&opts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	run.cancel = cancel
	inputR, inputW := io.Pipe()
	run.inputW = inputW
	var stderr syncBuffer
	go func() {
		run.done <- RunHTTPProxy(ctx, inputR, run.stdout, &stderr, srv.URL, nil, opts)
	}()
	if _, err := inputW.Write([]byte(deferKillTestCall)); err != nil {
		t.Fatalf("write input: %v", err)
	}
	testwait.For(t, 5*time.Second, func() bool { return len(run.manager.Snapshot()) == 1 }, "deferred HTTP hold")
	return run
}

func (r *httpDeferRun) stop(t *testing.T) {
	t.Helper()
	if err := r.inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	r.cancel()
	if err := <-r.done; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("RunHTTPProxy: %v", err)
	}
}

func TestDeferredHTTPReleaseKillSwitchOrdering(t *testing.T) {
	for _, tc := range deferKillScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			ks := deferKillTestController()
			var managerRef atomic.Pointer[deferred.Manager]
			run := startHTTPDeferRun(t, ks, func(o *MCPProxyOpts) {
				if tc.sink != nil {
					o.beforeDeferredSinkClaim = func() { tc.sink(t, ks, managerRef.Load()) }
				}
			})
			managerRef.Store(run.manager)
			held := run.manager.Snapshot()[0]
			if tc.arm != nil {
				tc.arm(ks, run.manager)
			}
			if err := run.manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); !errors.Is(err, tc.wantResolve) {
				t.Fatalf("resolve err = %v, want %v", err, tc.wantResolve)
			}
			if tc.wantBlocked {
				if got := run.calls.Load(); got != 0 {
					t.Fatalf("upstream requests = %d, want 0", got)
				}
				out := run.stdout.String()
				if !strings.Contains(out, `"code":-32004`) || !strings.Contains(out, deferKillTestMessage) {
					t.Fatalf("missing kill-switch denial: %s", out)
				}
				assertSingleKillSwitchResolution(t, run.receipts.snapshot())
				assertTerminalJournal(t, run.manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceKillSwitch)
			} else {
				if got := run.calls.Load(); got != 1 {
					t.Fatalf("upstream requests = %d, want 1", got)
				}
				assertSingleAllowResolution(t, run.receipts.snapshot())
				assertTerminalJournal(t, run.manager, held.DeferID, deferred.StateResolvedAllow, deferred.SourceApproval)
			}
			run.stop(t)
		})
	}
}

// TestDeferredHTTPReleaseRerunsUpstreamGate locks the upstream while the call
// is held; the release must apply the same live gate as the ordinary path.
func TestDeferredHTTPReleaseRerunsUpstreamGate(t *testing.T) {
	rule := contractruntimetest.HTTPEnforceRule("r-other", "api.example.com", "/", http.MethodPost)
	denied := mcpLiveLockLoader(t, contractruntime.ModeLive, rule)
	var locked atomic.Bool
	run := startHTTPDeferRun(t, deferKillTestController(), func(o *MCPProxyOpts) {
		o.ContractLoaderFn = func() *contractruntime.Loader {
			if locked.Load() {
				return denied
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
	data := decodeRPCError(t, run.stdout.String())
	if got := data[mcpBlockReasonKey]; got != string(blockreason.ContractDefaultDeny) {
		t.Fatalf("%s = %v, want %s", mcpBlockReasonKey, got, blockreason.ContractDefaultDeny)
	}
	recs := run.receipts.snapshot()
	if len(recs) != 1 || recs[0].Verdict != config.ActionBlock || recs[0].ResolutionSource != deferred.SourceUpstreamContract {
		t.Fatalf("resolution receipts = %+v, want one upstream_contract block", recs)
	}
	assertTerminalJournal(t, run.manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceUpstreamContract)
	run.stop(t)
}

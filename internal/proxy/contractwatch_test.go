// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const contractWatchTimeout = 10 * time.Second

type contractWatchHarness struct {
	fixture  contractruntimetest.Fixture
	storeDir string
	cfg      *config.Config
}

func newContractWatchHarness(t *testing.T) *contractWatchHarness {
	t.Helper()
	fixture := contractruntimetest.NewFixture(t)
	storeDir := t.TempDir()
	env := contractruntimetest.Env()
	contractruntimetest.WriteSignedActiveStore(t, fixture, storeDir, contractruntimetest.ActiveStoreOptions{
		Generation:  1,
		PriorHash:   "sha256:genesis",
		Environment: env,
	})
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.LearnLock.Enabled = true
	cfg.LearnLock.StoreDir = storeDir
	cfg.LearnLock.RosterPath = fixture.RosterPath()
	cfg.LearnLock.PinnedRootFingerprint = fixture.RootFingerprint()
	cfg.LearnLock.Environment = config.LearnLockEnvironment{ID: env.ID, Tenant: env.Tenant, DeploymentID: env.DeploymentID}
	cfg.LearnLock.MinimumSignatures = 1
	cfg.LearnLock.Mode = string(contractruntime.ModeLive)
	return &contractWatchHarness{fixture: fixture, storeDir: storeDir, cfg: cfg}
}

func (h *contractWatchHarness) promote(t *testing.T, generation uint64, prior string) {
	t.Helper()
	contractruntimetest.WriteSignedActiveStore(t, h.fixture, h.storeDir, contractruntimetest.ActiveStoreOptions{
		Generation:  generation,
		PriorHash:   prior,
		Environment: contractruntimetest.Env(),
	})
}

func waitContractGeneration(t *testing.T, p *Proxy, want uint64) {
	t.Helper()
	testwait.For(t, contractWatchTimeout, func() bool {
		set := p.currentContractLoader().Current()
		return set != nil && set.Generation() == want
	}, "promoted contract generation to apply live")
}

func TestProxyContractWatcher_PromotionAppliesLiveAcrossReload(t *testing.T) {
	h := newContractWatchHarness(t)
	p := newTestProxyWithConfig(t, h.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p.startContractWatcher(ctx)

	first := p.currentContractLoader()
	if first == nil || first.Current() == nil {
		t.Fatal("expected an initial loader with generation 1")
	}
	if got := p.contractWatch.active.Load(); got != 1 {
		t.Fatalf("active watchers after start = %d, want 1", got)
	}

	h.promote(t, 2, first.Current().ManifestHash())
	waitContractGeneration(t, p, 2)

	// A config reload builds a fresh loader. The old watcher must stop and
	// the new loader must pick up the next promotion live.
	if !p.Reload(h.cfg, scanner.MustNew(h.cfg)) {
		t.Fatal("reload failed")
	}
	second := p.currentContractLoader()
	if second == first {
		t.Fatal("reload did not publish a new loader")
	}
	if got := p.contractWatch.started.Load(); got != 2 {
		t.Fatalf("watchers started = %d, want 2", got)
	}
	if got := p.contractWatch.active.Load(); got != 1 {
		t.Fatalf("active watchers after reload = %d, want 1 (old watcher leaked)", got)
	}

	h.promote(t, 3, second.Current().ManifestHash())
	waitContractGeneration(t, p, 3)
	if first.Current().Generation() != 2 {
		t.Fatalf("replaced loader generation = %d, want it frozen at 2", first.Current().Generation())
	}

	p.stopContractWatcher()
	if got := p.contractWatch.active.Load(); got != 0 {
		t.Fatalf("active watchers after stop = %d, want 0", got)
	}
}

func TestProxyContractWatcher_ReloadBeforeStartDefersToStart(t *testing.T) {
	h := newContractWatchHarness(t)
	p := newTestProxyWithConfig(t, h.cfg)
	if !p.Reload(h.cfg, scanner.MustNew(h.cfg)) {
		t.Fatal("reload failed")
	}
	if got := p.contractWatch.started.Load(); got != 0 {
		t.Fatalf("watcher started before the proxy lifecycle context existed: %d", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p.startContractWatcher(ctx)
	if got := p.contractWatch.active.Load(); got != 1 {
		t.Fatalf("active watchers = %d, want 1", got)
	}
}

func TestProxyContractWatcher_StartWiresWatcherAndShutdownStopsIt(t *testing.T) {
	h := newContractWatchHarness(t)
	p := newTestProxyWithConfig(t, h.cfg)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.StartWithListener(ctx, ln) }()
	testwait.For(t, contractWatchTimeout, func() bool { return p.contractWatch.active.Load() == 1 }, "Start to arm the contract watcher")

	h.promote(t, 2, p.currentContractLoader().Current().ManifestHash())
	waitContractGeneration(t, p, 2)

	cancel()
	select {
	case <-done:
	case <-time.After(contractWatchTimeout):
		t.Fatal("proxy did not stop")
	}
	testwait.For(t, contractWatchTimeout, func() bool { return p.contractWatch.active.Load() == 0 }, "shutdown to stop the contract watcher")
}

func TestProxyContractWatcher_CorruptPromoteKeepsEnforcement(t *testing.T) {
	h := newContractWatchHarness(t)
	p := newTestProxyWithConfig(t, h.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p.startContractWatcher(ctx)
	loader := p.currentContractLoader()
	good := loader.Current()

	active := filepath.Join(h.storeDir, "active.json")
	if err := os.WriteFile(active, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt manifest: %v", err)
	}
	if err := loader.Reload(); err == nil {
		t.Fatal("corrupt manifest reload returned nil error")
	}
	if p.currentContractLoader().Current() != good {
		t.Fatal("corrupt promoted manifest dropped enforcement")
	}
	if got := p.contractWatch.active.Load(); got != 1 {
		t.Fatalf("watcher stopped after corrupt manifest: active = %d", got)
	}
}

func TestProxyContractWatcher_NoLoaderStartsNothing(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	p := newTestProxyWithConfig(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p.startContractWatcher(ctx)
	if got := p.contractWatch.started.Load(); got != 0 {
		t.Fatalf("watchers started with learn_lock disabled: %d", got)
	}
}

func TestProxyContractWatcher_LogContractWatchErrorHandlesNilLogger(t *testing.T) {
	p := newTestProxyWithConfig(t, config.Defaults())
	p.logContractWatchError(nil)
	p.logContractWatchError(os.ErrInvalid)
	p.logger = nil
	p.logContractWatchError(os.ErrInvalid)
}

// A watcher that fails to start must not mark its loader as watched: the next
// sync retries instead of leaving promotions unobserved until a reload.
func TestProxyContractWatcher_FailedStartIsRetried(t *testing.T) {
	h := newContractWatchHarness(t)
	p := newTestProxyWithConfig(t, h.cfg)
	if !p.Reload(h.cfg, scanner.MustNew(h.cfg)) {
		t.Fatal("reload failed")
	}
	moved := h.storeDir + ".moved"
	if err := os.Rename(h.storeDir, moved); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p.startContractWatcher(ctx)
	if got := p.contractWatch.active.Load(); got != 0 {
		t.Fatalf("active watchers = %d with the store missing, want 0", got)
	}
	if err := os.Rename(moved, h.storeDir); err != nil {
		t.Fatal(err)
	}
	p.syncContractWatcher()
	if got := p.contractWatch.active.Load(); got != 1 {
		t.Fatalf("active watchers after retry = %d, want 1", got)
	}
	t.Cleanup(p.stopContractWatcher)
}

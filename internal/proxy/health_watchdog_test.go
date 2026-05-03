// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/health"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// healthRespParse pulls the parts the watchdog tests inspect from /health.
type healthRespParse struct {
	Status     string          `json:"status"`
	Subsystems map[string]bool `json:"subsystems"`
}

// callHealth invokes the /health handler against the given proxy and returns
// the HTTP status plus parsed body. Uses ServeMux directly to avoid a real
// listener.
func callHealth(t *testing.T, p *Proxy) (int, healthRespParse) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", p.handleHealth)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body healthRespParse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /health body: %v (raw=%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

// newWatchdogProxy builds a proxy with cfg.HealthWatchdog.Enabled defaulted
// to true and a custom-constructed watchdog whose probe is supplied by the
// caller. The interval is small (50ms) so tests can advance the watchdog
// past staleness quickly. Returns the proxy plus a cleanup func that
// guarantees the watchdog goroutine exits.
func newWatchdogProxy(t *testing.T, probe health.Probe) (*Proxy, func()) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.HealthWatchdog.IntervalSeconds = 1     // 1s interval, 3s threshold
	cfg.HealthWatchdog.ExposeSubsystems = true // tests assert against subsystems map

	wd, err := health.New(health.Config{
		Interval: 50 * time.Millisecond,
		Probe:    probe,
	})
	if err != nil {
		t.Fatalf("health.New: %v", err)
	}

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, err := New(cfg, logger, sc, metrics.New(), WithHealthWatchdog(wd))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wd.Start(ctx)

	cleanup := func() {
		cancel()
		p.Close()
	}
	return p, cleanup
}

// TestHealth_DefaultProbeReportsHealthy verifies the live scanner-probe path:
// after construction the watchdog's first /health call has a stale scanner
// heartbeat (no Scan happened yet under fast-test interval), the default probe
// runs, scans the synthetic fail-fast URL, returns nil, and /health is 200.
//
// This is the inverse of the deadlock test: with a real scanner the probe
// completes well within the interval/2 budget.
func TestHealth_DefaultProbeReportsHealthy(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.HealthWatchdog.IntervalSeconds = 1
	cfg.HealthWatchdog.ExposeSubsystems = true // assert against subsystems map

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer p.Close()
	p.wd.Start(ctx)

	code, body := callHealth(t, p)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%+v)", code, body)
	}
	if body.Status != healthStatusHealthy {
		t.Errorf("expected status=healthy, got %q", body.Status)
	}
	for _, name := range []string{"scanner", "config", "session", "killswitch", "watchdog"} {
		if !body.Subsystems[name] {
			t.Errorf("subsystem %q expected true, got false", name)
		}
	}
}

// TestHealth_ScannerDeadlock_FlipsTo503 is the kickoff-spec integration test.
// A probe that blocks until ctx is cancelled simulates a scanner whose Scan
// won't return. The watchdog's interval/2 timeout fires, probe returns
// ctx.Err(), Snapshot marks scanner unhealthy, and /health flips to 503.
//
// The "within the check interval" guarantee in the kickoff is satisfied
// because the probe runs synchronously inside Snapshot under an interval/2
// deadline; one /health call after the scanner heartbeat ages out is
// sufficient to surface the wedge.
func TestHealth_ScannerDeadlock_FlipsTo503(t *testing.T) {
	t.Parallel()

	hang := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	p, cleanup := newWatchdogProxy(t, hang)
	defer cleanup()

	// Force the scanner heartbeat into the stale region. Construction-time
	// seed bumps it; we age it deterministically by reaching into the
	// watchdog directly. This avoids time.Sleep flakes under CI load.
	p.wd.AgeScannerForTest(time.Hour)

	code, body := callHealth(t, p)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (body=%+v)", code, body)
	}
	if body.Status != healthStatusUnhealthy {
		t.Errorf("expected status=unhealthy, got %q", body.Status)
	}
	if body.Subsystems["scanner"] {
		t.Errorf("expected subsystems.scanner=false, got true (body=%+v)", body)
	}
	// Other subsystems should remain healthy — wedge is isolated.
	if !body.Subsystems["config"] || !body.Subsystems["session"] ||
		!body.Subsystems["killswitch"] || !body.Subsystems["watchdog"] {
		t.Errorf("unexpected cascading unhealth: %+v", body.Subsystems)
	}
}

// TestHealth_ProbeRecovers_RebeatsToHealthy verifies the re-beat behavior:
// once the probe returns nil after a stale period, the scanner heartbeat is
// refreshed and /health returns 200 again on the next call.
func TestHealth_ProbeRecovers_RebeatsToHealthy(t *testing.T) {
	t.Parallel()

	failNext := make(chan struct{}, 1)
	probe := func(ctx context.Context) error {
		select {
		case <-failNext:
			return context.DeadlineExceeded
		default:
			return nil
		}
	}
	p, cleanup := newWatchdogProxy(t, probe)
	defer cleanup()

	// First /health: scanner stale → probe nil → re-beat → healthy.
	p.wd.AgeScannerForTest(time.Hour)
	code, body := callHealth(t, p)
	if code != http.StatusOK {
		t.Fatalf("after recovery expected 200, got %d (body=%+v)", code, body)
	}
	if !body.Subsystems["scanner"] {
		t.Fatalf("expected scanner=true after re-beat")
	}

	// Now arm the probe to fail and age the scanner again — should flip to 503.
	failNext <- struct{}{}
	p.wd.AgeScannerForTest(time.Hour)
	code, body = callHealth(t, p)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("after probe-fails-arm expected 503, got %d (body=%+v)", code, body)
	}
	if body.Subsystems["scanner"] {
		t.Errorf("expected scanner=false on probe failure")
	}
}

// TestScannerProbe_NilPointers_ReturnsError covers the two early-return
// branches in scannerProbe: a nil scannerPtr or nil cfgPtr both yield a
// non-nil error so the watchdog marks scanner unhealthy.
func TestScannerProbe_NilPointers_ReturnsError(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	t.Run("nil scanner pointer", func(t *testing.T) {
		var emptyScanner *scanner.Scanner
		p.scannerPtr.Store(emptyScanner)
		t.Cleanup(func() { p.scannerPtr.Store(sc) })

		if err := p.scannerProbe(context.Background()); err == nil {
			t.Fatal("expected error on nil scanner, got nil")
		}
	})

	t.Run("nil config pointer", func(t *testing.T) {
		var emptyCfg *config.Config
		p.cfgPtr.Store(emptyCfg)
		t.Cleanup(func() { p.cfgPtr.Store(cfg) })

		if err := p.scannerProbe(context.Background()); err == nil {
			t.Fatal("expected error on nil config, got nil")
		}
	})

	t.Run("live scanner returns nil", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.scannerProbe(ctx); err != nil {
			t.Fatalf("expected nil error from live scanner probe, got %v", err)
		}
	})
}

// TestScannerProbe_SingleflightPreventsGoroutineLeak covers the singleflight
// guard that stops /health from spawning a fresh probe goroutine on every
// poll while the scanner is wedged. Without the guard an attacker (or a
// noisy monitor) hitting unauthenticated /health repeatedly during a wedge
// would accumulate unbounded leaked goroutines, turning the health endpoint
// into a denial-of-service amplifier exactly when enforcement is already
// degraded. After the fix, concurrent probes during a wedge return an
// immediate error without launching a second scan goroutine.
func TestScannerProbe_SingleflightPreventsGoroutineLeak(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	// Simulate a wedged scan by pinning the inflight flag to true. The next
	// scannerProbe call must short-circuit without spawning a goroutine.
	if !p.probeInflight.CompareAndSwap(false, true) {
		t.Fatal("probeInflight should start false")
	}
	t.Cleanup(func() { p.probeInflight.Store(false) })

	gBefore := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := p.scannerProbe(ctx)
		cancel()
		if err == nil {
			t.Fatalf("expected error while inflight, got nil")
		}
		if !strings.Contains(err.Error(), "in flight") {
			t.Fatalf("expected 'in flight' error, got %v", err)
		}
	}
	gAfter := runtime.NumGoroutine()
	if gAfter > gBefore+2 {
		t.Errorf("goroutines leaked under inflight contention: before=%d after=%d (want growth <= 2 for goroutine GC slack)", gBefore, gAfter)
	}
}

// TestHealth_ExposeSubsystemsDefault_HidesMap covers the default-secure
// behavior of /health: with HealthWatchdog.ExposeSubsystems left at its
// false default, the per-subsystem boolean map MUST be omitted from the
// response so unauthenticated callers cannot distinguish scanner-wedge
// from config-failure from kill-switch wiring. The 503 status on wedge
// is preserved unconditionally so external supervisors keep a clean
// liveness signal.
func TestHealth_ExposeSubsystemsDefault_HidesMap(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.HealthWatchdog.IntervalSeconds = 1
	// ExposeSubsystems default is false; do not set it.

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.wd.Start(ctx)

	code, body := callHealth(t, p)
	if code != http.StatusOK {
		t.Errorf("status = %d, want 200", code)
	}
	if len(body.Subsystems) != 0 {
		t.Errorf("Subsystems must be omitted by default, got %+v", body.Subsystems)
	}
}

// TestHealth_ExposeSubsystemsTrue_IncludesMapAnd503OnWedge confirms the
// opt-in path still works: when the operator sets ExposeSubsystems=true
// the per-subsystem map is present, AND a wedge still flips status to
// 503 so the breakdown remains accurate diagnostic data on the trusted
// network the operator chose to expose it on.
func TestHealth_ExposeSubsystemsTrue_IncludesMapAnd503OnWedge(t *testing.T) {
	t.Parallel()

	hang := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	p, cleanup := newWatchdogProxy(t, hang)
	defer cleanup()

	// Force the scanner heartbeat to look stale; the wedged probe will
	// fail and flip scanner unhealthy.
	p.wd.AgeScannerForTest(time.Hour)
	code, body := callHealth(t, p)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (subsystem unhealthy)", code)
	}
	if len(body.Subsystems) == 0 {
		t.Fatalf("Subsystems must be present when ExposeSubsystems=true")
	}
	if body.Subsystems["scanner"] {
		t.Errorf("expected scanner=false on wedge probe, got %+v", body.Subsystems)
	}
}

func TestHealth_ConfigPointerNil_Returns503NotPanic(t *testing.T) {
	t.Parallel()

	p, cleanup := newWatchdogProxy(t, func(context.Context) error {
		t.Fatal("probe must not run when config pointer is nil")
		return nil
	})
	defer cleanup()

	var nilCfg *config.Config
	p.cfgPtr.Store(nilCfg)

	code, body := callHealth(t, p)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (body=%+v)", code, body)
	}
	if body.Status != healthStatusUnhealthy {
		t.Fatalf("expected status=unhealthy, got %q", body.Status)
	}
	if body.Subsystems["config"] {
		t.Fatalf("expected config=false, got %+v", body.Subsystems)
	}
	if body.Subsystems["scanner"] {
		t.Fatalf("expected scanner=false when config is nil, got %+v", body.Subsystems)
	}
}

func TestHealth_ReloadedScannerKeepsHeartbeat(t *testing.T) {
	t.Parallel()

	p, cleanup := newWatchdogProxy(t, func(context.Context) error {
		return context.DeadlineExceeded
	})
	defer cleanup()

	cfg := p.CurrentConfig().Clone()
	newSc := scanner.New(cfg)
	if ok := p.Reload(cfg, newSc); !ok {
		t.Fatal("Reload returned false")
	}

	p.wd.AgeScannerForTest(time.Hour)
	_ = newSc.Scan(context.Background(), "ftp://heartbeat-after-reload.invalid/")

	code, body := callHealth(t, p)
	if code != http.StatusOK {
		t.Fatalf("expected 200 after reloaded scanner heartbeat, got %d (body=%+v)", code, body)
	}
	if !body.Subsystems["scanner"] {
		t.Fatalf("expected scanner=true after reloaded scanner Scan heartbeat, got %+v", body.Subsystems)
	}
}

// TestHealth_WatchdogDisabled_LegacyShape verifies that turning the watchdog
// off in config restores the pre-watchdog response (no `subsystems` key, 200
// regardless of subsystem state).
func TestHealth_WatchdogDisabled_LegacyShape(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.HealthWatchdog.Enabled = false

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()
	if p.wd != nil {
		t.Fatalf("expected nil watchdog when disabled, got %v", p.wd)
	}

	code, body := callHealth(t, p)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if body.Status != healthStatusHealthy {
		t.Errorf("expected status=healthy, got %q", body.Status)
	}
	if body.Subsystems != nil {
		t.Errorf("expected subsystems omitted when watchdog disabled, got %+v", body.Subsystems)
	}
}

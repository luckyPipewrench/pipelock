package health

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testInterval = 100 * time.Millisecond
	testEpoch    = int64(1_700_000_000_000_000_000) // 2023-11-14 in nanos
)

// fakeClock is a monotonic mock clock advanced explicitly by tests. nowFn
// reads stored nanos; Advance bumps them. Safe for concurrent use because
// the goroutine calls nowFn while tests advance the clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Unix(0, testEpoch)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// allAlive is the SnapshotInput shape used when a test wants to isolate a
// specific failure mode and have all other presence bools be true. Both
// SessionEnabled and KillSwitchEnabled default to false here so the
// "subsystem turned off → healthy" branch is exercised; tests that need
// the enabled-and-required path flip the flags explicitly.
var allAlive = SnapshotInput{
	ScannerPtrAlive:   bool(true),
	ConfigPtrAlive:    bool(true),
	SessionEnabled:    bool(false),
	SessionPtrAlive:   bool(false),
	KillSwitchEnabled: bool(true),
	KillSwitchPresent: bool(true),
}

func okProbe(_ context.Context) error  { return nil }
func errProbe(_ context.Context) error { return errors.New("probe failed") }

// hangProbe blocks until ctx is canceled. Use with a context that has a
// deadline; the probe returns ctx.Err() once the deadline fires.
func hangProbe(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// recordingProbe captures the deadline visible to the probe so tests can
// assert that Snapshot wrapped the parent context with Interval/2.
type recordingProbe struct {
	mu       sync.Mutex
	deadline time.Time
	hadDL    bool
	calls    atomic.Int32
	ret      error
}

func (r *recordingProbe) Call(ctx context.Context) error {
	dl, ok := ctx.Deadline()
	r.mu.Lock()
	r.deadline = dl
	r.hadDL = ok
	r.mu.Unlock()
	r.calls.Add(1)
	return r.ret
}

func mustNew(t *testing.T, cfg Config) *Watchdog {
	t.Helper()
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

func TestNew_ValidatesConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
	}{
		{"zero interval", Config{Probe: okProbe}},
		{"negative interval", Config{Interval: -1, Probe: okProbe}},
		{"nil probe", Config{Interval: testInterval}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestNew_NowFnDefaultsToTimeNow(t *testing.T) {
	t.Parallel()
	w, err := New(Config{Interval: testInterval, Probe: okProbe})
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic when nowFn is invoked.
	w.BeatScanner()
	if w.scannerBeat.Load() == 0 {
		t.Fatalf("BeatScanner did not store time")
	}
}

func TestSnapshot_AllHealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	snap := w.Snapshot(ctx, allAlive)
	if !snap.Healthy {
		t.Fatalf("expected Healthy=true, got %+v", snap)
	}
	for _, key := range []string{SubsystemScanner, SubsystemConfig, SubsystemSession, SubsystemKillSwitch, SubsystemWatchdog} {
		if !snap.Subsystems[key] {
			t.Errorf("subsystem %q expected true, got false", key)
		}
	}
}

func TestSnapshot_ScannerStale_ProbeOK_RebeatsAndHealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	probe := &recordingProbe{}
	w := mustNew(t, Config{Interval: testInterval, Probe: probe.Call, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	// Age the scanner heartbeat past the threshold.
	clock.Advance(4 * testInterval)

	// First Snapshot: scanner beat stale → probe runs → healthy.
	// But watchdog beat is also stale because goroutine stopped — split that
	// out by re-seeding selfBeat to "now" so we can isolate the scanner path.
	w.selfBeat.Store(clock.Now().UnixNano())

	snap := w.Snapshot(ctx, allAlive)
	if !snap.Subsystems[SubsystemScanner] {
		t.Fatalf("expected scanner healthy after successful probe, got %+v", snap)
	}
	if got := probe.calls.Load(); got != 1 {
		t.Fatalf("expected probe called once, got %d", got)
	}

	// Probe should have wrapped a deadline ≤ Interval/2 from clock.Now.
	probe.mu.Lock()
	if !probe.hadDL {
		t.Fatalf("probe context had no deadline")
	}
	probe.mu.Unlock()

	// Second Snapshot: scanner beat was refreshed by the successful probe,
	// so probe must NOT be called again.
	snap2 := w.Snapshot(ctx, allAlive)
	if !snap2.Subsystems[SubsystemScanner] {
		t.Fatalf("expected scanner still healthy")
	}
	if got := probe.calls.Load(); got != 1 {
		t.Fatalf("expected probe still called once after re-beat, got %d", got)
	}
}

func TestSnapshot_ScannerStale_ProbeFails_Unhealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: errProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()
	w.selfBeat.Store(clock.Now().UnixNano()) // isolate from watchdog staleness

	clock.Advance(4 * testInterval)
	snap := w.Snapshot(ctx, allAlive)
	if snap.Healthy {
		t.Fatalf("expected Healthy=false")
	}
	if snap.Subsystems[SubsystemScanner] {
		t.Fatalf("expected scanner=false, got %+v", snap)
	}
	// Other subsystems should remain healthy.
	if !snap.Subsystems[SubsystemConfig] || !snap.Subsystems[SubsystemSession] || !snap.Subsystems[SubsystemKillSwitch] {
		t.Fatalf("unexpected cascading unhealth: %+v", snap)
	}
}

func TestSnapshot_ScannerPtrNil_ProbeNotCalled(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	probe := &recordingProbe{}
	w := mustNew(t, Config{Interval: testInterval, Probe: probe.Call, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	in := allAlive
	in.ScannerPtrAlive = false
	snap := w.Snapshot(ctx, in)
	if snap.Subsystems[SubsystemScanner] {
		t.Fatalf("expected scanner=false when pointer nil")
	}
	if got := probe.calls.Load(); got != 0 {
		t.Fatalf("probe called %d times when pointer nil; expected 0", got)
	}
}

func TestSnapshot_ConfigPtrNil_CascadesToScanner(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	probe := &recordingProbe{}
	w := mustNew(t, Config{Interval: testInterval, Probe: probe.Call, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	in := allAlive
	in.ConfigPtrAlive = false
	snap := w.Snapshot(ctx, in)
	if snap.Subsystems[SubsystemConfig] {
		t.Fatalf("expected config=false")
	}
	if snap.Subsystems[SubsystemScanner] {
		t.Fatalf("expected scanner=false (cascaded from config nil)")
	}
	if got := probe.calls.Load(); got != 0 {
		t.Fatalf("probe called %d times when config nil; expected 0", got)
	}
}

func TestSnapshot_SessionDisabled_AlwaysHealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	in := allAlive // SessionEnabled=false, SessionPtrAlive=false
	snap := w.Snapshot(ctx, in)
	if !snap.Subsystems[SubsystemSession] {
		t.Fatalf("expected session=true when profiling disabled")
	}
}

func TestSnapshot_SessionEnabled_PtrNil_Unhealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	in := allAlive
	in.SessionEnabled = true
	in.SessionPtrAlive = false
	snap := w.Snapshot(ctx, in)
	if snap.Subsystems[SubsystemSession] {
		t.Fatalf("expected session=false when enabled-but-nil")
	}
}

func TestSnapshot_KillSwitchEnabledButAbsent_Unhealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	in := allAlive
	in.KillSwitchEnabled = true
	in.KillSwitchPresent = false
	snap := w.Snapshot(ctx, in)
	if snap.Subsystems[SubsystemKillSwitch] {
		t.Fatalf("expected killswitch=false when enabled-but-absent")
	}
	if snap.Healthy {
		t.Fatalf("expected overall unhealthy")
	}
}

func TestSnapshot_KillSwitchDisabled_Healthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()

	in := allAlive
	in.KillSwitchEnabled = false
	in.KillSwitchPresent = false
	snap := w.Snapshot(ctx, in)
	if !snap.Subsystems[SubsystemKillSwitch] {
		t.Fatalf("expected killswitch=true when disabled (subsystem not in use)")
	}
}

func TestSnapshot_WatchdogGoroutineDeath_FlipsUnhealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop() // simulate goroutine death

	// Immediately after Stop, selfBeat is fresh from Start seed → healthy.
	snap := w.Snapshot(ctx, allAlive)
	if !snap.Subsystems[SubsystemWatchdog] {
		t.Fatalf("expected watchdog fresh right after Stop")
	}

	// Advance fake clock past staleAfter (3 × interval). With the goroutine
	// stopped, no further selfBeat updates happen.
	clock.Advance(4 * testInterval)
	snap = w.Snapshot(ctx, allAlive)
	if snap.Subsystems[SubsystemWatchdog] {
		t.Fatalf("expected watchdog=false after goroutine death")
	}
	if snap.Healthy {
		t.Fatalf("expected overall unhealthy on watchdog death")
	}
}

func TestProbe_ContextHasIntervalHalfDeadline(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	probe := &recordingProbe{}
	w := mustNew(t, Config{Interval: testInterval, Probe: probe.Call, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()
	w.selfBeat.Store(clock.Now().UnixNano())

	// Force probe path.
	clock.Advance(4 * testInterval)
	beforeNow := time.Now()
	_ = w.Snapshot(ctx, allAlive)

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if !probe.hadDL {
		t.Fatalf("probe got no deadline")
	}
	// Deadline should be roughly within Interval/2 of real now (timeouts use
	// real clock; nowFn only governs heartbeat math).
	maxDeadline := beforeNow.Add(testInterval/2 + 50*time.Millisecond)
	if probe.deadline.After(maxDeadline) {
		t.Fatalf("probe deadline %v exceeds Interval/2 budget (max %v)", probe.deadline, maxDeadline)
	}
}

func TestProbe_HangingScanner_TimesOutToUnhealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: 20 * time.Millisecond, Probe: hangProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()
	w.selfBeat.Store(clock.Now().UnixNano())

	// Force probe path.
	clock.Advance(4 * 20 * time.Millisecond)

	snap := w.Snapshot(ctx, allAlive)
	if snap.Subsystems[SubsystemScanner] {
		t.Fatalf("expected scanner=false on probe timeout")
	}
	if snap.Healthy {
		t.Fatalf("expected unhealthy")
	}
}

func TestStartIdempotent(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Start(ctx) // must not double-launch or panic
	w.Stop()
}

func TestStopBeforeStart_NoOp(t *testing.T) {
	t.Parallel()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe})
	w.Stop() // must not block or panic
}

func TestStopTwice_SecondCallReturns(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()
	w.Stop() // must not block or panic
}

func TestBeatMethods_StoreUniqueTimes(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})

	w.BeatScanner()
	scannerT := w.scannerBeat.Load()

	clock.Advance(time.Second)
	w.BeatConfig()
	configT := w.configBeat.Load()

	clock.Advance(time.Second)
	w.BeatSession()
	sessionT := w.sessionBeat.Load()

	clock.Advance(time.Second)
	w.BeatKillSwitch()
	ksT := w.killSwitchBeat.Load()

	if scannerT >= configT || configT >= sessionT || sessionT >= ksT {
		t.Fatalf("expected monotonic beats: scanner=%d config=%d session=%d ks=%d", scannerT, configT, sessionT, ksT)
	}
}

func TestInterval_Getter(t *testing.T) {
	t.Parallel()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe})
	if got := w.Interval(); got != testInterval {
		t.Fatalf("Interval()=%v want %v", got, testInterval)
	}
}

func TestSnapshot_NeverStarted_WatchdogReportsHealthy(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	w := mustNew(t, Config{Interval: testInterval, Probe: okProbe, NowFn: clock.Now})

	// Construct only — no Start. Tests that exercise handlers without the
	// full proxy lifecycle hit this path. Watchdog must report healthy
	// because there is no goroutine that should be bumping selfBeat.
	snap := w.Snapshot(context.Background(), allAlive)
	if !snap.Subsystems[SubsystemWatchdog] {
		t.Fatalf("expected watchdog=true when never Started, got %+v", snap)
	}
	// Even after a long fake-clock advance, the not-started signal stays.
	clock.Advance(time.Hour)
	snap = w.Snapshot(context.Background(), allAlive)
	if !snap.Subsystems[SubsystemWatchdog] {
		t.Fatalf("expected watchdog=true after never-started + long advance, got %+v", snap)
	}
}

func TestAgeScannerForTest_BackdatesBeat(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	probe := &recordingProbe{}
	w := mustNew(t, Config{Interval: testInterval, Probe: probe.Call, NowFn: clock.Now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	w.Stop()
	w.selfBeat.Store(clock.Now().UnixNano()) // isolate from watchdog staleness

	// Without aging, Snapshot uses the fresh seeded heartbeat — no probe.
	_ = w.Snapshot(ctx, allAlive)
	if probe.calls.Load() != 0 {
		t.Fatalf("probe ran without aging; expected 0 calls, got %d", probe.calls.Load())
	}

	// Age the scanner beat past staleAfter (3 × testInterval). Next Snapshot
	// should see staleness and run the probe.
	w.AgeScannerForTest(4 * testInterval)
	_ = w.Snapshot(ctx, allAlive)
	if probe.calls.Load() != 1 {
		t.Fatalf("probe expected 1 call after AgeScannerForTest, got %d", probe.calls.Load())
	}
}

func TestGoroutineBumpsSelfBeat(t *testing.T) {
	// Real time, very small interval. Single integration check that the
	// goroutine actually does its job. No time.Sleep; we poll the atomic
	// with a generous deadline and exit as soon as it advances.
	t.Parallel()
	w, err := New(Config{Interval: 5 * time.Millisecond, Probe: okProbe})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	defer w.Stop()

	initial := w.selfBeat.Load()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if w.selfBeat.Load() > initial {
			return
		}
		// Yield without sleeping — the ticker fires on real wallclock.
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
			t.Fatal("ctx canceled during poll")
		}
	}
	t.Fatalf("selfBeat never advanced: initial=%d final=%d", initial, w.selfBeat.Load())
}

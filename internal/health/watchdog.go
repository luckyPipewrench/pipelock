// Package health provides a wedge-detection watchdog for pipelock.
//
// The /health endpoint historically answered 200 as long as the HTTP handler
// itself responded, even if internal subsystems were deadlocked. This package
// adds liveness signals: the scanner bumps a heartbeat on normal-path scan
// completion, the watchdog itself ticks a self-heartbeat, and Snapshot combines
// those timestamps with proxy-supplied subsystem presence checks that /health
// uses to set its status code (503 when any subsystem is unhealthy).
//
// Detection is hybrid:
//
//   - The scanner heartbeat is the cheap normal-path signal: each Scan()
//     completion performs one atomic store.
//   - A bounded synthetic probe runs only when the scanner heartbeat is stale.
//     This distinguishes a quiet-idle system from a wedged one without
//     poisoning every /health call with a probe.
//   - Config, session, and kill-switch checks are structural presence checks
//     supplied by the proxy: optional subsystems are healthy when disabled, and
//     required subsystems are unhealthy when their live pointer is missing.
//
// The watchdog goroutine is intentionally minimal: it stores time.Now into an
// atomic on each tick and otherwise does nothing. If it dies, its self-beat
// ages out and /health flips to 503 even if every other subsystem looks fine.
package health

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Subsystem name keys returned in Snapshot.Subsystems. Stable for probes and
// dashboards; do not rename without coordinating with KiloClaw integration.
const (
	SubsystemScanner    = "scanner"
	SubsystemConfig     = "config"
	SubsystemSession    = "session"
	SubsystemKillSwitch = "killswitch"
	SubsystemWatchdog   = "watchdog"
)

// Probe is a synthetic scanner call. It must respect ctx and return a
// non-nil error on timeout or scanner unavailability. Any non-nil error from
// Probe is treated as a wedge indicator.
type Probe func(ctx context.Context) error

// SnapshotInput carries live presence state from the calling Proxy. The
// watchdog cannot read these directly without taking a dependency on the
// proxy package; passing them in keeps internal/health acyclic.
//
// SessionEnabled and KillSwitchEnabled mirror config-side opt-in flags. When
// false, the corresponding subsystem is considered healthy regardless of
// its pointer state — the operator legitimately turned the feature off, so
// a missing controller is normal, not wedged. When the flag is true the
// pointer must be wired or the subsystem reports unhealthy.
type SnapshotInput struct {
	ScannerPtrAlive   bool // proxy.scannerPtr.Load() != nil
	ConfigPtrAlive    bool // proxy.cfgPtr.Load() != nil
	SessionEnabled    bool // session profiling configured at all
	SessionPtrAlive   bool // proxy.sessionMgrPtr.Load() != nil; ignored when !SessionEnabled
	KillSwitchEnabled bool // cfg.KillSwitch.Enabled
	KillSwitchPresent bool // proxy.ks != nil; ignored when !KillSwitchEnabled
}

// Snapshot is the watchdog's view of system liveness. Healthy is the AND of
// every value in Subsystems.
type Snapshot struct {
	Healthy    bool
	Subsystems map[string]bool
}

// Config configures a Watchdog at construction.
type Config struct {
	// Interval is the self-beat tick rate and the basis for the staleness
	// threshold (3 × Interval). Required, must be > 0.
	Interval time.Duration
	// Probe is the synthetic scanner check invoked when the scanner
	// heartbeat is stale. Required.
	Probe Probe
	// NowFn is an injectable clock; defaults to time.Now. Tests use this
	// to control staleness without time.Sleep.
	NowFn func() time.Time
}

// Watchdog tracks per-subsystem heartbeats and answers Snapshot for the
// /health endpoint. The zero value is unusable; call New.
type Watchdog struct {
	interval   time.Duration
	staleAfter time.Duration
	probe      Probe
	nowFn      func() time.Time

	scannerBeat    atomic.Int64
	configBeat     atomic.Int64
	sessionBeat    atomic.Int64
	killSwitchBeat atomic.Int64
	selfBeat       atomic.Int64

	// startedOnce flips true the first time Start is called and never goes
	// back. Snapshot uses this so a Watchdog constructed but never Started
	// (common in unit tests that exercise handlers without the full proxy
	// lifecycle) reports watchdog=true — there is no goroutine that should
	// be running, so there is no signal to be stale. Once Start is called,
	// staleness on selfBeat means the goroutine died (or was deliberately
	// Stopped, which we treat the same: no further heartbeats expected).
	startedOnce atomic.Bool

	startMu sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New constructs a Watchdog. Returns an error if cfg is invalid.
func New(cfg Config) (*Watchdog, error) {
	if cfg.Interval <= 0 {
		return nil, errors.New("health: Interval must be > 0")
	}
	if cfg.Probe == nil {
		return nil, errors.New("health: Probe is required")
	}
	nowFn := cfg.NowFn
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Watchdog{
		interval:   cfg.Interval,
		staleAfter: 3 * cfg.Interval,
		probe:      cfg.Probe,
		nowFn:      nowFn,
		done:       make(chan struct{}),
	}, nil
}

// Start seeds every heartbeat to the current clock value and launches the
// self-beat goroutine. Idempotent; subsequent calls are no-ops while the
// goroutine is running. Stop must be called to halt it.
//
// Seeding prevents a cold-start system from reporting unhealthy before any
// real traffic has arrived.
func (w *Watchdog) Start(parent context.Context) {
	w.startMu.Lock()
	defer w.startMu.Unlock()
	if w.started {
		return
	}
	w.started = true
	w.startedOnce.Store(true)

	now := w.nowFn().UnixNano()
	w.scannerBeat.Store(now)
	w.configBeat.Store(now)
	w.sessionBeat.Store(now)
	w.killSwitchBeat.Store(now)
	w.selfBeat.Store(now)

	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel

	go w.tick(ctx)
}

// Stop cancels the self-beat goroutine and blocks until it exits. Safe to
// call before Start (no-op) or twice (second call returns immediately).
func (w *Watchdog) Stop() {
	w.startMu.Lock()
	cancel := w.cancel
	w.cancel = nil
	w.startMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-w.done
}

func (w *Watchdog) tick(ctx context.Context) {
	defer close(w.done)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.selfBeat.Store(w.nowFn().UnixNano())
		}
	}
}

// BeatScanner records that the scanner just completed a scan. Cheap; safe
// to call from every Scanner.Scan completion.
func (w *Watchdog) BeatScanner() { w.scannerBeat.Store(w.nowFn().UnixNano()) }

// BeatConfig records a successful config load or reload.
func (w *Watchdog) BeatConfig() { w.configBeat.Store(w.nowFn().UnixNano()) }

// BeatSession records session-manager activity.
func (w *Watchdog) BeatSession() { w.sessionBeat.Store(w.nowFn().UnixNano()) }

// BeatKillSwitch records kill-switch state observation.
func (w *Watchdog) BeatKillSwitch() { w.killSwitchBeat.Store(w.nowFn().UnixNano()) }

// Interval returns the configured tick interval; useful for callers that
// want to budget probe timeouts as a fraction of it.
func (w *Watchdog) Interval() time.Duration { return w.interval }

// AgeScannerForTest backdates the scanner heartbeat by d so the next
// Snapshot sees it as stale. Test-only helper: the suffix marks intent.
// Production code paths use BeatScanner to record activity; nothing
// production should ever subtract from a heartbeat.
func (w *Watchdog) AgeScannerForTest(d time.Duration) {
	w.scannerBeat.Add(-d.Nanoseconds())
}

// Snapshot returns the current per-subsystem liveness map. The scanner
// uses the hybrid rule: pointer alive AND (fresh heartbeat OR probe returns
// nil within Interval/2). Config / session / killswitch are presence
// checks. Watchdog is healthy iff its self-heartbeat is fresh — if the
// goroutine dies, this flips to false within staleAfter.
//
// On a successful probe Snapshot re-beats the scanner so subsequent /health
// calls do not re-pay the probe cost until the heartbeat ages out again.
func (w *Watchdog) Snapshot(ctx context.Context, in SnapshotInput) Snapshot {
	now := w.nowFn().UnixNano()
	threshold := w.staleAfter.Nanoseconds()

	sub := make(map[string]bool, 5)
	if !w.startedOnce.Load() {
		// Constructed but never Started (test path that exercises the
		// handler without the full proxy lifecycle). No goroutine is
		// expected to bump selfBeat, so there is nothing to be stale.
		sub[SubsystemWatchdog] = true
	} else {
		sub[SubsystemWatchdog] = (now - w.selfBeat.Load()) < threshold
	}
	sub[SubsystemConfig] = in.ConfigPtrAlive
	if in.KillSwitchEnabled {
		sub[SubsystemKillSwitch] = in.KillSwitchPresent
	} else {
		sub[SubsystemKillSwitch] = true
	}
	if in.SessionEnabled {
		sub[SubsystemSession] = in.SessionPtrAlive
	} else {
		sub[SubsystemSession] = true
	}

	switch {
	case !in.ScannerPtrAlive || !in.ConfigPtrAlive:
		// Pointer first: a missing scanner or config is structurally
		// broken regardless of how recent the last beat was.
		sub[SubsystemScanner] = false
	case (now - w.scannerBeat.Load()) < threshold:
		sub[SubsystemScanner] = true
	default:
		// Beat stale, pointers alive: probe synthetically with an
		// Interval/2 budget. On success re-beat so /health does not
		// re-probe on every call.
		probeCtx, cancel := context.WithTimeout(ctx, w.interval/2)
		err := w.probe(probeCtx)
		cancel()
		if err == nil {
			w.scannerBeat.Store(now)
			sub[SubsystemScanner] = true
		} else {
			sub[SubsystemScanner] = false
		}
	}

	healthy := true
	for _, ok := range sub {
		if !ok {
			healthy = false
			break
		}
	}
	return Snapshot{Healthy: healthy, Subsystems: sub}
}

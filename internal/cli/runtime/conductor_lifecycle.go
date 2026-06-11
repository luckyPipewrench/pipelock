// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"sync/atomic"
)

// reloadCompletedHook is a test-only seam invoked after every config reload
// cycle (see the reloader consumer loop in Start). Reload tests block on it so
// they wait for the actual reload EVENT rather than polling stderr against a
// wall-clock deadline: under CI load fsnotify delivery latency made a fixed poll
// deadline the gating factor and the reload-test family flaky. nil in
// production, so this adds one nil-load per reload and nothing else.
var reloadCompletedHook atomic.Pointer[func()]

// SetReloadCompletedHookForTest installs fn to be called once per completed
// config reload cycle, returning a restore func. Pass nil to clear. Test-only;
// not safe for concurrent (t.Parallel) reload tests because the hook is process
// global.
func SetReloadCompletedHookForTest(fn func()) (restore func()) {
	prev := reloadCompletedHook.Load()
	if fn == nil {
		reloadCompletedHook.Store(nil)
	} else {
		reloadCompletedHook.Store(&fn)
	}
	return func() { reloadCompletedHook.Store(prev) }
}

func fireReloadCompletedHook() {
	if p := reloadCompletedHook.Load(); p != nil {
		(*p)()
	}
}

// setConductorCancel publishes the cancel func for the follower-side Conductor
// sub-context so teardownConductor can stop the pollers on a runtime
// fleet-license revocation. Called from Start before the pollers launch. Lives
// in the untagged file because runtime license enforcement (CRL watcher, expiry
// timer, reload path) must compile on both the Apache-only core and the
// enterprise build; the conductor handles are nil on core, so teardown is a
// no-op there.
func (s *Server) setConductorCancel(cancel context.CancelFunc) {
	if s == nil {
		return
	}
	s.conductorLifeMu.Lock()
	s.conductorCancel = cancel
	cancelNow := s.conductorDown.Load()
	s.conductorLifeMu.Unlock()
	if cancelNow && cancel != nil {
		cancel()
	}
}

func (s *Server) setConductorWait(wait func()) {
	if s == nil {
		return
	}
	s.conductorLifeMu.Lock()
	s.conductorWait = wait
	s.conductorLifeMu.Unlock()
}

// teardownConductor fail-closes the follower-side Conductor runtime when its
// fleet entitlement is revoked, expires, or is downgraded at runtime. It cancels
// the poller goroutines, detaches the durable-audit observer, closes the audit
// producer, waits for the pollers to stop, then releases the audit queue lock.
// The proxy/detection path is deliberately left running: losing a paid fleet
// entitlement must never take down free detection (the product rule is "sell
// coordination, not detection"). Idempotent and safe to call concurrently from
// the runtime CRL watcher, the expiry timer, and the config reload path.
// Conductor stays down until process restart, matching the restart-only
// conductor invariant.
func (s *Server) teardownConductor(reason string) {
	if s == nil {
		return
	}
	s.conductorLifeMu.Lock()
	// If no Conductor handles or cancel func exist, the follower runtime never
	// launched (e.g. conductor disabled, or the Apache-only core build); there
	// is nothing to tear down. conductorDown already set means a prior teardown
	// won the race.
	if s.conductorDown.Load() || (s.conductorCancel == nil && !s.hasConductorRuntime()) {
		s.conductorLifeMu.Unlock()
		return
	}
	s.conductorDown.Store(true)
	cancel := s.conductorCancel
	wait := s.conductorWait
	s.conductorWait = nil
	// Take ownership of the producer under the lock and clear the field so it is
	// closed exactly once and never reused after teardown. conductorDown is
	// already set, so a racing teardown bails at the guard above and a later
	// hasConductorRuntime() check never sees the closed handle.
	producer := s.conductorProducer
	s.conductorProducer = nil
	// Take ownership of the audit queue too so its single-writer lock is
	// released on teardown (and only once). On the Apache-only core build the
	// field is always nil; on enterprise it holds an *auditbatcher.Queue, which
	// satisfies io.Closer. Asserting the interface keeps this untagged file free
	// of an enterprise import.
	auditQueue := s.conductorAuditQueue
	s.conductorAuditQueue = nil
	s.conductorLifeMu.Unlock()

	// Fail closed on strict stale policy BEFORE cancelling the pollers. The
	// stale enforcer's ticker is about to stop and can never re-engage once the
	// fleet entitlement is permanently gone; a strict follower whose active
	// bundle later ages past grace would otherwise serve stale config forever.
	// Engage the conductor_stale kill-switch source now so the deny is in place
	// before the enforcer dies, closing the teardown fail-open window. This is an
	// independent OR-composed source: it stays engaged regardless of any later
	// clear of conductor_remote. Under continue_last_known_good the flag is false
	// and the existing serve-last-config semantics are preserved.
	if s.conductorStaleStrictDeny.Load() && s.killswitch != nil {
		s.killswitch.SetConductorStale(true,
			"conductor fleet entitlement lost under strict stale policy; denying all traffic (fail-closed)")
	}
	// Stop the follower pollers. Their Run loops return context.Canceled, which
	// the Start error branches treat as a clean stop (no process-wide cancel).
	if cancel != nil {
		cancel()
	}
	// Detach the durable-audit observer BEFORE closing the producer. SetObserver
	// synchronizes on the recorder mutex, so once it returns no in-flight Record
	// can still call the producer, making Close race-free. The recorder keeps
	// recording locally; only the Conductor audit fan-out stops.
	if s.recorder != nil {
		s.recorder.SetObserver(nil)
	}
	if producer != nil {
		_ = producer.Close()
	}
	// The audit transport owns Claim/Ack/Release/Drop. Wait for it to observe the
	// cancelled conductor context before releasing the queue lock, otherwise a
	// replacement process could Open the same dir while this process still has a
	// leased record in flight.
	if wait != nil {
		wait()
	}
	// Release the durable audit queue's single-writer lock after producers and
	// transports have stopped touching it.
	closeConductorAuditQueue(auditQueue)
	if s.opts.Stderr != nil {
		_, _ = fmt.Fprintf(s.opts.Stderr,
			"pipelock: fleet license %s; Conductor runtime stopped, detection continues\n", reason)
	}
}

func closeConductorAuditQueue(auditQueue any) {
	if closer, ok := auditQueue.(interface{ Close() error }); ok && closer != nil {
		_ = closer.Close()
	}
}

func (s *Server) hasConductorRuntime() bool {
	return s.conductorApply != nil ||
		s.conductorAuditQueue != nil ||
		s.conductorAudit != nil ||
		s.conductorRemoteKill != nil ||
		s.conductorBundle != nil ||
		s.conductorStale != nil ||
		s.conductorProducer != nil
}

// expireLicensedRuntime tears down every license-gated runtime surface when the
// license expires: agent listeners (Pro) and the follower-side Conductor runtime
// (Enterprise). Both teardowns are safe no-ops when the corresponding surface is
// not running, so the expiry timer can call this unconditionally.
func (s *Server) expireLicensedRuntime() {
	if s == nil {
		return
	}
	if s.proxy != nil {
		s.proxy.ShutdownAgentServers()
	}
	s.teardownConductor("expired")
	if s.opts.Stderr != nil {
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: license expired, licensed runtime surfaces stopped\n")
	}
}

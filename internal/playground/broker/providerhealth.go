// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ProviderState is the coarse, operator-facing verdict on whether the broker can
// currently reach and use its machine provider.
type ProviderState string

const (
	// ProviderStateUnknown means no provider call has completed yet. It is a
	// startup-only state: the orphan reaper reconciles unconditionally, so a
	// running broker leaves "unknown" within one reaper interval even when the
	// warm pool is disabled.
	ProviderStateUnknown ProviderState = "unknown"
	// ProviderStateOK means the last provider call succeeded.
	ProviderStateOK ProviderState = "ok"
	// ProviderStateDegraded means calls are failing but not yet enough
	// consecutive failures to call the provider unusable.
	ProviderStateDegraded ProviderState = "degraded"
	// ProviderStateFailing means providerFailingThreshold consecutive calls have
	// failed. The broker cannot create sandboxes; visitor sessions are failing.
	ProviderStateFailing ProviderState = "failing"
)

const (
	// providerFailingThreshold is how many consecutive provider failures before
	// the broker declares itself unable to serve. Kept small so a genuine
	// outage surfaces in seconds, but above 1 so a single transient blip does
	// not page an operator.
	providerFailingThreshold = 3

	// providerBackoffBase is the first backoff delay after a failure, and
	// providerBackoffMax caps the exponential growth.
	//
	// WHY THIS EXISTS: a persistently rejected credential previously produced a
	// 2-second retry loop that ran for five days (~86k rejected API calls/day).
	// Backoff converts that into ~288 calls/day at the cap while still
	// recovering automatically within five minutes of the provider returning.
	providerBackoffBase = 5 * time.Second
	providerBackoffMax  = 5 * time.Minute

	// providerErrMaxLen bounds the stored error string. It is kept in the
	// snapshot for internal callers, so it is truncated and never assumed short.
	providerErrMaxLen = 200
)

// ProviderHealth records the outcome of machine-provider calls so that
//
//  1. /api/live/health can report whether the broker can actually create
//     sandboxes, instead of reporting only on its own internal counters, and
//  2. the warm-pool maintainer can back off instead of hot-looping against a
//     failure that will not clear on its own.
//
// It is safe for concurrent use.
//
// DELIBERATELY NOT A CIRCUIT BREAKER ON THE VISITOR PATH: this type records and
// advises, it never blocks a call. The warm pool consults it; the visitor's
// cold-lease path does not. Denying a visitor's session because earlier
// background calls failed would turn a cost optimisation into an outage, and a
// visitor request may well be the call that succeeds. A visitor still gets a
// real attempt and, if it genuinely fails, a real error.
type ProviderHealth struct {
	now func() time.Time
	log io.Writer

	mu    sync.Mutex
	logMu sync.Mutex

	consecutiveFailures int
	lastErr             string
	lastErrAt           time.Time
	lastOKAt            time.Time
	backoffUntil        time.Time
	// provisioningFailure is set when CreateMachine failed. A successful
	// list/destroy proves API reachability, but it does not prove the provider
	// can create a visitor sandbox, so background success must not clear it.
	provisioningFailure bool
	// announcedFailing ensures the transition into "failing" is logged once,
	// not on every retry. Without this the loud signal is itself the log spam.
	announcedFailing bool
}

// NewProviderHealth returns a tracker. now may be nil (uses time.Now); log may
// be nil (discards).
func NewProviderHealth(now func() time.Time, log io.Writer) *ProviderHealth {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = io.Discard
	}
	return &ProviderHealth{now: now, log: log}
}

// RecordSuccess clears the failure streak and any active backoff.
func (h *ProviderHealth) RecordSuccess() {
	if h == nil {
		return
	}
	h.mu.Lock()
	recovered := h.announcedFailing
	h.consecutiveFailures = 0
	h.lastErr = ""
	h.backoffUntil = time.Time{}
	h.lastOKAt = h.now()
	h.announcedFailing = false
	h.provisioningFailure = false
	h.mu.Unlock()
	if recovered {
		h.logRecovered()
	}
}

// RecordBackgroundSuccess clears failures caused by background provider work,
// but never lets list/destroy success hide a failed sandbox creation.
func (h *ProviderHealth) RecordBackgroundSuccess() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.provisioningFailure {
		h.mu.Unlock()
		return
	}
	recovered := h.announcedFailing
	h.consecutiveFailures = 0
	h.lastErr = ""
	h.backoffUntil = time.Time{}
	h.lastOKAt = h.now()
	h.announcedFailing = false
	h.mu.Unlock()
	if recovered {
		h.logRecovered()
	}
}

// RecordFailure counts a failed provider call and extends the backoff window.
//
// Context cancellation is NOT counted: a cancelled call is the broker shutting
// down, not evidence that the provider is unusable. DeadlineExceeded IS counted:
// a provider operation that cannot finish inside its bounded deadline is an
// availability failure and must not leave provider health looking OK.
func (h *ProviderHealth) RecordFailure(err error) {
	h.recordFailure(err, true)
}

// RecordBackgroundFailure records list/destroy failures without classifying
// them as a failed provisioning attempt.
func (h *ProviderHealth) RecordBackgroundFailure(err error) {
	h.recordFailure(err, false)
}

func (h *ProviderHealth) recordFailure(err error, provisioning bool) {
	if h == nil || err == nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	h.mu.Lock()
	h.consecutiveFailures++
	if provisioning {
		h.provisioningFailure = true
	}
	h.lastErr = truncateProviderErr(err.Error())
	h.lastErrAt = h.now()
	h.backoffUntil = h.now().Add(backoffFor(h.consecutiveFailures))
	announce := h.consecutiveFailures >= providerFailingThreshold && !h.announcedFailing
	failures := h.consecutiveFailures
	provisioningFailure := h.provisioningFailure
	if announce {
		h.announcedFailing = true
	}
	h.mu.Unlock()
	if announce {
		if provisioningFailure {
			h.writeLog(
				"provider: FAILING after %d consecutive errors; broker cannot create sandboxes\n",
				failures)
		} else {
			h.writeLog("provider: FAILING after %d consecutive background errors\n", failures)
		}
	}
}

// logRecovered emits the shared recovery transition after the state lock is released.
func (h *ProviderHealth) logRecovered() {
	h.writeLog("provider: recovered; machine provider reachable again\n")
}

func (h *ProviderHealth) writeLog(format string, args ...any) {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	_, _ = fmt.Fprintf(h.log, format, args...)
}

// BackoffActive reports whether the caller should skip this round of background
// provider work, and until when.
func (h *ProviderHealth) BackoffActive() (until time.Time, active bool) {
	if h == nil {
		return time.Time{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.backoffUntil.IsZero() {
		return time.Time{}, false
	}
	if h.now().Before(h.backoffUntil) {
		return h.backoffUntil, true
	}
	return h.backoffUntil, false
}

// ProviderHealthSnapshot is an immutable view for the health endpoint.
type ProviderHealthSnapshot struct {
	OK                  bool
	State               ProviderState
	ConsecutiveFailures int
	LastErr             string
	LastErrAt           time.Time
	LastOKAt            time.Time
	BackoffUntil        time.Time
}

// Snapshot returns the current provider health.
//
// OK is true unless the provider is FAILING. "unknown" and "degraded" report OK
// so that a broker restart, or one transient blip, does not read as an outage;
// State carries the finer detail for an operator.
func (h *ProviderHealth) Snapshot() ProviderHealthSnapshot {
	if h == nil {
		return ProviderHealthSnapshot{OK: true, State: ProviderStateUnknown}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	state := ProviderStateUnknown
	switch {
	case h.consecutiveFailures >= providerFailingThreshold:
		state = ProviderStateFailing
	case h.consecutiveFailures > 0:
		state = ProviderStateDegraded
	case !h.lastOKAt.IsZero():
		state = ProviderStateOK
	}
	return ProviderHealthSnapshot{
		OK:                  state != ProviderStateFailing,
		State:               state,
		ConsecutiveFailures: h.consecutiveFailures,
		LastErr:             h.lastErr,
		LastErrAt:           h.lastErrAt,
		LastOKAt:            h.lastOKAt,
		BackoffUntil:        h.backoffUntil,
	}
}

func backoffFor(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := providerBackoffBase
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= providerBackoffMax {
			return providerBackoffMax
		}
	}
	if d > providerBackoffMax {
		return providerBackoffMax
	}
	return d
}

func truncateProviderErr(s string) string {
	if len(s) <= providerErrMaxLen {
		return s
	}
	return s[:providerErrMaxLen] + "..."
}

// healthTrackingProvider wraps a MachineProvider and feeds every reachability-
// relevant call outcome into a ProviderHealth.
//
// WHY A WRAPPER: the three independent consumers of the provider (warm pool,
// lease manager, orphan reaper) would otherwise each need their own bookkeeping
// calls, and any future consumer would silently not report. Wrapping means the
// reaper alone — which runs unconditionally every couple of minutes — is enough
// to keep provider health fresh even when the warm pool is disabled.
type healthTrackingProvider struct {
	inner  MachineProvider
	health *ProviderHealth
}

// NewHealthTrackingProvider wraps inner so its call outcomes update health.
// Returns inner unchanged when health is nil.
func NewHealthTrackingProvider(inner MachineProvider, health *ProviderHealth) MachineProvider {
	if health == nil {
		return inner
	}
	return &healthTrackingProvider{inner: inner, health: health}
}

func (p *healthTrackingProvider) CreateMachine(ctx context.Context, spec MachineSpec) (*Machine, error) {
	m, err := p.inner.CreateMachine(ctx, spec)
	if err != nil {
		p.health.RecordFailure(err)
	} else {
		p.health.RecordSuccess()
	}
	return m, err
}

func (p *healthTrackingProvider) DestroyMachine(ctx context.Context, id string) error {
	err := p.inner.DestroyMachine(ctx, id)
	p.recordBackground(err)
	return err
}

func (p *healthTrackingProvider) ListManagedMachines(ctx context.Context) ([]Machine, error) {
	ms, err := p.inner.ListManagedMachines(ctx)
	p.recordBackground(err)
	return ms, err
}

// WaitReady is deliberately NOT tracked. Its failure means a VM did not boot in
// time, which is a guest problem, not evidence that the provider API is
// unreachable or unauthorised. Counting it would let slow boots trip the
// provider-failing signal and mask the credential class of failure this tracker
// exists to catch.
func (p *healthTrackingProvider) WaitReady(ctx context.Context, id string) error {
	return p.inner.WaitReady(ctx, id)
}

func (p *healthTrackingProvider) recordBackground(err error) {
	if err != nil {
		p.health.RecordBackgroundFailure(err)
		return
	}
	p.health.RecordBackgroundSuccess()
}

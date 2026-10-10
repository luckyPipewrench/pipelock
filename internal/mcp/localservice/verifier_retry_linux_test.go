// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// attemptCounter counts verification attempts and signals the first one.
type attemptCounter struct {
	n      atomic.Int64
	first  chan struct{}
	second chan struct{}
}

func newAttemptCounter() *attemptCounter {
	return &attemptCounter{first: make(chan struct{}), second: make(chan struct{})}
}

func (a *attemptCounter) hook() {
	switch a.n.Add(1) {
	case 1:
		close(a.first)
	case 2:
		close(a.second)
	}
}

func (a *attemptCounter) waitFirst(t *testing.T) {
	t.Helper()
	a.wait(t, a.first)
}

// waitSecond returns once a second attempt has begun, which proves the first
// one finished and was retried.
func (a *attemptCounter) waitSecond(t *testing.T) {
	t.Helper()
	a.wait(t, a.second)
}

func (a *attemptCounter) wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(testwait.Deadline(30 * time.Second)):
		t.Fatal("timed out waiting for a verification attempt")
	}
}

type verifyResult struct {
	ev  Evidence
	err error
}

func verifyAsync(ctx context.Context, v *Verifier, h *helper, t *testing.T, pin Pin) <-chan verifyResult {
	t.Helper()
	conn := dialUnaccepted(t, h)
	out := make(chan verifyResult, 1)
	go func() {
		ev, err := v.VerifyConnContext(ctx, conn, pin)
		out <- verifyResult{ev, err}
	}()
	return out
}

func awaitResult(t *testing.T, ch <-chan verifyResult) verifyResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(testwait.Deadline(30 * time.Second)):
		t.Fatal("timed out waiting for VerifyConnContext to return")
	}
	return verifyResult{}
}

func TestVerifyConnContextRetriesUntilAccept(t *testing.T) {
	t.Parallel()
	h := startServer(t, modeLateAccept, loopbackAny)
	counter := newAttemptCounter()
	v := NewVerifier()
	v.onAttempt = counter.hook

	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(30*time.Second))
	defer cancel()
	res := verifyAsync(ctx, v, h, t, basePin(t))

	// The server has not accepted, so attempt one sees the pending state and a
	// second attempt begins; only then is the server told to accept.
	counter.waitSecond(t)
	h.acceptNow(t)

	r := awaitResult(t, res)
	if r.err != nil {
		t.Fatalf("VerifyConnContext = %v, want success once the server accepts", r.err)
	}
	if r.ev.PID != h.cmd.Process.Pid {
		t.Fatalf("evidence pid = %d, want %d", r.ev.PID, h.cmd.Process.Pid)
	}
	if got := counter.n.Load(); got < 2 {
		t.Fatalf("attempts = %d, want a retry before success", got)
	}
}

func TestVerifyConnContextNeverAcceptedFailsAtCap(t *testing.T) {
	t.Parallel()
	h := startServer(t, modeNoAccept, loopbackAny)
	counter := newAttemptCounter()
	v := NewVerifier()
	v.onAttempt = counter.hook
	v.retryCap = 100 * time.Millisecond

	r := awaitResult(t, verifyAsync(context.Background(), v, h, t, basePin(t)))
	if !errors.Is(r.err, ErrSocketNotFound) {
		t.Fatalf("VerifyConnContext = %v, want ErrSocketNotFound at the cap", r.err)
	}
	if r.ev.PID != 0 {
		t.Fatalf("failure returned evidence %+v", r.ev)
	}
	if got := counter.n.Load(); got < 2 {
		t.Fatalf("attempts = %d, want the pending state retried", got)
	}
}

func TestVerifyConnContextStopsWhenContextEnds(t *testing.T) {
	t.Parallel()
	h := startServer(t, modeNoAccept, loopbackAny)
	counter := newAttemptCounter()
	v := NewVerifier()
	v.onAttempt = counter.hook
	// The cap is far beyond the test deadline, so only cancellation can end it.
	v.retryCap = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := verifyAsync(ctx, v, h, t, basePin(t))
	counter.waitFirst(t)
	cancel()

	r := awaitResult(t, res)
	if !errors.Is(r.err, ErrSocketNotFound) {
		t.Fatalf("VerifyConnContext = %v, want the last pending error", r.err)
	}
}

func TestVerifyConnContextDoesNotRetryOtherErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pin     func(p *Pin)
		wantErr error
	}{
		{name: "principal mismatch", pin: func(p *Pin) { p.PrincipalUID++ }, wantErr: ErrPrincipalMismatch},
		{name: "executable mismatch", pin: func(p *Pin) { p.ExecutableSHA256 = testHashA }, wantErr: ErrApplicationMismatch},
		{name: "invalid pin", pin: func(p *Pin) { p.ExecutableSHA256 = "short" }, wantErr: ErrInvalidPin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := startServer(t, modeServe, loopbackAny)
			conn := dialAccepted(t, h, "")
			pin := basePin(t)
			tt.pin(&pin)

			counter := newAttemptCounter()
			v := NewVerifier()
			v.onAttempt = counter.hook
			v.retryCap = time.Hour

			_, err := v.VerifyConnContext(context.Background(), conn, pin)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyConnContext = %v, want %v", err, tt.wantErr)
			}
			if got := counter.n.Load(); got != 1 {
				t.Fatalf("attempts = %d, want exactly 1 (not retryable)", got)
			}
		})
	}
}

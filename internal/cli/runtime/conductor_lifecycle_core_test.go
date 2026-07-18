// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

type coreConductorCloser struct {
	closes atomic.Int32
	err    error
}

func (c *coreConductorCloser) Close() error {
	c.closes.Add(1)
	return c.err
}

type coreConductorRunner struct{}

func (coreConductorRunner) Run(context.Context) error { return nil }

func TestCoreConductorLifecycleHelpers(t *testing.T) {
	var calls atomic.Int32
	restore := SetReloadCompletedHookForTest(func() { calls.Add(1) })
	fireReloadCompletedHook()
	got := calls.Load()
	restore()
	if got != 1 {
		t.Fatalf("reload hook calls = %d, want 1", got)
	}
	fireReloadCompletedHook()
	if got := calls.Load(); got != 1 {
		t.Fatalf("reload hook calls after restore = %d, want unchanged 1", got)
	}

	errCloser := &coreConductorCloser{err: errors.New("ignored")}
	closeConductorAuditQueue(errCloser)
	closeConductorAuditQueue(struct{}{})
	if got := errCloser.closes.Load(); got != 1 {
		t.Fatalf("queue close count = %d, want 1", got)
	}

	if (&Server{}).hasConductorRuntime() {
		t.Fatal("empty server must not report conductor runtime")
	}
	if !(&Server{conductorRemoteKill: coreConductorRunner{}}).hasConductorRuntime() {
		t.Fatal("server with conductor runner must report conductor runtime")
	}
	if !(&Server{conductorProducer: &coreConductorCloser{}}).hasConductorRuntime() {
		t.Fatal("server with conductor producer must report conductor runtime")
	}
}

func TestCoreConductorExpireLicensedRuntimeStopsRuntime(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	producer := &coreConductorCloser{}
	queue := &coreConductorCloser{}
	var waited atomic.Bool
	var stderr bytes.Buffer
	s := &Server{
		opts:                ServerOpts{Stderr: &stderr},
		conductorProducer:   producer,
		conductorAuditQueue: queue,
	}
	s.setConductorCancel(cancel)
	s.setConductorWait(func() {
		if ctx.Err() == nil {
			t.Fatal("conductor wait ran before cancellation")
		}
		waited.Store(true)
	})

	s.expireLicensedRuntime()

	if !s.conductorDown.Load() {
		t.Fatal("expiry must mark conductor down")
	}
	if got := producer.closes.Load(); got != 1 {
		t.Fatalf("producer close count = %d, want 1", got)
	}
	if got := queue.closes.Load(); got != 1 {
		t.Fatalf("queue close count = %d, want 1", got)
	}
	if !waited.Load() {
		t.Fatal("expiry teardown must wait for conductor goroutines")
	}
	if !strings.Contains(stderr.String(), "license expired") {
		t.Fatalf("stderr = %q, want license expiry notice", stderr.String())
	}
}

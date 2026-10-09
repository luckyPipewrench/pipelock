// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sinkBody       = "ok"
	maxSinkSamples = 8
)

// sink is the local origin server. It records which workload key each request
// carried so the run can compare what reached the origin against the plan, one
// request at a time, instead of comparing aggregate counts.
type sink struct {
	plan     workload
	server   *http.Server
	listener net.Listener
	seen     []atomic.Int32

	unknown atomic.Int64

	mu      sync.Mutex
	samples []string
}

func startSink(ctx context.Context, plan workload) (*sink, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &sink{plan: plan, listener: listener, seen: make([]atomic.Int32, plan.total())}
	s.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(s.handle)}
	go func() { _ = s.server.Serve(listener) }()
	return s, nil
}

func (s *sink) addr() string { return s.listener.Addr().String() }

func (s *sink) handle(w http.ResponseWriter, r *http.Request) {
	key, _ := keyFromTarget(r.URL.String())
	s.record(key)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, sinkBody)
}

func (s *sink) record(key string) {
	slot, ok := s.plan.parseKey(key)
	if !ok {
		s.unknown.Add(1)
		s.mu.Lock()
		if len(s.samples) < maxSinkSamples {
			s.samples = append(s.samples, key)
		}
		s.mu.Unlock()
		return
	}
	s.seen[slot].Add(1)
}

func (s *sink) close() { _ = s.server.Shutdown(context.WithoutCancel(context.Background())) }

// hits returns how many requests reached the sink for each planned slot.
func (s *sink) hits() []int {
	out := make([]int, len(s.seen))
	for i := range s.seen {
		out[i] = int(s.seen[i].Load())
	}
	return out
}

// unknownSamples returns a bounded sample of keys the sink received that are
// not part of the plan.
func (s *sink) unknownSamples() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.samples...)
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// TestProbeConcurrent_PreservesOrderUnderOutOfOrderCompletion proves the
// containment proof's parallelization keeps results positionally aligned with
// targets even when probes COMPLETE out of order. Order is load-bearing:
// decodeProbeResults validates result[i] against target[i], and the differential
// proof relies on the control target being first. The probe for target 0 is
// gated to finish only after the last target has started, so completion order is
// the reverse of index order; the test fails if probeConcurrent returned results
// in completion order instead of target order. Runs under -race to catch any
// shared-state bug in the per-index writes.
func TestProbeConcurrent_PreservesOrderUnderOutOfOrderCompletion(t *testing.T) {
	t.Parallel()
	targets := []string{"t0", "t1", "t2", "t3", "t4"}
	gate := make(chan struct{})
	probe := func(_ context.Context, target string) playground.ProbeResult {
		switch target {
		case "t4":
			close(gate) // release t0 only once the last target has started
		case "t0":
			<-gate // forced to complete after t4
		}
		return playground.ProbeResult{Target: target, Open: target == "t2"}
	}
	results := probeConcurrent(context.Background(), targets, probe)
	if len(results) != len(targets) {
		t.Fatalf("got %d results, want %d", len(results), len(targets))
	}
	for i, tg := range targets {
		if results[i].Target != tg {
			t.Fatalf("results[%d].Target = %q, want %q (order not preserved across out-of-order completion)", i, results[i].Target, tg)
		}
	}
	if !results[2].Open {
		t.Fatalf("results[2] (t2) Open = false, want true (result content misaligned with index)")
	}
}

func TestRunProbe_OpenAndRefused(t *testing.T) {
	t.Parallel()

	// An open loopback listener (reachable) ...
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	openTarget := ln.Addr().String()

	// ... and a port nothing listens on. Connection refused is reachable, not
	// kernel containment.
	const closedTarget = "127.0.0.1:1"

	var out, errOut bytes.Buffer
	if err := runProbe(t.Context(), &out, &errOut, openTarget+", "+closedTarget); err != nil {
		t.Fatalf("runProbe: %v", err)
	}

	// stdout must carry ONLY the JSON results (no narration).
	if strings.Contains(out.String(), "[agent]") {
		t.Errorf("stdout leaked narration: %q", out.String())
	}

	var results []playground.ProbeResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("parse probe JSON %q: %v", out.String(), err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Target != openTarget || !results[0].Open {
		t.Errorf("open target: got %+v, want Open=true", results[0])
	}
	if results[0].Blocked {
		t.Errorf("open target: got Blocked=true")
	}
	if results[1].Target != closedTarget || results[1].Open || results[1].Blocked {
		t.Errorf("closed target: got %+v, want Open=false Blocked=false", results[1])
	}
}

func TestRunProbe_EmptyTargets(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	if err := runProbe(t.Context(), &out, &errOut, "  , ,"); err == nil {
		t.Fatal("expected error for empty target list")
	}
}

func TestRunLocalProbe_UnavailableUnixSocket(t *testing.T) {
	t.Parallel()

	const target = "unix:/tmp/pipelock-definitely-not-present.sock"
	var out, errOut bytes.Buffer
	if err := runLocalProbe(t.Context(), &out, &errOut, target); err != nil {
		t.Fatalf("runLocalProbe: %v", err)
	}
	if strings.Contains(out.String(), "[agent]") {
		t.Errorf("stdout leaked narration: %q", out.String())
	}

	var results []playground.ProbeResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("parse local probe JSON %q: %v", out.String(), err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Target != target || results[0].Open || !results[0].Blocked {
		t.Fatalf("local probe = %+v, want unavailable socket classified as blocked", results[0])
	}
}

func TestRunLocalProbe_EmptyTargets(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	if err := runLocalProbe(t.Context(), &out, &errOut, "  , ,"); err == nil {
		t.Fatal("expected error for empty local target list")
	}
}

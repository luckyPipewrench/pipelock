// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

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

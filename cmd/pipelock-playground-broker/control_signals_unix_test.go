// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestControlSignalsIncludesUnixControlSignals(t *testing.T) {
	got := controlSignals()
	want := map[os.Signal]bool{
		syscall.SIGUSR1: false,
		syscall.SIGUSR2: false,
		syscall.SIGTERM: false,
		syscall.SIGINT:  false,
	}
	for _, sig := range got {
		if _, ok := want[sig]; ok {
			want[sig] = true
		}
	}
	for sig, seen := range want {
		if !seen {
			t.Fatalf("controlSignals missing %v from %v", sig, got)
		}
	}
}

func TestApplyControlSignalPauseResume(t *testing.T) {
	srv := newBrokerControlTestServer(t)

	var out bytes.Buffer
	if shutdown := applyControlSignal(&out, srv, syscall.SIGUSR1); shutdown {
		t.Fatal("SIGUSR1 requested shutdown, want pause only")
	}
	if !srv.Killed() {
		t.Fatal("SIGUSR1 did not pause broker")
	}
	if shutdown := applyControlSignal(&out, srv, syscall.SIGUSR2); shutdown {
		t.Fatal("SIGUSR2 requested shutdown, want resume only")
	}
	if srv.Killed() {
		t.Fatal("SIGUSR2 did not resume broker")
	}
	if got := out.String(); !strings.Contains(got, "paused") || !strings.Contains(got, "resumed") {
		t.Fatalf("operator output = %q, want pause and resume messages", got)
	}
}

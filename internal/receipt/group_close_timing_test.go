// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestGroupCloseTiming(t *testing.T) {
	raw := os.Getenv("PIPELOCK_CLOSE_TIMING_RECORDS")
	if raw == "" {
		t.Skip("opt-in close timing")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		t.Fatalf("PIPELOCK_CLOSE_TIMING_RECORDS must be a non-negative integer representable as int: %q (parse error: %v)", raw, err)
	}
	_, key := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := set.Emit(set.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: fmt.Sprintf("https://api.vendor.example/%d", i)})); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range set.Emitters() {
		if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := e.EmitTranscriptRoot(e.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if path := os.Getenv("PIPELOCK_CLOSE_TIMING_PROFILE"); path != "" {
		f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if err := pprof.StartCPUProfile(f); err != nil {
			t.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}
	start := time.Now()
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
	t.Logf("close records=%d seconds=%.6f", n, time.Since(start).Seconds())
}

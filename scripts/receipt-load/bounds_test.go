// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSummaryRejectsFailedVerifier(t *testing.T) {
	root := t.TempDir()
	r := fakeResult(100, 90, 95, verdictPass, perfMeasured)
	putResult(t, root, 2, 1, 1, modeRequired, r)
	args := []string{"--root", root, "--modes", modeRequired, "--cpus", "2", "--chains", "1"}
	if _, err := summarizeCommand(args); err != nil {
		t.Fatal(err)
	}
	r.Integrity.Verify.Exit = 1
	putResult(t, root, 2, 1, 1, modeRequired, r)
	if code := realMain(append([]string{"summarize"}, args...)); code == exitOK {
		t.Fatal("failed verifier returned success")
	}
	row := readSummary(t, root)["2/1/required"]
	if row["integrity"] != verdictFail || row["integrity_failures"] != "1" || row["verify_failures"] != "1" || row["median_req_s"] != "" {
		t.Fatalf("failed verifier row: %v", row)
	}
}

func TestSummaryBoundsSamples(t *testing.T) {
	root := t.TempDir()
	for _, count := range []int{0, -1, maxSummarySamples + 1, int(^uint(0) >> 1)} {
		_, err := summarizeCommand([]string{"--root", root, "--samples", strconv.Itoa(count), "--modes", modeOff, "--cpus", "2", "--chains", "1"})
		if err == nil || !strings.Contains(err.Error(), "--samples") {
			t.Fatalf("sample bound %d: %v", count, err)
		}
		if err := writeSummary(summaryParams{root: root, samples: count}); err == nil {
			t.Fatalf("writeSummary accepted %d", count)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "summary.csv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid samples wrote summary: %v", err)
	}
}

func TestBundleLogBounds(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"line", strings.Repeat("x", 70*1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.log")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := bundleLogLines(path); err == nil {
				t.Fatal("oversized log accepted")
			}
		})
	}
}

func TestBundleLogBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       int
	}{
		{"empty", "", 0},
		{"matches", strings.Repeat("rule bundle loaded\n", maxBundleLogLines+1), maxBundleLogLines},
		{"large-file", strings.Repeat("x\n", 8*1024*1024/2), 0},
		{"line-limit", strings.Repeat("x", maxProxyLogLineBytes-2) + "\nrule bundle loaded\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.log")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			lines, err := bundleLogLines(path)
			if err != nil || len(lines) != tc.want {
				t.Fatalf("lines=%v error=%v", lines, err)
			}
		})
	}
}

func TestUnavailableProcessStatsPreserveIntegrity(t *testing.T) {
	old := readProcessStat
	readProcessStat = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { readProcessStat = old })
	opt := smallOptions(t, realPipelock(t))
	opt.requests, opt.warmup = 10, 2
	res, err := runMode(context.Background(), opt, modeRequired)
	if err != nil {
		t.Fatalf("process stats aborted integrity collection: %v", err)
	}
	if res.Integrity.Verdict != verdictPass || !res.Integrity.Shutdown.Clean || res.Performance.Verdict != perfInvalid || !hasReason(res.Performance.Reasons, "measurement unavailable") {
		t.Fatalf("result: %+v", res)
	}
}

func TestFailedSignalHasBoundedWait(t *testing.T) {
	// Releasing a second handle makes Signal fail even while the real child lives.
	port, err := freePort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	cmd := localCommand(context.Background(), newFakePipelock(t, "hang"), "", os.Environ(), "run", "--listen", addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	original := cmd.Process
	exited := make(chan struct{})
	logFile, err := os.CreateTemp(t.TempDir(), "proxy-log-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	p := &proxyProc{cmd: cmd, exited: exited, log: logFile}
	go func() { _, p.exitErr = original.Wait(); close(exited) }()
	t.Cleanup(func() { _ = original.Kill(); <-exited })
	if err := awaitProxy(context.Background(), addr, p); err != nil {
		t.Fatal(err)
	}
	duplicate, err := os.FindProcess(original.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Release(); err != nil {
		t.Fatal(err)
	}
	cmd.Process = duplicate
	done := make(chan shutdownReport, 1)
	go func() { done <- p.stop(20 * time.Millisecond) }()
	select {
	case rep := <-done:
		if rep.Clean || p.stopped {
			t.Fatal("live child marked stopped after signal and kill failures")
		}
		cmd.Process = original
		p.cleanup()
		if !p.stopped {
			t.Fatal("cleanup did not retry termination")
		}
	case <-time.After(time.Second):
		_ = original.Kill()
		<-done
		t.Fatal("failed signal waited without a deadline")
	}
}

func TestRelativeOutputIsNormalized(t *testing.T) {
	binary := newFakePipelock(t, "ok")
	root := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(wd, root)
	if err != nil {
		t.Fatal(err)
	}
	opt, _, _, err := parseFlags([]string{"--binary", binary, "--out", relative, "--requests", strconv.Itoa(1), "--warmup", "0", "--modes", modeOff})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(opt.out) {
		t.Fatalf("output not absolute: %q", opt.out)
	}
	if res, err := runMode(context.Background(), opt, modeOff); err != nil || res.Integrity.Verdict != verdictPass {
		t.Fatalf("relative output run: %v %v", res, err)
	}
}

func TestBundleLogMemoryBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary log line\n", 500000)), 0o600); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	lines, err := bundleLogLines(path)
	runtime.ReadMemStats(&after)
	if err != nil || len(lines) != 0 {
		t.Fatalf("large ordinary log: lines=%v error=%v", lines, err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1024*1024 {
		t.Fatalf("log scan allocated %d bytes; want at most 1 MiB", allocated)
	}
}

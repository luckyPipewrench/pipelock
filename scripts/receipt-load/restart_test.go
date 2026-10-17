// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestRestartFlags(t *testing.T) {
	for _, tt := range []struct {
		name, value string
		valid       bool
	}{
		{"disabled", "0", true},
		{"first", "1", true},
		{"last", "9", true},
		{"negative", "-1", false},
		{"total", "10", false},
		{"past", "11", false},
		{"malformed", "once", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opt, _, _, err := parseFlags([]string{"--binary", os.Args[0], "--out", t.TempDir(), "--requests", "10", "--restart-after", tt.value})
			if (err == nil) != tt.valid {
				t.Fatalf("parseFlags = %+v, %v", opt, err)
			}
			if tt.valid && strconv.Itoa(opt.restartAfter) != tt.value {
				t.Fatalf("restartAfter = %d", opt.restartAfter)
			}
		})
	}
}

func TestMeasuredPhases(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		after                    int
		interrupted, failRestart bool
		want                     []string
		wantErr                  bool
	}{
		{name: "disabled", want: []string{"load:0:10"}},
		{name: "restart", after: 4, want: []string{"load:0:4", "restart", "load:4:6"}},
		{name: "stop failure", after: 4, failRestart: true, want: []string{"load:0:4", "restart"}, wantErr: true},
		{name: "interrupted", after: 4, interrupted: true, want: []string{"load:0:4"}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			got, err := measuredPhases(options{requests: 10, restartAfter: tt.after}, func(offset, count int) phaseResult {
				calls = append(calls, "load:"+strconv.Itoa(offset)+":"+strconv.Itoa(count))
				r := phaseResult{outcomes: make([]requestOutcome, count), elapsed: time.Second, samples: map[int]string{0: "body"}, interrupted: tt.interrupted}
				for i := range r.outcomes {
					r.outcomes[i] = requestOutcome{ran: true, status: offset + i, doneAtNS: int64(i + 1)}
				}
				return r
			}, func() error {
				calls = append(calls, "restart")
				if tt.failRestart {
					return errors.New("stop failed")
				}
				return nil
			})
			if !reflect.DeepEqual(calls, tt.want) || (err != nil) != tt.wantErr {
				t.Fatalf("calls=%v err=%v", calls, err)
			}
			if !tt.wantErr {
				if len(got.outcomes) != 10 {
					t.Fatalf("outcomes=%d", len(got.outcomes))
				}
				for i, out := range got.outcomes {
					if out.status != i {
						t.Fatalf("identity %d: %+v", i, out)
					}
				}
				if tt.after > 0 && (got.outcomes[4].doneAtNS != time.Second.Nanoseconds()+1 || got.elapsed != 2*time.Second || got.samples[4] != "body") {
					t.Fatalf("merged phase=%+v", got)
				}
			}
		})
	}
}

func TestRestartProcessFailures(t *testing.T) {
	for _, tt := range []struct {
		name, behavior, reason string
		budget                 time.Duration
	}{
		{"clean", "ok", "", 20 * time.Second},
		{"unclean", "shutdownfail", "restart stop failed", 20 * time.Second},
		{"timeout", "hang", "ignored SIGTERM", 100 * time.Millisecond},
		{"restart failure", "restartfail", "restart readiness", 20 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opt := smallOptions(t, newFakePipelock(t, tt.behavior))
			opt.restartAfter = 17
			opt.shutdownTimeout = tt.budget
			code := runModes(context.Background(), opt, []string{modeOff})
			got := readResult(t, filepath.Join(opt.out, modeOff))
			if tt.reason != "" {
				if code != exitIntegrity || !hasReason(got.Integrity.Reasons, tt.reason) {
					t.Fatalf("code=%d integrity=%+v", code, got.Integrity)
				}
				return
			}
			if code != exitOK || got.Restart == nil || !got.Restart.Ready || !got.Restart.Shutdown.Clean || got.Restart.StopSeconds <= 0 || got.Performance.Latency.Samples != opt.requests {
				t.Fatalf("code=%d result=%+v", code, got)
			}
			raw, err := os.ReadFile(filepath.Join(opt.out, modeOff, "samples.csv"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(raw), "unix_ns,") != 1 {
				t.Fatal("duplicate sampling header")
			}
		})
	}
}

func TestRestartVerificationFailure(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "verifyfail"))
	opt.restartAfter = 17
	if code := runModes(context.Background(), opt, []string{modeBest}); code != exitIntegrity {
		t.Fatalf("exit=%d, want integrity failure", code)
	}
	got := readResult(t, filepath.Join(opt.out, modeBest))
	if got.Restart == nil || got.Restart.Ready || !got.Restart.Verify.Ran || got.Restart.Verify.Exit != 1 || !hasReason(got.Integrity.Reasons, "verification before restart exited 1") {
		t.Fatalf("restart=%+v integrity=%+v", got.Restart, got.Integrity)
	}
}

func TestDefaultOmitsRestartEvidence(t *testing.T) {
	raw, err := json.Marshal(result{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "restart") {
		t.Fatalf("default acquired restart fields: %s", raw)
	}
}

func TestRealRestartContinuity(t *testing.T) {
	bin := realPipelock(t)
	for _, chains := range []int{1, 2} {
		t.Run(strconv.Itoa(chains), func(t *testing.T) {
			opt := smallOptions(t, bin)
			// Small enough to stay near the other real-proxy runs under CI's per-test
			// ceiling. It covers the two-generation topology but never reaches a
			// periodic checkpoint; full-size restart runs cover that path.
			opt.requests = 200
			opt.warmup = 20
			opt.concurrency = 8
			opt.restartAfter = 100
			opt.chains = chains
			if code := runModes(context.Background(), opt, []string{modeRequired}); code != exitOK {
				t.Fatalf("run exit=%d", code)
			}
			name := modeRequired
			if chains > 1 {
				name = "chains-2-" + name
			}
			dirs := newRunDirs(filepath.Join(opt.out, name))
			got := readResult(t, dirs.root)
			if got.Restart == nil || !got.Restart.Ready || !got.Restart.Verify.Ran || got.Restart.Verify.Exit != 0 || !got.Integrity.Verify.Ran || got.Integrity.Verify.Exit != 0 || got.Integrity.ReceiptMissing != 0 {
				t.Fatalf("restart=%+v integrity=%+v", got.Restart, got.Integrity)
			}
			for kind, k := range got.Integrity.Kinds {
				if k.Expected != k.Observed || k.Duplicate != 0 {
					t.Fatalf("%s: %+v", kind, k)
				}
			}
			t.Logf("%d chains: %d measured + %d warmup, restart after %d, stop %.6fs / %.0fs, both verifications passed", chains, opt.requests, opt.warmup, opt.restartAfter, got.Restart.StopSeconds, got.Restart.ShutdownBudgetSeconds)
			plan := newWorkload(opt.seed, opt.warmup, opt.requests)
			// Continuity uses only lifecycle data, so no request attribution is needed.
			after, err := scanRecorder(dirs.recorder, plan, "unused.vendor.example:80")
			if err != nil {
				t.Fatal(err)
			}
			if chains != 1 {
				rejectUnlinkedGroup(t, dirs, after, chains)
				return
			}
			// Removing a valid run's predecessor link leaves individually valid
			// chains. The restart topology check must still reject that evidence.
			before := newRecorderObservation(plan.total())
			var predecessor string
			for session := range after.opens {
				path := filepath.Join(dirs.recorder, receipt.ChainLinkFileName(session))
				if _, err := os.Stat(path); err == nil {
					predecessor = session
					before.opens[session] = after.opens[session]
					before.closes[session] = after.closes[session]
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}
			if predecessor == "" {
				t.Fatal("no predecessor link to remove")
			}
			env, _ := buildChildEnv(os.Environ(), dirs)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if v := verifyRecorder(ctx, filepath.Join(dirs.root, "bin", "pipelock"), dirs, env, after); v.Exit != 0 {
				t.Fatalf("unlinked positive control must remain individually verifiable: %+v", v)
			}
			if err := checkRestartContinuity(dirs, before, after, 1); err == nil {
				t.Fatal("missing restart link accepted")
			}
			t.Log("missing-link negative rejected; existing whole-recorder verification alone passed")
		})
	}
}

// rejectUnlinkedGroup checks the grouped rule against real signed lifecycle
// data. The binding is part of signed opens, so a fresh unlinked successor
// group is modeled in memory: on disk it would fail signature verification
// before the topology check could be the deciding guard.
func rejectUnlinkedGroup(t *testing.T, dirs runDirs, after *recorderObservation, chains int) {
	t.Helper()
	before, fresh := newRecorderObservation(0), newRecorderObservation(0)
	for session, open := range after.opens {
		if open.GroupBinding != nil && open.GroupBinding.PreviousGroupID == "" {
			before.opens[session], before.closes[session] = open, after.closes[session]
		}
	}
	if err := checkRestartContinuity(dirs, before, after, chains); err != nil {
		t.Fatalf("real grouped restart rejected: %v", err)
	}
	for session, open := range after.opens {
		copied := *open
		if before.opens[session] == nil && open.GroupBinding != nil {
			binding := *open.GroupBinding
			binding.PreviousGroupID, binding.PreviousOpenManifestSHA256 = "", ""
			copied.GroupBinding = &binding
		}
		fresh.opens[session], fresh.closes[session] = &copied, after.closes[session]
	}
	if err := checkRestartContinuity(dirs, before, fresh, chains); err == nil {
		t.Fatal("fresh unlinked successor group accepted")
	}
	t.Log("unlinked successor group negative rejected")
}

func TestRestartGroupTopology(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mutate  func(*recorderObservation, *recorderObservation)
		wantErr bool
	}{
		{name: "linked"},
		{name: "missing predecessor", wantErr: true, mutate: func(b, a *recorderObservation) { delete(a.opens, "old-0") }},
		{name: "missing initial close", wantErr: true, mutate: func(b, a *recorderObservation) { delete(b.closes, "old-0") }},
		{name: "missing final close", wantErr: true, mutate: func(b, a *recorderObservation) { delete(a.closes, "new-0") }},
		{name: "wrong predecessor", wantErr: true, mutate: func(b, a *recorderObservation) { a.opens["new-0"].GroupBinding.PreviousGroupID = "other" }},
		{name: "missing binding", wantErr: true, mutate: func(b, a *recorderObservation) { a.opens["new-0"].GroupBinding = nil }},
		{name: "split successor", wantErr: true, mutate: func(b, a *recorderObservation) { a.opens["new-0"].GroupBinding.GroupID = "other" }},
		{name: "split predecessor", wantErr: true, mutate: func(b, a *recorderObservation) { b.opens["old-0"].GroupBinding.GroupID = "other" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before, after := newRecorderObservation(0), newRecorderObservation(0)
			for i := range 2 {
				old, next := "old-"+strconv.Itoa(i), "new-"+strconv.Itoa(i)
				before.opens[old] = &receipt.SessionOpen{GroupBinding: &receipt.ReceiptGroupBinding{GroupID: "first"}}
				before.closes[old] = true
				after.opens[old] = before.opens[old]
				after.closes[old] = true
				after.opens[next] = &receipt.SessionOpen{GroupBinding: &receipt.ReceiptGroupBinding{GroupID: "second", PreviousGroupID: "first"}}
				after.closes[next] = true
			}
			if tt.mutate != nil {
				tt.mutate(before, after)
			}
			if err := checkRestartContinuity(runDirs{}, before, after, 2); (err != nil) != tt.wantErr {
				t.Fatalf("continuity=%v", err)
			}
		})
	}
	if err := checkRestartContinuity(runDirs{}, nil, nil, 1); err == nil {
		t.Fatal("missing checkpoint accepted")
	}
}

func TestSummarySeparatesRestartSamples(t *testing.T) {
	baseline := result{Requests: 10}
	restarted := baseline
	restarted.Restart = &restartReport{AfterRequests: 4}
	if sampleIdentity(baseline) == sampleIdentity(restarted) {
		t.Fatal("restart and uninterrupted samples mixed")
	}
	other := baseline
	other.Restart = &restartReport{AfterRequests: 5}
	if sampleIdentity(other) == sampleIdentity(restarted) {
		t.Fatal("different restart boundaries mixed")
	}
	other.Restart.AfterRequests = 4
	other.Restart.StopSeconds = 0.01
	if sampleIdentity(other) != sampleIdentity(restarted) {
		t.Fatal("observed stop timing changed sample identity")
	}
}

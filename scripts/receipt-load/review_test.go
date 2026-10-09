// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReviewV2Identity(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	sinkAddr := "127.0.0.1:19"
	writeSynthRecorder(t, dir, plan, sinkAddr, perfectReceipts(plan, modeRequired))
	path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var eventLine string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, `"event_id"`) {
			eventLine = line
			break
		}
	}
	// A duplicated event replaces another event, preserving per-key counts.
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if line != eventLine && strings.Contains(line, `"event_id"`) {
			lines[i] = eventLine
			break
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanRecorder(dir, plan, sinkAddr); err == nil {
		t.Fatal("duplicate EventID accepted")
	}
}

func TestReviewForeignTargetsAreNotControl(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	receipts := perfectReceipts(plan, modeRequired)
	receipts = append(receipts, synthReceipt{kind: kindV1Allow, slot: 0, actionID: "foreign", target: "http://api.vendor.example/ok?wk=s1-m000000"})
	if rep := evaluateSynth(t, modeRequired, receipts); rep.Verdict != verdictFail {
		t.Fatal("foreign workload receipt passed as control")
	}
}

func TestReviewNativeAELSignature(t *testing.T) {
	bin := realPipelock(t)
	opt := smallOptions(t, bin)
	opt.requests, opt.warmup = 10, 2
	res, err := runMode(context.Background(), opt, modeRequired)
	if err != nil || res.Integrity.Verdict != verdictPass {
		t.Fatalf("control: %v %s", err, res.Integrity.Verify.Output)
	}
	dirs := newRunDirs(filepath.Join(opt.out, modeRequired))
	plan := newWorkload(opt.seed, opt.warmup, opt.requests)
	plan.runNonce = strings.TrimPrefix(res.Inputs.Workload.Tag, plan.tag()+"-r")
	evidencePaths, err := filepath.Glob(filepath.Join(dirs.recorder, "evidence-*.jsonl"))
	if err != nil || len(evidencePaths) == 0 {
		t.Fatal("no evidence")
	}
	evidence, err := os.ReadFile(evidencePaths[0])
	if err != nil {
		t.Fatal(err)
	}
	host := extractSinkHost(t, string(evidence))
	obs, err := scanRecorder(dirs.recorder, plan, host)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dirs.recorder, "ael", "*", "recorders", "pipelock.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("paths: %v %v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	payload, sig, ok := strings.Cut(lines[1], ".")
	if !ok {
		t.Fatal("missing signed record")
	}
	replacement := "A"
	if sig[0] == 'A' {
		replacement = "B"
	}
	lines[1] = payload + "." + replacement + sig[1:]
	if err := os.WriteFile(paths[0], []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	env, _ := buildChildEnv(os.Environ(), dirs)
	if rep := verifyRecorder(context.Background(), bin, dirs, env, obs); rep.Exit == 0 {
		t.Fatal("modified AEL signature accepted")
	}
}

func TestReviewRunKeysAreDistinct(t *testing.T) {
	a, b := newWorkload(1, 0, 1), newWorkload(1, 0, 1)
	a.runNonce, b.runNonce = "first", "second"
	if _, ok := b.parseKey(a.key(0)); ok {
		t.Fatal("another run's key accepted")
	}
}

func TestReviewSinkRefusesAmbiguousKeys(t *testing.T) {
	plan := newWorkload(1, 0, 1)
	s := &sink{plan: plan, seen: make([]atomic.Int32, plan.total())}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.vendor.example/ok?wk="+plan.key(0)+"&wk=foreign", nil)
	s.handle(httptest.NewRecorder(), request)
	if s.unknown.Load() != 1 || s.hits()[0] != 0 {
		t.Fatalf("ambiguous key accepted: unknown=%d hits=%v", s.unknown.Load(), s.hits())
	}
}

func TestReviewShardCorrelation(t *testing.T) {
	plan := newWorkload(1, 0, 1)
	scanner := &recorderScanner{plan: plan, sinkAddr: synthSink, obs: newRecorderObservation(1), actionSlot: map[string]int{}, controlIDs: map[string]struct{}{}, eventIDs: map[string]bool{}, actionRuns: map[string]string{}}
	line := v1Line(kindV1Intent, actionIDFor(0), sinkTarget(synthSink, "wk="+plan.key(0)))
	var env evidenceEnvelope
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		t.Fatal(err)
	}
	env.Session = "shard-one"
	if err := scanner.v1Receipt(env); err != nil {
		t.Fatal(err)
	}
	env.Session = "shard-two"
	env.Detail = json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(string(env.Detail), `"run0"`, `"run1"`), actionIDFor(0), "other-action"))
	if err := scanner.v1Receipt(env); err == nil || err.Error() != "workload key maps to multiple recorder shards" {
		t.Fatalf("cross-shard correlation returned %v", err)
	}
}

func TestReviewRunIdentityIsFresh(t *testing.T) {
	bin := realPipelock(t)
	var tags []string
	for range 2 {
		opt := smallOptions(t, bin)
		opt.requests, opt.warmup = 1, 0
		res, err := runMode(context.Background(), opt, modeOff)
		if err != nil || res.Integrity.Verdict != verdictPass {
			t.Fatalf("run failed: %v", err)
		}
		tags = append(tags, res.Inputs.Workload.Tag)
	}
	if tags[0] == tags[1] {
		t.Fatal("repeated seed reused run identity")
	}
}

func TestReviewControlActionIDCannotOwnWorkload(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	var receipts []synthReceipt
	for _, r := range perfectReceipts(plan, modeBest) {
		if r.slot == 0 && r.kind == kindAEL {
			continue
		}
		if r.slot == 0 {
			r.actionID = "control-open"
		}
		receipts = append(receipts, r)
	}
	for _, order := range []string{"control-first", "control-last"} {
		t.Run(order, func(t *testing.T) {
			dir := t.TempDir()
			writeSynthRecorder(t, dir, plan, synthSink, receipts)
			if order == "control-last" {
				path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
				data, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				lines = append(lines[1:], lines[0])
				if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := scanRecorder(dir, plan, synthSink); err == nil {
				t.Fatal("control activity can replace a missing request activity")
			}
		})
	}
}

func TestReviewOffDoesNotExemptControls(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, nil)
	obs, err := scanRecorder(dir, plan, synthSink)
	if err != nil {
		t.Fatal(err)
	}
	hits := make([]int, plan.total())
	for slot := range hits {
		if !plan.blocked(slot) {
			hits[slot] = 1
		}
	}
	rep := evaluateIntegrity(integrityInput{mode: modeOff, plan: plan, obs: obs, outcomes: make([]requestOutcome, plan.total()), sinkHits: hits})
	if rep.Verdict != verdictFail {
		t.Fatal("off mode exempted unverified control evidence")
	}
}

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReviewR2MalformedQuery(t *testing.T) {
	for _, suffix := range []string{"&wk=%zz", "&wk=foreign;ignored=value", "&other=%zz"} {
		target := sinkTarget(synthSink, "wk=s1-m000000"+suffix)
		if key, ok := keyFromTarget(target); ok {
			t.Fatalf("malformed query accepted as %q", key)
		}
	}
}

func TestReviewR2TargetShape(t *testing.T) {
	s := &recorderScanner{sinkAddr: synthSink}
	for _, target := range []string{"https://" + synthSink + "/ok?wk=s1-m000000", "http://" + synthSink + "/other?wk=s1-m000000", "http://user@" + synthSink + "/ok?wk=s1-m000000", "http://" + synthSink + "/ok?wk=s1-m000000#fragment"} {
		if s.classify(target) != targetUncorrelatable {
			t.Fatalf("wrong target accepted: %s", target)
		}
	}
	if s.classify(sinkTarget(synthSink, "wk=s1-m000000")) != targetWorkload {
		t.Fatal("positive control rejected")
	}
}

func TestReviewR2SummaryCPULabel(t *testing.T) {
	r := fakeResult(100, 80, 90, verdictPass, perfMeasured)
	r.Inputs.Host.HarnessGOMAXPROCS = 8
	r.Inputs.Host.ChildGOMAXPROCS = "8"
	r.Inputs.Host.CgroupCPUQuota = "800000/100000 us (/scope)"
	row := summaryRow(2, 1, modeRequired, 1, []result{r})
	if row[4] == verdictPass || row[7] != "" {
		t.Fatalf("CPU mismatch reported as usable: %v", row)
	}
}

func TestReviewR2RunShardPairing(t *testing.T) {
	plan := newWorkload(1, 0, 2)
	for _, scenario := range []string{"missing-session", "missing-run", "session-reused", "run-reused"} {
		t.Run(scenario, func(t *testing.T) {
			s := &recorderScanner{plan: plan, sinkAddr: synthSink, obs: newRecorderObservation(2), actionSlot: map[string]int{}, controlIDs: map[string]struct{}{}, eventIDs: map[string]bool{}, actionRuns: map[string]string{}}
			for slot := range 2 {
				session, run := "shard-one", "run-one"
				if slot == 1 {
					switch scenario {
					case "missing-session":
						session, run = "", "run-two"
					case "missing-run":
						session, run = "shard-two", ""
					case "session-reused":
						run = "run-two"
					case "run-reused":
						session = "shard-two"
					}
				}
				env := evidenceEnvelope{Session: session, Detail: []byte(`{"action_record":{"action_id":"` + actionIDFor(slot) + `","run_nonce":"` + run + `","verdict":"allow","target":"` + sinkTarget(synthSink, "wk="+plan.key(slot)) + `"}}`)}
				err := s.v1Receipt(env)
				if slot == 0 && err != nil {
					t.Fatal(err)
				}
				if slot == 1 && err == nil {
					t.Fatal("invalid shard/run binding accepted")
				}
			}
		})
	}
}

func TestReviewR2V2MissingSession(t *testing.T) {
	plan := newWorkload(1, 0, 1)
	s := &recorderScanner{plan: plan, sinkAddr: synthSink, obs: newRecorderObservation(1), eventIDs: map[string]bool{}}
	env := evidenceEnvelope{Detail: []byte(`{"event_id":"one","payload":{"target":"` + sinkTarget(synthSink, "wk="+plan.key(0)) + `"}}`)}
	if err := s.v2Receipt(env); err == nil {
		t.Fatal("empty v2 session accepted")
	}
}

func TestReviewR2NativeFileSelection(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeBest))
	// The canonical stream is the only stream VerifyRun authenticates.
	path := dir + "/ael/run0/recorders/other.jsonl"
	writeReviewFile(t, path, aelRecord("activity", "control-open")+"\n")
	if _, err := scanRecorder(dir, plan, synthSink); err == nil {
		t.Fatal("unverified native sidecar accepted")
	}
}

func writeReviewFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReviewR2CPUUnavailable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "getconf")
	writeReviewFile(t, path, "#!/bin/sh\nexit 1\n")
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // Test-owned command must be executable.
		t.Fatal(err)
	}
	t.Setenv("PATH", root+":"+os.Getenv("PATH"))
	res, err := runMode(context.Background(), smallOptions(t, newFakePipelock(t, "clean")), modeOff)
	if err != nil {
		t.Fatal(err)
	}
	if res.Integrity.Verdict != verdictPass {
		t.Fatal("positive control integrity failed")
	}
	if res.Performance.Verdict != perfInvalid {
		t.Fatal("unavailable CPU accounting reported a usable zero")
	}
}

func TestReviewR2OffNativeMetadata(t *testing.T) {
	for _, path := range []string{"manifest.json", "flight-recorder-signing.key.pub", "ael/run0/manifest.json"} {
		t.Run(path, func(t *testing.T) {
			plan := newWorkload(1, 0, 1)
			dir := t.TempDir()
			full := filepath.Join(dir, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			writeReviewFile(t, full, "{}\n")
			obs, err := scanRecorder(dir, plan, synthSink)
			if err != nil {
				t.Fatal(err)
			}
			rep := evaluateIntegrity(integrityInput{mode: modeOff, plan: plan, obs: obs, outcomes: []requestOutcome{{ran: true}}, sinkHits: []int{1}})
			if rep.Verdict == verdictPass {
				t.Fatal("off mode accepted unverified metadata")
			}
		})
	}
}

func TestReviewR2CPUMatching(t *testing.T) {
	for _, scenario := range []string{"valid", "equivalent-ratio", "missing-quota", "missing-ratio", "unbounded", "overflow", "zero-period", "fractional", "wrong-harness", "wrong-child", "wrong-quota"} {
		t.Run(scenario, func(t *testing.T) {
			host := fakeResult(100, 80, 90, verdictPass, perfMeasured).Inputs.Host
			switch scenario {
			case "equivalent-ratio":
				host.CgroupCPUQuota = "400000/200000 us (/other)"
			case "missing-ratio":
				host.CgroupCPUQuota = "malformed us (/other)"
			case "missing-quota":
				host.CgroupCPUQuota = ""
			case "unbounded":
				host.CgroupCPUQuota = "none visible"
			case "overflow":
				host.CgroupCPUQuota = "9223372036854775808/100000 us (/other)"
			case "zero-period":
				host.CgroupCPUQuota = "200000/0 us (/other)"
			case "fractional":
				host.CgroupCPUQuota = "200001/100000 us (/other)"
			case "wrong-harness":
				host.HarnessGOMAXPROCS = 8
			case "wrong-child":
				host.ChildGOMAXPROCS = "8"
			case "wrong-quota":
				host.CgroupCPUQuota = "800000/100000 us (/other)"
			}
			want := scenario == "valid" || scenario == "equivalent-ratio"
			if matchesCPU(host, 2) != want {
				t.Fatalf("CPU qualification disagrees for %+v", host)
			}
		})
	}
}

func TestReviewR2SinkTargetShape(t *testing.T) {
	plan := newWorkload(1, 0, 1)
	for _, shape := range []struct{ method, path string }{{http.MethodGet, "/other"}, {http.MethodPost, "/ok"}, {http.MethodGet, "/%6fk"}} {
		s := &sink{plan: plan, seen: make([]atomic.Int32, 1)}
		req := httptest.NewRequestWithContext(context.Background(), shape.method, "http://api.vendor.example"+shape.path+"?wk="+plan.key(0), nil)
		s.handle(httptest.NewRecorder(), req)
		if s.unknown.Load() != 1 || s.hits()[0] != 0 {
			t.Fatalf("sink counted unplanned request: %+v", shape)
		}
	}
}

func TestReviewR2NativeProducerSidecar(t *testing.T) {
	opt := smallOptions(t, realPipelock(t))
	opt.requests, opt.warmup = 1, 0
	res, err := runMode(context.Background(), opt, modeRequired)
	if err != nil || res.Integrity.Verdict != verdictPass {
		t.Fatalf("real producer failed: %v", err)
	}
	dirs := newRunDirs(filepath.Join(opt.out, modeRequired))
	paths, err := filepath.Glob(filepath.Join(dirs.recorder, "ael", "*", "recorders", "pipelock.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("native paths: %v %v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 {
		t.Fatal("real native stream has no activity")
	}
	writeReviewFile(t, filepath.Join(filepath.Dir(paths[0]), "other.jsonl"), lines[1]+"\n")
	plan := newWorkload(opt.seed, opt.warmup, opt.requests)
	plan.runNonce = strings.TrimPrefix(res.Inputs.Workload.Tag, plan.tag()+"-r")
	evidence, err := filepath.Glob(filepath.Join(dirs.recorder, "evidence-*.jsonl"))
	if err != nil || len(evidence) == 0 {
		t.Fatal("no evidence")
	}
	raw, err := os.ReadFile(evidence[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanRecorder(dirs.recorder, plan, extractSinkHost(t, string(raw))); err == nil {
		t.Fatal("real producer sidecar was not rejected")
	}
}

func TestReviewR2RecorderFileSelection(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	for _, path := range []string{"nested/evidence-proxy.run.x-0.jsonl", "evidence-invalid.jsonl"} {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeBest))
			full := filepath.Join(dir, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			writeReviewFile(t, full, v1Line(kindV1Allow, "control-extra", "pipelock://session/open")+"\n")
			if _, err := scanRecorder(dir, plan, synthSink); err == nil {
				t.Fatal("unverified recorder sidecar accepted")
			}
		})
	}
}

func TestReviewR2RecorderSessionMatchesFile(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, perfectReceipts(plan, modeBest))
	path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.ReplaceAll(string(data), `"session_id":"proxy.run.x"`, `"session_id":"other-session"`)
	if changed == string(data) {
		t.Fatal("positive mutation control changed no sessions")
	}
	writeReviewFile(t, path, changed)
	if _, err := scanRecorder(dir, plan, synthSink); err == nil {
		t.Fatal("receipt session differs from verified file identity")
	}
}

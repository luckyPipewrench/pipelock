// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func awaitSegmentWorker(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("segment worker did not exit")
	}
}

func TestGroupSegmentWorkerCoalescesWithoutBlockingOrLosingWork(t *testing.T) {
	w := newGroupSegmentWorker(context.Background(), "", map[string]*groupCloseVerifier{"one": {}, "two": {}}, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	seen := map[string][]string{}
	w.verify = func(session string, segment sealedGroupSegment) error {
		first.Do(func() { close(entered); <-release })
		seen[session] = append(seen[session], segment.path)
		return nil
	}
	w.activate()
	_ = w.register("one", "first", nil)
	awaitSegmentWorker(t, entered)
	registered := make(chan struct{})
	go func() {
		for i := range 1000 {
			for _, session := range []string{"one", "two"} {
				_ = w.register(session, fmt.Sprint(i), nil)
			}
		}
		close(registered)
	}()
	awaitSegmentWorker(t, registered)
	if cap(w.wake) != 1 || len(w.wake) != 1 {
		t.Fatal("wake-ups were not bounded and coalesced")
	}
	close(release)
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	awaitSegmentWorker(t, w.done)
	for _, session := range []string{"one", "two"} {
		offset := 0
		if session == "one" {
			offset = 1
		}
		if len(seen[session]) != 1000+offset {
			t.Fatalf("%s verified %d segments", session, len(seen[session]))
		}
		for i := range 1000 {
			if seen[session][i+offset] != fmt.Sprint(i) {
				t.Fatalf("%s verification reordered at %d", session, i)
			}
		}
	}
}

func TestGroupSegmentWorkerCancellationAndRepeatedFinish(t *testing.T) {
	for _, activated := range []bool{false, true} {
		t.Run(fmt.Sprint(activated), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			w := newGroupSegmentWorker(ctx, "", map[string]*groupCloseVerifier{"one": {}}, nil)
			calls := 0
			w.verify = func(string, sealedGroupSegment) error { calls++; return nil }
			if activated {
				w.activate()
				w.activate()
			}
			cancel()
			awaitSegmentWorker(t, w.done)
			// Cancellation joins the sole worker; all later registrations remain
			// available to the close-time fallback, without spawning a goroutine.
			_ = w.register("one", "after cancellation", nil)
			w.waitIdle()
			if err := w.finish(); err != nil {
				t.Fatal(err)
			}
			if err := w.finish(); err != nil || calls != 1 {
				t.Fatalf("repeated finish err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestGroupSegmentWorkerFailureRefusedAndReportedOnce(t *testing.T) {
	for _, mode := range []string{"verification", "unknown_shard", "missing_verifier", "identity", "size"} {
		t.Run(mode, func(t *testing.T) {
			var notices bytes.Buffer
			set := closeTestGroup(t, 80)
			// Fixture barrier makes replacing the diagnostic sink race-free.
			set.verification.notices = &notices
			w := set.verification
			session := set.open.Shards[0].SessionID
			want := errors.New("injected background verification failure")
			switch mode {
			case "verification":
				w.verify = func(string, sealedGroupSegment) error { return want }
			case "unknown_shard":
				session = "unknown"
			case "missing_verifier":
				delete(set.verifiers, session)
			case "identity", "size":
				path := filepath.Join(set.recorder.Dir(), "evidence-"+session+"-0.jsonl")
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				chain, err := newGroupShardVerifier(set.open, set.openHash, 0)
				if err != nil {
					t.Fatal(err)
				}
				w.verifiers[session] = &groupCloseVerifier{chain: chain, files: make(map[string]verifiedGroupFile)}
				if mode == "identity" {
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					raw, err := os.ReadFile(filepath.Clean(path + ".old"))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
					requireReplacedGroupTestFile(t, path, info)
				} else {
					info = segmentSizeInfo{FileInfo: info}
				}
				_ = w.register(session, path, info)
			}
			if mode != "identity" && mode != "size" {
				_ = w.register(session, "unused", nil)
			}
			w.waitIdle()
			if _, err := set.PublishClose(); err == nil {
				t.Fatal("background failure published a close")
			}
			if mode == "verification" && (w.finish() == nil || errors.Is(w.finish(), want)) {
				t.Fatal("close did not use the fresh inventory failure")
			}
			if got := strings.Count(notices.String(), "background verification failed"); got != 1 {
				t.Fatalf("failure emitted %d times: %s", got, notices.String())
			}
		})
	}
}

type segmentSizeInfo struct{ os.FileInfo }

func (s segmentSizeInfo) Size() int64 { return s.FileInfo.Size() + 1 }

func TestGroupSegmentWorkerFailureDoesNotFailLiveRequests(t *testing.T) {
	_, key := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true, MaxEntriesPerFile: closeTestFileEntries}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	var notices bytes.Buffer
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Notices: &notices}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	set.verification.waitIdle()
	set.verification.verify = func(string, sealedGroupSegment) error { return errors.New("sealed segment is invalid") }
	for range 128 {
		if err := set.EmitDurable(set.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"})); err != nil {
			t.Fatalf("background failure changed request behavior: %v", err)
		}
	}
	set.verification.waitIdle()
	for _, e := range set.Emitters() {
		if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := e.EmitTranscriptRoot(e.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatalf("fresh verification of intact evidence refused a close: %v", err)
	}
	if strings.Count(notices.String(), "background verification failed") != 1 {
		t.Fatal(notices.String())
	}
	awaitSegmentWorker(t, set.verification.done)
}

func TestGroupSegmentWorkerRecorderCloseJoinsWithoutPublish(t *testing.T) {
	want := errors.New("close verification failed")
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			set := closeTestGroup(t, 80)
			if fail {
				set.verification.verify = func(string, sealedGroupSegment) error { return want }
			}
			err := set.recorder.Close()
			if !fail && err != nil || fail && !errors.Is(err, want) {
				t.Fatalf("Close error=%v failure=%t", err, fail)
			}
			awaitSegmentWorker(t, set.verification.done)
			if err2 := set.recorder.Close(); !fail && err2 != nil || fail && !errors.Is(err2, want) {
				t.Fatalf("repeated Close error=%v", err2)
			}
		})
	}
}

func TestGroupSegmentWorkerCancellationDuringVerificationRetainsBacklog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := newGroupSegmentWorker(ctx, "", map[string]*groupCloseVerifier{"one": {}}, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	w.verify = func(string, sealedGroupSegment) error {
		calls++
		if calls == 1 {
			close(entered)
			<-release
		}
		return nil
	}
	w.activate()
	_ = w.register("one", "first", nil)
	awaitSegmentWorker(t, entered)
	_ = w.register("one", "second", nil)
	cancel()
	close(release)
	awaitSegmentWorker(t, w.done)
	if calls != 1 {
		t.Fatalf("canceled worker processed %d segments", calls)
	}
	if err := w.finish(); err != nil || calls != 2 {
		t.Fatalf("close discarded backlog: calls=%d err=%v", calls, err)
	}
}

func TestGroupSegmentWorkerCloseBeforeActivation(t *testing.T) {
	w := newGroupSegmentWorker(context.Background(), "", nil, nil)
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	awaitSegmentWorker(t, w.done)
}

// Match the repository's repeated-lifecycle leak check in
// internal/mcp/reaper_linux_test.go: ten cycles and two goroutines of slack
// for unrelated runtime/test machinery. A leaked worker per cycle exceeds it.
func TestGroupSegmentWorkerRepeatedLifecycleDoesNotLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	for range 10 {
		for _, cancelFirst := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			w := newGroupSegmentWorker(ctx, "", nil, nil)
			w.activate()
			if cancelFirst {
				cancel()
				awaitSegmentWorker(t, w.done)
			}
			if err := w.finish(); err != nil {
				t.Fatal(err)
			}
			cancel()
		}
	}
	testwait.For(t, 2*time.Second, func() bool { return runtime.NumGoroutine() <= before+2 }, "group segment worker goroutines to exit")
	t.Logf("goroutines before=%d after=%d", before, runtime.NumGoroutine())
}

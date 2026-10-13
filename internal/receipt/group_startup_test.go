// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func startupTestRecorder(t *testing.T, dir string, key ed25519.PrivateKey) *recorder.Recorder {
	t.Helper()
	r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func startupTestClose(t *testing.T, set *ReceiptShardSet, r *recorder.Recorder, closed bool) {
	t.Helper()
	if closed {
		for _, e := range set.Emitters() {
			if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
				t.Fatal(err)
			}
			if err := e.EmitTranscriptRoot(e.Session()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := set.PublishClose(); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStartupAuthenticatesSessionsOnce(t *testing.T) {
	for _, terminalClosed := range []bool{true, false} {
		t.Run(map[bool]string{true: "empty_closed_successor", false: "incomplete_successor"}[terminalClosed], func(t *testing.T) {
			_, key := generateTestKey(t)
			dir := t.TempDir()
			cfg := func(r *recorder.Recorder) EmitterConfig {
				return EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
			}
			r := startupTestRecorder(t, dir, key)
			first, err := OpenInitialReceiptShardSet(cfg(r), "proxy", 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			for range 8 {
				if err := first.EmitDurable(first.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Target: "https://api.vendor.example/data"})); err != nil {
					t.Fatal(err)
				}
			}
			startupTestClose(t, first, r, true)
			old, _ := first.Opening()
			r = startupTestRecorder(t, dir, key)
			second, err := OpenSuccessorReceiptShardSet(cfg(r), "proxy", 2, 0, old.GroupID)
			if err != nil {
				t.Fatal(err)
			}
			startupTestClose(t, second, r, terminalClosed)
			terminal, _ := second.Opening()
			// A legacy neighbor is authenticated by the existing whole-v1 inventory.
			legacyRec := startupTestRecorder(t, dir, key)
			legacySession, err := recorder.AcquireRunSession(legacyRec, "legacy")
			if err != nil {
				t.Fatal(err)
			}
			legacyCfg := cfg(legacyRec)
			legacyCfg.Session = legacySession
			legacy := NewEmitter(legacyCfg)
			if legacy == nil || legacy.InitError() != nil {
				t.Fatal("legacy initialization failed")
			}
			if err := legacy.EmitSessionOpen(); err != nil {
				t.Fatal(err)
			}
			if err := legacy.EmitSessionClose("graceful_shutdown"); err != nil {
				t.Fatal(err)
			}
			if err := legacy.EmitTranscriptRoot(legacySession); err != nil {
				t.Fatal(err)
			}
			if err := legacyRec.Close(); err != nil {
				t.Fatal(err)
			}
			want := make(map[string]uint64)
			if err := recorder.WalkSessionHistory(dir, legacySession, func(recorder.Entry) error { want[legacySession]++; return nil }); err != nil {
				t.Fatal(err)
			}
			for _, o := range []ReceiptGroupOpen{old, terminal} {
				for _, shard := range o.Shards {
					if err := recorder.WalkSessionHistory(dir, shard.SessionID, func(recorder.Entry) error { want[shard.SessionID]++; return nil }); err != nil {
						t.Fatal(err)
					}
				}
			}
			var mu sync.Mutex
			got := make(map[string]uint64)
			nativeWant := make(map[string]uint64)
			nativeGot := make(map[string]uint64)
			nativePaths, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "pipelock.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range nativePaths {
				raw, err := os.ReadFile(path) // #nosec G304 -- private fixture path from the native-run glob.
				if err != nil {
					t.Fatal(err)
				}
				run := filepath.Base(filepath.Dir(filepath.Dir(path)))
				for _, line := range bytes.Split(raw, []byte{'\n'}) {
					if len(bytes.TrimSpace(line)) > 0 {
						nativeWant[run]++
					}
				}
			}
			options := verification.Options{Progress: func(p verification.Progress) error {
				mu.Lock()
				defer mu.Unlock()
				if p.Kind == "recorder_record" {
					got[p.Session] += p.Records
				}
				if p.Kind == "native_ael" {
					nativeGot[p.Session] += p.Records
				}
				return nil
			}}
			if _, err := loadClosedGroupPredecessorWithOptions(dir, terminal.GroupID, []string{terminal.SignerKey}, options); err != nil {
				t.Fatal(err)
			}
			for session, count := range want {
				if got[session] != count {
					t.Errorf("session %s authenticated %d records, want exactly %d", session, got[session], count)
				}
			}
			for run, count := range nativeWant {
				if nativeGot[run] != count {
					t.Errorf("native run %s authenticated %d records, want exactly %d", run, nativeGot[run], count)
				}
			}
		})
	}
}

func TestStartupParallelJoinAndBudget(t *testing.T) {
	for _, budget := range []int{1, 2, 8} {
		for _, failure := range []string{"corrupt", "unreadable"} {
			t.Run(fmt.Sprintf("%d/%s", budget, failure), func(t *testing.T) {
				previous := runtime.GOMAXPROCS(budget)
				defer runtime.GOMAXPROCS(previous)
				_, key := generateTestKey(t)
				dir := t.TempDir()
				r := startupTestRecorder(t, dir, key)
				cfg := EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
				set, err := OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
				if err != nil {
					t.Fatal(err)
				}
				startupTestClose(t, set, r, true)
				open, _ := set.Opening()
				paths, _ := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[1].SessionID+"-*.jsonl"))
				raw, err := os.ReadFile(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				if failure == "unreadable" {
					err = os.Chmod(paths[0], 0)
				} else {
					err = os.WriteFile(paths[0], append(raw, []byte("{}\n")...), 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
				entered := make(chan struct{})
				release := make(chan struct{})
				other := make(chan struct{})
				var firstOnce, otherOnce sync.Once
				options := verification.Options{Progress: func(p verification.Progress) error {
					if p.Kind == "recorder_bytes" && p.Session == open.Shards[0].SessionID {
						firstOnce.Do(func() { close(entered); <-release })
					}
					if p.Kind == "recorder_bytes" && p.Session == open.Shards[1].SessionID {
						otherOnce.Do(func() { close(other) })
					}
					return nil
				}}
				done := make(chan error, 1)
				go func() {
					_, err := loadClosedGroupPredecessorWithOptions(dir, open.GroupID, []string{open.SignerKey}, options)
					done <- err
				}()
				select {
				case <-entered:
				case <-time.After(testwait.Deadline(time.Second)):
					t.Fatal("slow shard did not start")
				}
				if budget > 1 && failure == "corrupt" {
					select {
					case <-other:
					case <-time.After(testwait.Deadline(time.Second)):
						close(release)
						t.Fatal("independent shard did not run concurrently")
					}
				}
				select {
				case err := <-done:
					close(release)
					t.Fatalf("used corrupt result before slow shard finished: %v", err)
				default:
				}
				close(release)
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("corrupt shard admitted")
					}
				case <-time.After(testwait.Deadline(time.Second)):
					t.Fatal("workers did not join")
				}
			})
		}
	}
}

func TestStartupCancellationAndConsumedMutationRefuse(t *testing.T) {
	for _, mutation := range []string{"cancel", "replace", "delete", "extra", "unreadable"} {
		t.Run(mutation, func(t *testing.T) {
			_, key := generateTestKey(t)
			dir := t.TempDir()
			r := startupTestRecorder(t, dir, key)
			cfg := EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
			set, err := OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			startupTestClose(t, set, r, true)
			open, _ := set.Opening()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var once sync.Once
			options := verification.Options{Context: ctx, Progress: func(p verification.Progress) error {
				once.Do(func() {
					paths, e := filepath.Glob(filepath.Join(dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
					if e != nil || len(paths) != 1 {
						t.Fatalf("paths=%v err=%v", paths, e)
					}
					switch mutation {
					case "cancel":
						cancel()
					case "delete":
						if e := os.Remove(paths[0]); e != nil {
							t.Fatal(e)
						}
					case "unreadable":
						if e := os.Chmod(paths[0], 0); e != nil {
							t.Fatal(e)
						}
					case "replace":
						raw, e := os.ReadFile(paths[0])
						if e != nil {
							t.Fatal(e)
						}
						if e = os.Rename(paths[0], paths[0]+".old"); e != nil {
							t.Fatal(e)
						}
						if e = os.WriteFile(paths[0], raw, 0o600); e != nil {
							t.Fatal(e)
						}
					case "extra":
						if e := os.WriteFile(filepath.Join(dir, "evidence-unclaimed-000000.jsonl"), []byte("{}\n"), 0o600); e != nil {
							t.Fatal(e)
						}
					}
				})
				return nil
			}}
			r = startupTestRecorder(t, dir, key)
			cfg.Recorder = r
			cfg.StartupVerification = options
			if _, err = OpenSuccessorReceiptShardSet(cfg, "proxy", 2, 0, open.GroupID); err == nil {
				t.Fatal("mutation admitted successor")
			}
			if mutation == "cancel" && !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("cancellation missing")
			}
			paths, err := filepath.Glob(filepath.Join(dir, "receipt-group-*-open.json"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("successor published: %v %v", paths, err)
			}
		})
	}
}

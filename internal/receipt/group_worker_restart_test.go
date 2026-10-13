// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestRestartAfterBackgroundWorkerClose(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		for _, tamper := range []bool{false, true} {
			t.Run(fmt.Sprintf("fallback=%t/tamper=%t", fallback, tamper), func(t *testing.T) {
				_, key := generateTestKey(t)
				dir := t.TempDir()
				r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true, MaxEntriesPerFile: closeTestFileEntries}, nil, key)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = r.Close() })
				var notices bytes.Buffer
				cfg := EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Notices: &notices}
				set, err := OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
				if err != nil {
					t.Fatal(err)
				}
				w := set.verification
				w.waitIdle()
				failedSession := set.open.Shards[0].SessionID
				workerErr := errors.New("injected segment verification error")
				if fallback {
					// The existing idle barrier gives this test exclusive ownership
					// of the worker hook before another segment is registered.
					verify := w.verify
					w.verify = func(session string, segment sealedGroupSegment) error {
						if session == failedSession {
							return workerErr
						}
						return verify(session, segment)
					}
				}
				for range 80 {
					if err := set.EmitDurable(set.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Target: "https://api.vendor.example/data"})); err != nil {
						t.Fatal(err)
					}
				}
				w.waitIdle()
				for _, shard := range set.open.Shards {
					if len(w.progress[shard.SessionID].sealed) < 2 {
						t.Fatal("fixture did not rotate multiple segments")
					}
				}
				if fallback && !errors.Is(w.progress[failedSession].err, workerErr) {
					t.Fatal("fixture did not trigger worker failure")
				}
				startupTestClose(t, set, r, true)
				awaitSegmentWorker(t, w.done)
				if fallback {
					if _, err := set.verifiers[failedSession].chain.head(); err == nil {
						t.Fatal("failed incremental accumulator unexpectedly supplied a close head")
					}
					if strings.Count(notices.String(), "background verification failed") != 1 {
						t.Fatal("worker failure was not reported exactly once")
					}
				}
				open, openHash := set.Opening()
				trusted := []string{open.SignerKey}
				closed := VerifyReceiptGroup(dir, open.GroupID, trusted)
				if closed.Verdict != GroupValid {
					t.Fatalf("worker close verdict: %+v", closed)
				}
				want := make(map[string]uint64)
				nativeWant := make(map[string]uint64)
				heads := make([]ReceiptGroupShardHead, len(open.Shards))
				for i, shard := range open.Shards {
					if err := recorder.WalkSessionHistory(dir, shard.SessionID, func(recorder.Entry) error { want[shard.SessionID]++; return nil }); err != nil {
						t.Fatal(err)
					}
					heads[i], err = VerifyGroupShardHead(dir, open, openHash, i)
					if err != nil {
						t.Fatal(err)
					}
				}
				paths, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "pipelock.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range paths {
					raw, err := os.ReadFile(filepath.Clean(path))
					if err != nil {
						t.Fatal(err)
					}
					run := filepath.Base(filepath.Dir(filepath.Dir(path)))
					for _, b := range raw {
						if b == '\n' {
							nativeWant[run]++
						}
					}
				}
				if tamper {
					path := filepath.Join(dir, "evidence-"+failedSession+"-0.jsonl")
					raw, err := os.ReadFile(filepath.Clean(path))
					if err != nil {
						t.Fatal(err)
					}
					changed := bytes.Replace(raw, []byte(`"checkpoint"`), []byte(`"badpointxx"`), 1)
					if bytes.Equal(raw, changed) {
						t.Fatal("segment mutation did not change the fixture")
					}
					if err := os.WriteFile(path, changed, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				got, nativeGot := make(map[string]uint64), make(map[string]uint64)
				var mu sync.Mutex
				cfg.StartupVerification = verification.Options{Progress: func(p verification.Progress) error {
					mu.Lock()
					defer mu.Unlock()
					switch p.Kind {
					case "recorder_record":
						got[p.Session] += p.Records
					case "native_ael":
						nativeGot[p.Session] += p.Records
					}
					return nil
				}}
				cfg.Recorder = startupTestRecorder(t, dir, key)
				successor, err := OpenSuccessorReceiptShardSet(cfg, "proxy", 2, 0, open.GroupID)
				if tamper {
					if err == nil || successor != nil {
						t.Fatal("changed closed segment admitted a successor")
					}
					artifacts, globErr := filepath.Glob(filepath.Join(dir, "receipt-group-*-open.json"))
					if globErr != nil || len(artifacts) != 1 {
						t.Fatalf("refused restart published an opening: %v, %v", artifacts, globErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(nativeGot, nativeWant) {
					t.Fatalf("restart work repeated or omitted: recorder=%v want=%v native=%v want=%v", got, want, nativeGot, nativeWant)
				}
				newOpen, newHash := successor.Opening()
				name, err := ReceiptGroupFileName(newOpen.GroupID, "transition")
				if err != nil {
					t.Fatal(err)
				}
				wire, err := readBoundedGroupFile(dir, name)
				if err != nil {
					t.Fatal(err)
				}
				transition, err := UnmarshalReceiptGroupTransition(wire, newOpen, open, newHash, openHash, closed.CloseManifestSHA, trusted)
				if err != nil {
					t.Fatal(err)
				}
				for i, head := range heads {
					want := ReceiptGroupPredecessor{ShardIndex: i, SessionID: head.SessionID, FinalChainSeq: head.FinalChainSeq, FinalChainHash: head.FinalChainHash}
					if transition.Predecessors[i] != want {
						t.Fatalf("successor predecessor %d: %+v want %+v", i, transition.Predecessors[i], want)
					}
				}
				startupTestClose(t, successor, cfg.Recorder, true)
				if result := VerifyReceiptGroup(dir, newOpen.GroupID, trusted); result.Verdict != GroupValid {
					t.Fatalf("restarted group verdict: %+v", result)
				}
			})
		}
	}
}

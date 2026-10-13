// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func reverifyTestGroup(t *testing.T, transient, prefix bool, notices *bytes.Buffer) *ReceiptShardSet {
	t.Helper()
	_, key := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true, MaxEntriesPerFile: closeTestFileEntries}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := PrepareInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Notices: notices}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if transient {
		verify := set.verification.verify
		first := true
		set.verification.verify = func(session string, segment sealedGroupSegment) error {
			if first && (!prefix || set.verifiers[session].native != nil) {
				first = false
				return &os.PathError{Op: "open", Path: segment.path, Err: syscall.EMFILE}
			}
			return verify(session, segment)
		}
	}
	if err := set.Activate(testConfigHash); err != nil {
		t.Fatal(err)
	}
	for range 80 {
		if err := set.EmitDurable(set.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"})); err != nil {
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
	set.verification.waitIdle()
	if transient && !errors.Is(set.verification.err, syscall.EMFILE) {
		t.Fatalf("worker did not encounter the injected error: %v", set.verification.err)
	}
	return set
}

func TestGroupSegmentWorkerTransientErrorReverifiesClose(t *testing.T) {
	for _, prefix := range []bool{false, true} {
		t.Run(map[bool]string{false: "first_segment", true: "after_prefix"}[prefix], func(t *testing.T) {
			var notices bytes.Buffer
			set := reverifyTestGroup(t, true, prefix, &notices)
			if _, err := set.PublishClose(); err != nil {
				t.Fatalf("PublishClose after one transient EMFILE: %v", err)
			}
			if err := set.recorder.Close(); err != nil {
				t.Fatalf("Recorder.Close after recovered publication: %v", err)
			}
			result := VerifyReceiptGroup(set.recorder.Dir(), set.open.GroupID, []string{set.open.SignerKey})
			if result.Verdict != GroupValid {
				t.Fatalf("group verdict=%s: %s", result.Verdict, result.Error)
			}
			if got := strings.Count(notices.String(), "background verification failed"); got != 1 {
				t.Fatalf("failure emitted %d times: %s", got, notices.String())
			}
			t.Log("one worker EMFILE recovered; PublishClose and Recorder.Close succeeded; GROUP_VALID")
		})
	}
}

func TestGroupSegmentWorkerReverificationRefusesChangedEvidence(t *testing.T) {
	for _, transient := range []bool{false, true} {
		for _, mode := range []string{"tampered", "replaced", "missing", "extra", "ael_replaced", "ael_tampered"} {
			t.Run(mode+"/"+map[bool]string{false: "healthy_worker", true: "failed_worker"}[transient], func(t *testing.T) {
				var notices bytes.Buffer
				set := reverifyTestGroup(t, transient, true, &notices)
				session := set.open.Shards[0].SessionID
				if transient {
					for s, p := range set.verification.progress {
						if p.err != nil {
							session = s
							break
						}
					}
				}
				path := filepath.Join(set.recorder.Dir(), "evidence-"+session+"-0.jsonl")
				if strings.HasPrefix(mode, "ael_") {
					path = filepath.Join(set.recorder.Dir(), "ael", set.verifiers[session].chain.run, "recorders", "pipelock.jsonl")
				}
				raw, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "replaced", "ael_replaced":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
				case "missing":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
				case "extra":
					path = filepath.Join(set.recorder.Dir(), "evidence-"+session+"-999.jsonl")
				default:
					raw[0] = '!'
				}
				if mode != "missing" {
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "replaced" || mode == "ael_replaced" {
					requireReplacedGroupTestFile(t, path, info)
				}
				if _, err := set.PublishClose(); err == nil {
					t.Fatal("changed evidence published a close")
				} else {
					t.Logf("PublishClose refused %s: %v", mode, err)
				}
				result := VerifyReceiptGroup(set.recorder.Dir(), set.open.GroupID, []string{set.open.SignerKey})
				if result.Verdict == GroupValid {
					t.Fatal("changed evidence verified GROUP_VALID")
				}
				if transient && strings.Count(notices.String(), "background verification failed") != 1 {
					t.Fatal(notices.String())
				}
			})
		}
	}
}

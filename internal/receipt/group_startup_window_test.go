// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Prepare/Activate permits the original prefix recovery contract, while keeping
// a closed predecessor immutable. These cases also cover the next restart.
func TestStartupPublicationWindow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closed bool
		tail   string
		refuse bool
	}{
		{name: "unrelated_closed", closed: true},
		{name: "unrelated_unclosed"},
		{name: "junk_closed", closed: true, tail: "{}\n", refuse: true},
		{name: "junk_unclosed", tail: "{}\n", refuse: true},
		{name: "torn_unclosed", tail: `{"v":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			startupTestClose(t, first, r, true)
			old, _ := first.Opening()
			r = startupTestRecorder(t, dir, key)
			last, err := OpenSuccessorReceiptShardSet(cfg(r), "proxy", 2, 0, old.GroupID)
			if err != nil {
				t.Fatal(err)
			}
			startupTestClose(t, last, r, tc.closed)
			previous, _ := last.Opening()
			r = startupTestRecorder(t, dir, key)
			prepared, err := PrepareSuccessorReceiptShardSet(cfg(r), "proxy", 2, 0, previous.GroupID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.tail == "" {
				err = os.WriteFile(filepath.Join(dir, "operator-notes.txt"), []byte("notes"), 0o600)
			} else {
				paths, globErr := filepath.Glob(filepath.Join(dir, "evidence-"+previous.Shards[0].SessionID+"-*.jsonl"))
				if globErr != nil || len(paths) == 0 {
					t.Fatalf("paths: %v %v", paths, globErr)
				}
				var f *os.File
				f, err = os.OpenFile(paths[len(paths)-1], os.O_WRONLY|os.O_APPEND, 0)
				if err == nil {
					_, err = f.WriteString(tc.tail)
					_ = f.Close()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			err = prepared.Activate(testConfigHash)
			if (err != nil) != tc.refuse {
				t.Fatalf("activation: %v refuse=%t", err, tc.refuse)
			}
			opening, _ := prepared.Opening()
			name, _ := ReceiptGroupFileName(opening.GroupID, "transition")
			_, transitionErr := os.Stat(filepath.Join(dir, name))
			if tc.refuse {
				if !os.IsNotExist(transitionErr) {
					t.Fatalf("transition published on refusal: %v", transitionErr)
				}
				if !tc.closed && !strings.Contains(err.Error(), "prefix") {
					t.Fatalf("baseline prefix refusal changed: %v", err)
				}
			} else if transitionErr != nil {
				t.Fatal(transitionErr)
			}
			if !tc.closed && tc.tail != "" && !tc.refuse {
				seal := ChainLinkFileName(previous.Shards[0].SessionID)
				if _, err = os.Stat(filepath.Join(dir, seal)); err != nil {
					t.Fatalf("fresh torn tail not sealed: %v", err)
				}
			}
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
			r = startupTestRecorder(t, dir, key)
			terminal, found, err := FindTerminalReceiptGroup(dir, "proxy", []string{previous.SignerKey})
			if err != nil || !found {
				t.Fatalf("terminal: %s %t %v", terminal, found, err)
			}
			_, err = OpenSuccessorReceiptShardSet(cfg(r), "proxy", 2, 0, terminal)
			if (err != nil) != tc.refuse {
				t.Fatalf("next restart: %v refuse=%t", err, tc.refuse)
			}
		})
	}
}

func TestStartupFullDirectoryGuardBeforeOpening(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	r := startupTestRecorder(t, dir, key)
	cfg := EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	set, err := OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, set, r, true)
	opening, _ := set.Opening()
	previous, err := loadClosedGroupPredecessor(dir, opening.GroupID, []string{opening.SignerKey})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "operator-notes.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Recorder = startupTestRecorder(t, dir, key)
	if _, err = openReceiptShardSet(cfg, "proxy", 2, 0, true, previous); err == nil {
		t.Fatal("directory change admitted")
	}
	files, err := filepath.Glob(filepath.Join(dir, "receipt-group-*-open.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("opening published after change: %v %v", files, err)
	}
}

func TestStartupNativeUnrelatedFileWindow(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	r := startupTestRecorder(t, dir, key)
	cfg := EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
	set, err := OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, set, r, true)
	opening, _ := set.Opening()
	cfg.Recorder = startupTestRecorder(t, dir, key)
	next, err := PrepareSuccessorReceiptShardSet(cfg, "proxy", 2, 0, opening.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	run := next.previous.ceremony.proofs[opening.Shards[0].SessionID].session.claim.run
	if err = os.WriteFile(filepath.Join(dir, "ael", run, "operator-notes.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = next.Activate(testConfigHash); err != nil {
		t.Fatalf("unconsumed native file stranded opening: %v", err)
	}
	startupTestClose(t, next, cfg.Recorder, true)
	successor, _ := next.Opening()
	if result := VerifyReceiptGroup(dir, successor.GroupID, []string{opening.SignerKey}); result.Verdict != GroupValid {
		t.Fatalf("successor invalid: %+v", result)
	}
}

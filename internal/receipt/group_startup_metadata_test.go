// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// These mutations exercise the Prepare/Activate window. Metadata does not
// change signed heads; changed content must never reuse a retained proof.
func TestStartupPublicationMetadata(t *testing.T) {
	for _, tc := range []struct {
		name               string
		incomplete, refuse bool
	}{
		{name: "chmod_segment"},
		{name: "hardlink_segment"},
		{name: "identical_segment"},
		{name: "older_opening"},
		{name: "native_manifests"},
		{name: "native_recorders"},
		{name: "empty_writer_lock"},
		{name: "older_opening", incomplete: true},
		{name: "native_directory_mode"},
		{name: "own_artifact_metadata"},
		{name: "junk", refuse: true},
		{name: "same_size_edit", refuse: true},
		{name: "symlink", refuse: true},
		{name: "extra_segment", refuse: true},
		{name: "own_manifest_bytes", refuse: true},
		{name: "native_manifest_bytes", refuse: true},
		{name: "retained_head", refuse: true},
	} {
		name := tc.name
		if tc.incomplete {
			name += "_incomplete"
		}
		t.Run(name, func(t *testing.T) {
			prepared, r, older, previous := startupPreparedWindow(t, !tc.incomplete)
			dir := r.Dir()
			paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+previous.Shards[0].SessionID+"-*.jsonl"))
			if err != nil || len(paths) == 0 {
				t.Fatalf("segments: %v %v", paths, err)
			}
			path := paths[len(paths)-1]
			switch tc.name {
			case "chmod_segment":
				err = os.Chmod(path, 0o640) // #nosec G302 -- deliberate metadata mutation in an isolated test directory.
			case "hardlink_segment":
				err = os.Link(path, filepath.Join(t.TempDir(), "linked-segment"))
			case "identical_segment":
				raw, readErr := os.ReadFile(filepath.Clean(path))
				if readErr != nil {
					t.Fatal(readErr)
				}
				err = os.WriteFile(path+".tmp", raw, 0o600)
				if err == nil {
					err = os.Rename(path+".tmp", path)
				}
			case "older_opening", "own_artifact_metadata", "own_manifest_bytes":
				group := older
				if tc.name != "older_opening" {
					group = previous
				}
				n, _ := ReceiptGroupFileName(group.GroupID, "open")
				path = filepath.Join(dir, n)
				if tc.name == "own_manifest_bytes" {
					err = startupAppendFile(path, " ")
				} else {
					err = os.Chmod(path, 0o640) // #nosec G302 -- deliberate metadata mutation in an isolated test directory.
				}
			case "native_manifests":
				paths, err = filepath.Glob(filepath.Join(dir, "ael", "*", "manifest.json"))
				if err == nil {
					for _, p := range paths {
						if err = os.Chmod(p, 0o640); err != nil { // #nosec G302 -- deliberate metadata mutation in an isolated test directory.
							break
						}
					}
				}
			case "native_recorders":
				paths = nil
				for _, shard := range previous.Shards {
					run := prepared.previous.ceremony.proofs[shard.SessionID].session.claim.run
					paths = append(paths, filepath.Join(dir, "ael", run, "recorders"))
				}
				if err == nil {
					for _, p := range paths {
						raw, e := os.ReadFile(filepath.Clean(filepath.Join(p, "pipelock.jsonl")))
						if e != nil {
							t.Fatal(e)
						}
						old := filepath.Join(t.TempDir(), "old-recorders")
						if e = os.Rename(p, old); e != nil {
							t.Fatal(e)
						}
						if e = os.Mkdir(p, 0o750); e != nil {
							t.Fatal(e)
						}
						if e = os.WriteFile(filepath.Join(p, "pipelock.jsonl"), raw, 0o600); e != nil {
							t.Fatal(e)
						}
					}
				}
			case "native_directory_mode", "native_manifest_bytes":
				run := prepared.previous.ceremony.proofs[previous.Shards[0].SessionID].session.claim.run
				if tc.name == "native_directory_mode" {
					err = os.Chmod(filepath.Join(dir, "ael", run, "recorders"), 0o700) // #nosec G302 -- this path is a test directory, not a file.
				} else {
					err = startupAppendFile(filepath.Join(dir, "ael", run, "manifest.json"), " ")
				}
			case "empty_writer_lock":
				err = os.WriteFile(filepath.Join(dir, "writer-"+previous.Shards[0].SessionID+".lock"), nil, 0o600)
			case "junk":
				err = startupAppendFile(path, "{}\n")
			case "same_size_edit":
				raw, e := os.ReadFile(filepath.Clean(path))
				if e != nil {
					t.Fatal(e)
				}
				raw[0] = '['
				err = os.WriteFile(path, raw, 0o600)
			case "symlink":
				target := filepath.Join(t.TempDir(), "old-segment")
				err = os.Rename(path, target)
				if err == nil {
					err = os.Symlink(target, path)
				}
			case "extra_segment":
				err = os.WriteFile(filepath.Join(dir, "evidence-"+previous.Shards[0].SessionID+"-999999.jsonl"), []byte("{}\n"), 0o600)
			case "retained_head":
				prepared.previous.ceremony.proofs[previous.Shards[0].SessionID].head.FinalChainHash = "different"
				err = os.Chmod(path, 0o640) // #nosec G302 -- deliberate metadata mutation in an isolated test directory.
			}
			if err != nil {
				t.Fatal(err)
			}
			err = prepared.Activate(testConfigHash)
			if (err != nil) != tc.refuse {
				t.Fatalf("activation=%v refuse=%t", err, tc.refuse)
			}
			open, _ := prepared.Opening()
			n, _ := ReceiptGroupFileName(open.GroupID, "transition")
			_, statErr := os.Stat(filepath.Join(dir, n))
			if tc.refuse {
				if !os.IsNotExist(statErr) {
					t.Fatalf("transition published on refusal: %v", statErr)
				}
				return
			}
			if statErr != nil {
				t.Fatal(statErr)
			}
			startupTestClose(t, prepared, r, true)
			if result := VerifyReceiptGroup(dir, open.GroupID, []string{previous.SignerKey}); result.Verdict != GroupValid {
				t.Fatalf("closed successor: %+v", result)
			}
			r = startupTestRecorder(t, dir, prepared.signer)
			_, err = OpenSuccessorReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: prepared.signer, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, open.GroupID)
			if err != nil {
				t.Fatalf("next restart: %v", err)
			}
		})
	}
}

func startupPreparedWindow(t *testing.T, closed bool) (*ReceiptShardSet, *recorder.Recorder, ReceiptGroupOpen, ReceiptGroupOpen) {
	t.Helper()
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
	older, _ := first.Opening()
	r = startupTestRecorder(t, dir, key)
	middle, err := OpenSuccessorReceiptShardSet(cfg(r), "proxy", 2, 0, older.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, middle, r, true)
	middleOpen, _ := middle.Opening()
	r = startupTestRecorder(t, dir, key)
	last, err := OpenSuccessorReceiptShardSet(cfg(r), "proxy", 2, 0, middleOpen.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	startupTestClose(t, last, r, closed)
	previous, _ := last.Opening()
	r = startupTestRecorder(t, dir, key)
	prepared, err := PrepareSuccessorReceiptShardSet(cfg(r), "proxy", 2, 0, previous.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	return prepared, r, older, previous
}

func startupAppendFile(path, tail string) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(tail)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

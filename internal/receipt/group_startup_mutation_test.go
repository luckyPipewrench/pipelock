// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// These mutations exercise the existing group, chain and inventory contracts.
func TestStartupBaselineMutationsRefuseBeforePublication(t *testing.T) {
	root := t.TempDir()
	{
		if err := os.MkdirAll(root, 0o750); err != nil {
			t.Fatal(err)
		}
		_, key := generateTestKey(t)
		var groups []ReceiptGroupOpen
		for i := range 3 {
			r, err := recorder.New(recorder.Config{Enabled: true, Dir: root, SignCheckpoints: true}, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			cfg := EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
			var s *ReceiptShardSet
			if i == 0 {
				s, err = OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
			} else {
				s, err = OpenSuccessorReceiptShardSet(cfg, "proxy", 2, 0, groups[i-1].GroupID)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range s.Emitters() {
				if err = e.EmitSessionClose("graceful_shutdown"); err != nil {
					t.Fatal(err)
				}
				if err = e.EmitTranscriptRoot(e.Session()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.PublishClose(); err != nil {
				t.Fatal(err)
			}
			o, _ := s.Opening()
			groups = append(groups, o)
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
		}
		b, _ := json.Marshal(groups)
		if err := os.WriteFile(filepath.Join(root, "groups.meta"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "key.meta"), key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var groups []ReceiptGroupOpen
	b, err := os.ReadFile(filepath.Clean(filepath.Join(root, "groups.meta")))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &groups); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Clean(filepath.Join(root, "key.meta")))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"modified_segment", "deleted_segment", "extra_segment", "reordered_records", "reordered_segments", "native_signature_only", "missing_transition", "missing_transition_incomplete", "missing_prior_close", "unequal_manifest_count", "changed_trusted_key", "identical_duplicate_record", "torn_tail", "bad_complete_tail"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			err := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				rel, _ := filepath.Rel(root, p)
				dst := filepath.Join(dir, rel)
				if d.IsDir() {
					return os.MkdirAll(dst, 0o750)
				}
				if strings.HasSuffix(p, ".meta") {
					return nil
				}
				raw, e := os.ReadFile(filepath.Clean(p)) // #nosec G122 -- copying the private fixture created above; no concurrent fixture writer.
				if e != nil {
					return e
				}
				return os.WriteFile(dst, raw, 0o600)
			})
			if err != nil {
				t.Fatal(err)
			}
			last := groups[2]
			path := filepath.Join(dir, "evidence-"+last.Shards[0].SessionID+"-0.jsonl")
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			write := func(p string, b []byte) {
				if e := os.WriteFile(p, b, 0o600); e != nil {
					t.Fatal(e)
				}
			}
			remove := func(p string) {
				if e := os.Remove(p); e != nil {
					t.Fatal(e)
				}
			}
			trusted := []string{last.SignerKey}
			switch mutation {
			case "modified_segment":
				write(path, bytes.Replace(raw, []byte(`"checkpoint"`), []byte(`"badpointxx"`), 1))
			case "deleted_segment":
				remove(path)
			case "extra_segment":
				write(filepath.Join(dir, "evidence-"+last.Shards[0].SessionID+"-999999.jsonl"), []byte("{}\n"))
			case "reordered_records":
				lines := bytes.Split(raw, []byte{'\n'})
				lines[0], lines[1] = lines[1], lines[0]
				write(path, bytes.Join(lines, []byte{'\n'}))
			case "reordered_segments":
				lines := bytes.Split(raw, []byte{'\n'})
				write(path, bytes.Join(lines[2:], []byte{'\n'}))
				write(filepath.Join(dir, "evidence-"+last.Shards[0].SessionID+"-2.jsonl"), append(bytes.Join(lines[:2], []byte{'\n'}), '\n'))
			case "identical_duplicate_record":
				lines := bytes.Split(raw, []byte{'\n'})
				write(path, append(append(bytes.Clone(lines[0]), '\n'), raw...))
			case "native_signature_only":
				paths, _ := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "pipelock.jsonl"))
				b, e := os.ReadFile(paths[0])
				if e != nil {
					t.Fatal(e)
				}
				lines := bytes.Split(b, []byte{'\n'})
				parts := bytes.Split(lines[0], []byte{'.'})
				if len(parts) != 2 {
					t.Fatal("AEL wire shape")
				}
				sig := bytes.Clone(parts[1])
				if sig[0] == 'A' {
					sig[0] = 'B'
				} else {
					sig[0] = 'A'
				}
				lines[0] = append(append(bytes.Clone(parts[0]), '.'), sig...)
				write(paths[0], bytes.Join(lines, []byte{'\n'}))
			case "missing_transition":
				remove(filepath.Join(dir, "receipt-group-"+last.GroupID+"-transition.json"))
			case "missing_transition_incomplete":
				remove(filepath.Join(dir, "receipt-group-"+last.GroupID+"-close.json"))
				remove(filepath.Join(dir, "receipt-group-"+last.GroupID+"-transition.json"))
			case "missing_prior_close":
				remove(filepath.Join(dir, "receipt-group-"+groups[1].GroupID+"-close.json"))
			case "unequal_manifest_count":
				p := filepath.Join(dir, "receipt-group-"+last.GroupID+"-close.json")
				b, e := os.ReadFile(filepath.Clean(p))
				if e != nil {
					t.Fatal(e)
				}
				var manifest ReceiptGroupClose
				if e = json.Unmarshal(b, &manifest); e != nil {
					t.Fatal(e)
				}
				manifest.Shards = manifest.Shards[:1]
				b, e = json.Marshal(manifest)
				if e != nil {
					t.Fatal(e)
				}
				write(p, b)
			case "changed_trusted_key":
				trusted = []string{strings.Repeat("0", 64)}
			case "torn_tail":
				write(path, append(raw, []byte(`{"torn":`)...))
			case "bad_complete_tail":
				write(path, append(raw, []byte("{}\n")...))
			}
			r, e := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, ed25519.PrivateKey(key))
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = r.Close() }()
			cfg := EmitterConfig{Recorder: r, PrivKey: ed25519.PrivateKey(key), ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}
			if mutation == "changed_trusted_key" {
				_, err = loadClosedGroupPredecessor(dir, last.GroupID, trusted)
			} else {
				_, err = OpenSuccessorReceiptShardSet(cfg, "proxy", 2, 0, last.GroupID)
			}
			if err == nil {
				t.Fatal("baseline mutation admitted successor")
			}
			files, e := filepath.Glob(filepath.Join(dir, "receipt-group-*-open.json"))
			if e != nil || len(files) != len(groups) {
				t.Fatalf("successor published after refusal: %v %v", files, e)
			}
		})
	}
}

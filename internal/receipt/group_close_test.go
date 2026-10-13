// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type closeErrorReader struct{ err error }

func (r closeErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestGroupCloseFileReadFailure(t *testing.T) {
	set := closeTestGroup(t, 80)
	v := set.verifiers[set.open.Shards[0].SessionID]
	want := io.ErrUnexpectedEOF
	for name, file := range v.files {
		shard := recorder.SessionHistoryShard{Name: name, Info: file.info}
		if err := v.checkFile(shard, closeErrorReader{err: want}); !errors.Is(err, want) {
			t.Fatalf("read failure=%v", err)
		}
		shard.Info = nil
		if err := v.checkFile(shard, bytes.NewReader(nil)); err == nil {
			t.Fatal("file with no identity was accepted")
		}
		return
	}
	t.Fatal("fixture has no verified file")
}

func TestGroupCloseRefusesMissingSegmentVerifier(t *testing.T) {
	set := closeTestGroup(t, 0)
	delete(set.verifiers, set.open.Shards[0].SessionID)
	if _, err := set.PublishClose(); err == nil {
		t.Fatal("close accepted a segment without its shard verifier")
	}
	paths, err := filepath.Glob(filepath.Join(set.recorder.Dir(), "receipt-group-*-close.json"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("failed segment verification published a close: files=%v err=%v", paths, err)
	}
}

func TestGroupCloseSegmentRefusesMissingNativeManifest(t *testing.T) {
	set := closeTestGroup(t, 80)
	chain, err := newGroupShardVerifier(set.open, set.openHash, 0)
	if err != nil {
		t.Fatal(err)
	}
	known := set.verifiers[set.open.Shards[0].SessionID]
	if err := os.Remove(filepath.Join(set.recorder.Dir(), "ael", known.chain.run, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	v := &groupCloseVerifier{chain: chain, files: make(map[string]verifiedGroupFile)}
	path := filepath.Join(set.recorder.Dir(), "evidence-"+chain.shard.SessionID+"-0.jsonl")
	if err := v.seal(set.recorder.Dir(), path); err == nil {
		t.Fatal("missing native manifest was accepted")
	}
	if _, err := v.head(set.recorder.Dir()); err == nil {
		t.Fatal("failed verifier returned a close head")
	}
}

const closeTestFileEntries = 16

func closeTestGroup(t *testing.T, actions int) *ReceiptShardSet {
	t.Helper()
	_, key := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), SignCheckpoints: true, MaxEntriesPerFile: closeTestFileEntries}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	set, err := OpenInitialReceiptShardSet(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range actions {
		if err := set.Emit(set.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"})); err != nil {
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
	return set
}

func TestGroupCloseVerifierStateErrors(t *testing.T) {
	for _, mode := range []string{"sticky", "duplicate_segment", "missing_native", "invalid_location", "unverified_segment", "native_suffix", "missing_verifier", "invalid_v1", "invalid_v2", "valid_v2", "invalid_signer"} {
		t.Run(mode, func(t *testing.T) {
			set := closeTestGroup(t, 80)
			if _, err := set.PublishClose(); err != nil {
				t.Fatal(err)
			}
			v := set.verifiers[set.open.Shards[0].SessionID]
			var err error
			switch mode {
			case "sticky":
				v.err = errors.New("prior verification failure")
				if got := v.seal(set.recorder.Dir(), "unused"); !errors.Is(got, v.err) {
					t.Fatal(got)
				}
				_, err = v.head(set.recorder.Dir())
			case "duplicate_segment":
				for name := range v.files {
					err = v.seal(set.recorder.Dir(), filepath.Join(set.recorder.Dir(), name))
					break
				}
			case "missing_native":
				v.native = nil
				_, err = v.head(set.recorder.Dir())
			case "invalid_location":
				_, err = v.head(filepath.Join(set.recorder.Dir(), "absent"))
			case "unverified_segment":
				for name := range v.files {
					delete(v.files, name)
					break
				}
				_, err = v.head(set.recorder.Dir())
			case "native_suffix":
				path := filepath.Join(set.recorder.Dir(), "ael", v.chain.run, "recorders", "pipelock.jsonl")
				raw, readErr := os.ReadFile(filepath.Clean(path))
				if readErr != nil {
					t.Fatal(readErr)
				}
				raw = append(raw, []byte("bad suffix\n")...)
				if writeErr := os.WriteFile(path, raw, 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
				fresh, newErr := ael.NewRunVerifier(set.recorder.Dir(), v.chain.run, set.open.SignerKey)
				if newErr != nil {
					t.Fatal(newErr)
				}
				v.native = fresh
				_, err = v.head(set.recorder.Dir())
			case "missing_verifier":
				delete(set.verifiers, set.open.Shards[0].SessionID)
				// Finalization is deliberately one-shot; use a fresh group to
				// reach the missing mandatory state on its first close.
				other := closeTestGroup(t, 0)
				other.open.Shards = slices.Clone(other.open.Shards)
				other.open.Shards[0].SessionID = "missing"
				_, err = other.PublishClose()
			case "invalid_signer":
				other := closeTestGroup(t, 0)
				other.signer = nil
				_, err = other.PublishClose()
			case "invalid_v1":
				v.chain.count++
				_, err = v.chain.head()
			case "invalid_v2":
				v.chain.v2.Add(contractreceipt.EvidenceReceipt{})
				_, err = v.chain.head()
			case "valid_v2":
				v.chain.v2 = NewEvidenceChainWalker([]string{fixtureSignerKey(t)}, contractreceipt.ChainVerifyOptions{})
				entries, readErr := recorder.ReadHistoryEntries(runFile(filepath.Join(fixtureRunChainsDir, "valid"), fixtureRun1))
				if readErr != nil {
					t.Fatal(readErr)
				}
				for i, entry := range entries {
					ev, ok, extractErr := contractreceipt.EvidenceReceiptFromEntry(i, entry)
					if extractErr != nil {
						t.Fatal(extractErr)
					}
					if ok {
						v.chain.v2.Add(ev)
					}
				}
				if v.chain.v2.Count() == 0 {
					t.Fatal("v2 fixture matched no records")
				}
				if _, err := v.chain.head(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid verifier state accepted")
			}
		})
	}
}

func TestGroupShardVerifierRejectsMalformedTerminalEntries(t *testing.T) {
	for _, mode := range []string{"after_root", "bad_checkpoint", "bad_root", "bad_v2", "valid_v2", "after_close", "bad_first_open", "close_without_open"} {
		t.Run(mode, func(t *testing.T) {
			set := closeTestGroup(t, 0)
			if _, err := set.PublishClose(); err != nil {
				t.Fatal(err)
			}
			v := set.verifiers[set.open.Shards[0].SessionID].chain
			entries, err := recorder.ReadHistoryEntries(filepath.Join(set.recorder.Dir(), "evidence-"+v.shard.SessionID+"-0.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var opening, closing recorder.Entry
			for _, entry := range entries {
				if entry.Type != recorderEntryType {
					continue
				}
				r, decodeErr := receiptFromEntry(entry)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				if r.ActionRecord.SessionControl.Kind == SessionControlOpen {
					opening = entry
				}
				if r.ActionRecord.SessionControl.Kind == SessionControlClose {
					closing = entry
				}
			}
			entry := closing
			v.rooted = false
			v.closed = false
			switch mode {
			case "after_root":
				v.rooted = true
			case "bad_checkpoint":
				entry.Type = "checkpoint"
				entry.Detail = json.RawMessage(`{}`)
			case "bad_root":
				entry.Type = transcriptRootEntryType
				entry.Detail = json.RawMessage(`{}`)
			case "bad_v2":
				entry.Type = "evidence_receipt"
				entry.Detail = json.RawMessage(`{"unknown":1}`)
			case "valid_v2":
				fixture, readErr := recorder.ReadHistoryEntries(runFile(filepath.Join(fixtureRunChainsDir, "valid"), fixtureRun1))
				if readErr != nil {
					t.Fatal(readErr)
				}
				found := false
				for _, candidate := range fixture {
					if candidate.Type == "evidence_receipt" {
						entry = candidate
						entry.SessionID = v.shard.SessionID
						found = true
						break
					}
				}
				if !found {
					t.Fatal("fixture lacks v2 entry")
				}
			case "after_close":
				v.closed = true
			case "bad_first_open":
				v.count = 0
			case "close_without_open":
				v.opened = false
			}
			entry.RawDetail = nil
			entry.Sequence = entries[len(entries)-1].Sequence + 1
			entry.PrevHash = v.lastEntryHash
			entry.Hash = recorder.ComputeHash(entry)
			err = v.add(entry)
			if mode == "valid_v2" {
				if err != nil {
					t.Fatal(err)
				}
				if v.v2.Count() == 0 {
					t.Fatal("v2 entry was not verified")
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %s (opening=%s)", mode, opening.Hash)
			}
		})
	}
}

func TestGroupCloseOnlyDecodesUnverifiedSegments(t *testing.T) {
	for _, actions := range []int{128, 1024} {
		t.Run(strconv.Itoa(actions), func(t *testing.T) {
			set := closeTestGroup(t, actions)
			before := 0
			for _, v := range set.verifiers {
				before += v.chain.entryIndex
			}
			if before < actions {
				t.Fatalf("no verified history: decoded=%d actions=%d", before, actions)
			}
			if _, err := set.PublishClose(); err != nil {
				t.Fatal(err)
			}
			after := 0
			for i, shard := range set.open.Shards {
				v := set.verifiers[shard.SessionID]
				after += v.chain.entryIndex
				full, err := VerifyGroupShardHead(set.recorder.Dir(), set.open, set.openHash, i)
				if err != nil {
					t.Fatal(err)
				}
				cached, err := v.head(set.recorder.Dir())
				if err != nil {
					t.Fatal(err)
				}
				if full != cached {
					t.Fatalf("incremental head differs from full verifier: full=%+v cached=%+v", full, cached)
				}
			}
			bound := len(set.open.Shards) * (closeTestFileEntries + 1)
			if got := after - before; got > bound {
				t.Fatalf("close decoded %d entries, tail bound=%d", got, bound)
			}
			t.Logf("actions=%d decoded_at_close=%d bound=%d", actions, after-before, bound)
		})
	}
}

func TestGroupCloseRefusesChangedDiskHistory(t *testing.T) {
	for _, mode := range []string{"altered_rotated", "removed_rotated", "replaced_rotated", "reordered_rotated", "torn_tail", "extra_segment", "native_prefix", "native_replaced"} {
		t.Run(mode, func(t *testing.T) {
			set := closeTestGroup(t, 80)
			v := set.verifiers[set.open.Shards[0].SessionID]
			names := make([]string, 0, len(v.files))
			for name := range v.files {
				names = append(names, name)
			}
			slices.Sort(names)
			if len(names) < 2 {
				t.Fatal("fixture lacks previously verified rotated files")
			}
			path := filepath.Join(set.recorder.Dir(), names[0])
			if mode == "torn_tail" {
				paths, err := filepath.Glob(filepath.Join(set.recorder.Dir(), "evidence-"+v.chain.shard.SessionID+"-*.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				slices.SortFunc(paths, func(a, b string) int {
					_, sa, _ := recorder.ParseEvidenceFilename(filepath.Base(a))
					_, sb, _ := recorder.ParseEvidenceFilename(filepath.Base(b))
					if sa < sb {
						return -1
					}
					if sa > sb {
						return 1
					}
					return 0
				})
				path = paths[len(paths)-1]
			}
			if mode == "native_prefix" || mode == "native_replaced" {
				path = filepath.Join(set.recorder.Dir(), "ael", v.chain.run, "recorders", "pipelock.jsonl")
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "removed_rotated":
				err = os.Remove(path)
			case "replaced_rotated", "native_replaced":
				err = os.Rename(path, path+".old")
				if err == nil {
					err = os.WriteFile(path, raw, 0o600)
				}
			case "reordered_rotated":
				lines := bytes.Split(raw, []byte{'\n'})
				lines[0], lines[1] = lines[1], lines[0]
				err = os.WriteFile(path, bytes.Join(lines, []byte{'\n'}), 0o600)
			case "torn_tail":
				err = os.Truncate(path, info.Size()-1)
			case "extra_segment":
				err = os.WriteFile(filepath.Join(set.recorder.Dir(), "evidence-"+v.chain.shard.SessionID+"-99999999.jsonl"), raw, 0o600)
			case "native_prefix":
				raw[0] ^= 1
				err = os.WriteFile(path, raw, 0o600)
			default:
				raw = bytes.Replace(raw, []byte(`"hash":`), []byte(`"hAsh":`), 1)
				err = os.WriteFile(path, raw, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "replaced_rotated" || mode == "native_replaced" {
				requireReplacedGroupTestFile(t, path, info)
			}
			if mode != "removed_rotated" {
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := set.PublishClose(); err == nil {
				t.Fatal("changed evidence published a group close")
			}
			name, err := ReceiptGroupFileName(set.open.GroupID, "close")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(set.recorder.Dir(), name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("close was published: %v", err)
			}
		})
	}
}

func requireReplacedGroupTestFile(t *testing.T, path string, original os.FileInfo) {
	t.Helper()
	actual, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(original, actual) {
		t.Fatal("replacement precondition failed: original file identity retained")
	}
}

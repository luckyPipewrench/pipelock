// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// addUnrelatedEvidence writes count recorder sessions that belong to no
// receipt group, each beside an empty sidecar and an empty stray file.
func addUnrelatedEvidence(t *testing.T, dir, tag string, count int) {
	t.Helper()
	for i := range count {
		other := fmt.Sprintf("unrelated%s%03d", tag, i)
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Record(recorder.Entry{SessionID: other, Type: "decision", Transport: "fetch", Summary: "unrelated session"}); err != nil {
			t.Fatal(err)
		}
		if err := rec.Close(); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"chain-link-" + other + ".json", "stray-" + other} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// addEmptyFiles writes count empty files that are not evidence.
func addEmptyFiles(t *testing.T, dir, tag string, count int) {
	t.Helper()
	for i := range count {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("unrelated-%s-%03d", tag, i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

type groupScaleFixture struct {
	dir     string
	keys    []ed25519.PrivateKey
	trusted []string
	shards  int
}

func newGroupScaleFixture(t *testing.T) *groupScaleFixture {
	t.Helper()
	f := &groupScaleFixture{dir: t.TempDir(), shards: 2}
	for range 2 {
		_, key := generateTestKey(t)
		f.keys = append(f.keys, key)
		f.trusted = append(f.trusted, fmt.Sprintf("%x", key.Public()))
	}
	return f
}

// run opens a group (or a successor of previous), emits receipts per shard,
// and seals and closes it, returning the group ID.
func (f *groupScaleFixture) run(t *testing.T, generation int, previous string, receiptsPerShard, maxEntriesPerFile int) string {
	t.Helper()
	key := f.keys[generation]
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: f.dir, SignCheckpoints: true, MaxEntriesPerFile: maxEntriesPerFile}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	cfg := EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, PriorSignerKeys: f.trusted[:generation]}
	var set *ReceiptShardSet
	if previous == "" {
		set, err = OpenInitialReceiptShardSet(cfg, "proxy", f.shards, 0)
	} else {
		set, err = OpenSuccessorReceiptShardSet(cfg, "proxy", f.shards, 0, previous)
	}
	if err != nil {
		t.Fatalf("open generation %d: %v", generation, err)
	}
	for range f.shards * receiptsPerShard {
		opts := set.Admit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"})
		if err := set.EmitDurable(opts); err != nil {
			t.Fatal(err)
		}
	}
	for _, emitter := range set.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatalf("close generation %d: %v", generation, err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
	return open.GroupID
}

func (f *groupScaleFixture) assertValid(t *testing.T, groupID, when string) {
	t.Helper()
	if result := VerifyReceiptGroup(f.dir, groupID, f.trusted); result.Verdict != GroupValid {
		t.Fatalf("%s: group %s verdict %+v", when, groupID, result)
	}
}

// TestReceiptGroupLifecycleIgnoresUnrelatedEvidence is the reproduction of
// unrelated files breaking a group: 260 empty files used to fail the close,
// turn a closed GROUP_VALID group into GROUP_INVALID and refuse a successor.
func TestReceiptGroupLifecycleIgnoresUnrelatedEvidence(t *testing.T) {
	f := newGroupScaleFixture(t)
	addEmptyFiles(t, f.dir, "a", 260)
	first := f.run(t, 0, "", 2, 0)
	f.assertValid(t, first, "after closing beside 260 unrelated files")

	addEmptyFiles(t, f.dir, "b", 260)
	addUnrelatedEvidence(t, f.dir, "c", 300)
	if _, err := recorder.ListSessions(f.dir); !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
		t.Fatalf("display control: ListSessions err = %v, want the display budget refusal", err)
	}
	f.assertValid(t, first, "closed group after more unrelated files and 300 unrelated sessions")

	second := f.run(t, 1, first, 2, 0)
	f.assertValid(t, first, "predecessor after successor")
	f.assertValid(t, second, "successor")
	if _, err := VerifyReceiptGroups(f.dir, f.trusted, func(r ReceiptGroupResult) error {
		if r.Verdict != GroupValid {
			return fmt.Errorf("group %s verdict %s", r.GroupID, r.Verdict)
		}
		return nil
	}); err != nil {
		t.Fatalf("group inventory beside unrelated files: %v", err)
	}
}

// Eight chains reproduce the original long-run directory shape: each chain
// fits the display directory budget, while their combined history does not.
// Rotate every entry to exercise the file-count failure without a load test.
func TestReceiptGroupEightChainsPast745Files(t *testing.T) {
	f := newGroupScaleFixture(t)
	f.shards = 8
	first := f.run(t, 0, "", 93, 1)
	open := mustOpening(t, f.dir, first, f.trusted)
	total := 0
	for _, shard := range open.Shards {
		files, err := filepath.Glob(filepath.Join(f.dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(files) == 0 || len(files) > recorder.MaxEvidenceReadDirectoryEntries {
			t.Fatalf("shard %s: %d files, want 1..%d: %v", shard.SessionID, len(files), recorder.MaxEvidenceReadDirectoryEntries, err)
		}
		total += len(files)
	}
	if total < 745 {
		t.Fatalf("eight-chain fixture: %d files, want at least 745", total)
	}
	t.Logf("eight-chain group closed with %d evidence files", total)
	f.assertValid(t, first, "eight-chain group past 745 files")
	second := f.run(t, 1, first, 1, 0)
	f.assertValid(t, first, "eight-chain predecessor")
	f.assertValid(t, second, "eight-chain successor")
}

// TestAnchoringWalkReadsLongChainBesideUnrelatedEvidence covers the anchoring
// and verification extraction of a single chain that spans more shards than
// the display directory budget, next to unrelated sessions and files.
func TestAnchoringWalkReadsLongChainBesideUnrelatedEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a chain with hundreds of shards")
	}
	dir := t.TempDir()
	_, key := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true, MaxEntriesPerFile: 1}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	emitter := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	const emitted = recorder.MaxEvidenceReadDirectoryEntries + 10 + 1 // receipts including session_open
	for range emitted - 1 {
		if err := emitter.Emit(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	addEmptyFiles(t, dir, "a", 300)
	addUnrelatedEvidence(t, dir, "b", 20)

	count := 0
	if err := WalkReceiptsFromSessionDir(dir, "proxy", func(Receipt) error { count++; return nil }); err != nil || count != emitted {
		t.Fatalf("anchoring walk: %d of %d receipts, err %v", count, emitted, err)
	}
	receipts, err := ExtractReceiptsFromSessionDir(dir, "proxy")
	if err != nil || len(receipts) != emitted {
		t.Fatalf("verification extraction: %d of %d receipts, err %v", len(receipts), emitted, err)
	}
	if result := VerifyChain(receipts, fmt.Sprintf("%x", key.Public())); !result.Valid {
		t.Fatalf("long chain invalid: %+v", result)
	}
	stop := errors.New("stop")
	if err := WalkReceiptsFromSessionDir(dir, "proxy", func(Receipt) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("interrupted anchoring walk error = %v", err)
	}
	if err := WalkReceiptsFromSessionDir(dir, "proxy", nil); err == nil {
		t.Fatal("nil consumer accepted")
	}
}

// TestReceiptGroupClosesPastDisplayBudget closes, verifies and succeeds a
// group whose own shard sessions each span more shards than the display
// directory budget, as a long multi-chain run does.
func TestReceiptGroupClosesPastDisplayBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a receipt group with hundreds of shards per session")
	}
	f := newGroupScaleFixture(t)
	addUnrelatedEvidence(t, f.dir, "a", 100)
	first := f.run(t, 0, "", recorder.MaxEvidenceReadDirectoryEntries+10, 1)
	open := mustOpening(t, f.dir, first, f.trusted)
	for _, shard := range open.Shards {
		files, err := filepath.Glob(filepath.Join(f.dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(files) <= recorder.MaxEvidenceReadDirectoryEntries {
			t.Fatalf("shard %s has %d files, want more than %d: %v", shard.SessionID, len(files), recorder.MaxEvidenceReadDirectoryEntries, err)
		}
	}
	f.assertValid(t, first, "closed group past the display budget")
	second := f.run(t, 1, first, 1, 0)
	f.assertValid(t, second, "successor of a long group")

	// Malformed evidence in the group's own history still fails closed.
	shardFiles, err := filepath.Glob(filepath.Join(f.dir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(shardFiles) == 0 {
		t.Fatal(err)
	}
	victim := shardFiles[len(shardFiles)/2]
	if err := os.WriteFile(victim, []byte("{\"v\":3}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := VerifyReceiptGroup(f.dir, first, f.trusted); result.Verdict == GroupValid {
		t.Fatalf("group with a malformed shard verified: %+v", result)
	}
}

func mustOpening(t *testing.T, dir, groupID string, trusted []string) ReceiptGroupOpen {
	t.Helper()
	name, err := ReceiptGroupFileName(groupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readBoundedGroupFile(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	open, err := UnmarshalReceiptGroupOpen(raw, trusted)
	if err != nil {
		t.Fatal(err)
	}
	return open
}

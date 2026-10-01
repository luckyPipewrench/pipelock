// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeadTrustedVerifierRepeatedRotations(t *testing.T) {
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	keyA, keyB := hex.EncodeToString(pubA), hex.EncodeToString(pubB)
	stream, err := NewHeadTrustedVerifier(keyB, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	var prior Receipt
	prevHash := GenesisHash
	// Reusing two keys across many segments must not grow segment/trust state.
	for i := range 200 {
		priv := privA
		if i%2 == 1 {
			priv = privB
		}
		record := validActionRecord()
		record.ChainPrevHash = prevHash
		if i > 0 {
			record.KeyTransition = &KeyTransition{PriorSignerKey: prior.SignerKey, PriorChainSeq: prior.ActionRecord.ChainSeq, PriorChainHash: prevHash}
		}
		r, signErr := Sign(record, priv)
		if signErr != nil {
			t.Fatal(signErr)
		}
		if err := stream.Add(r); err != nil {
			t.Fatal(err)
		}
		prevHash, err = ReceiptHash(r)
		if err != nil {
			t.Fatal(err)
		}
		prior = r
		if len(stream.v.segments) != 0 || len(stream.v.trusted) != 1 || len(stream.v.signerKeys) > 2 {
			t.Fatal("stream retained segment history")
		}
	}
	full, _, err := stream.Finish()
	if err != nil || full.ReceiptCount != 200 || len(full.SignerKeys) != 2 || full.SignerKeys[0] != keyA || full.SignerKeys[1] != keyB {
		t.Fatalf("summary=%+v err=%v", full, err)
	}
}

func TestHeadTrustedVerifierLifecycleSpill(t *testing.T) {
	pub, priv := generateTestKey(t)
	key := hex.EncodeToString(pub)
	stream, err := NewHeadTrustedVerifier(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	prevHash := ""
	var receipts []Receipt
	for i := range runCacheLimit + 5 {
		open := fixedSessionOpen()
		open.RunNonce = fmt.Sprintf("run-%d", i)
		open.OpenNonce = fmt.Sprintf("open-%d", i)
		open.ChainOpenSeq = uint64(i)
		if i == 0 {
			open.GenesisAnchorHead = ""
			open.GenesisAnchorLog = ""
			open.GenesisHash = ComputeSessionOpenGenesis(open)
			prevHash = open.GenesisHash
		} else {
			open.PriorChainHead = prevHash
			open.PriorChainSeq = uint64(i) - 1
		}
		record := validActionRecord()
		record.ChainSeq = uint64(i)
		record.ChainPrevHash = prevHash
		record.RunNonce = open.RunNonce
		record.SessionControl = &SessionControl{Kind: SessionControlOpen, Open: &open}
		r, signErr := Sign(record, priv)
		if signErr != nil {
			t.Fatal(signErr)
		}
		if err := stream.Add(r); err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, r)
		prevHash, err = ReceiptHash(r)
		if err != nil {
			t.Fatal(err)
		}
	}
	if batch := VerifyChainTrusted(receipts, []string{key}); !batch.Valid {
		t.Fatalf("batch positive control: %s", batch.Error)
	}
	if _, _, err := stream.Finish(); err != nil {
		t.Fatal(err)
	}
	store := stream.v.runStore
	if store.dir == "" || len(store.cache) > runCacheLimit {
		t.Fatal("lifecycle cache did not spill")
	}
	dir := store.dir
	// Re-open the first run with a newly signed, correctly linked receipt.
	// Replay detection must still consult identities evicted from memory.
	open := fixedSessionOpen()
	open.RunNonce = "run-0"
	open.OpenNonce = "replayed-open"
	open.ChainOpenSeq = uint64(len(receipts))
	open.PriorChainHead = prevHash
	open.PriorChainSeq = uint64(len(receipts)) - 1
	record := validActionRecord()
	record.ChainSeq = uint64(len(receipts))
	record.ChainPrevHash = prevHash
	record.RunNonce = open.RunNonce
	record.SessionControl = &SessionControl{Kind: SessionControlOpen, Open: &open}
	r, err := Sign(record, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Add(r); err == nil || !strings.Contains(err.Error(), "duplicate session_open") {
		t.Fatalf("spilled replay err=%v", err)
	}
	if _, _, err := stream.Finish(); err == nil {
		t.Fatal("failed walk released a summary")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temporary lifecycle state remains: %v", err)
	}
}

func TestBoundedRunStoreFailuresAndClose(t *testing.T) {
	s := &boundedRunStore{dir: t.TempDir()}
	if err := s.write(storedRun{Run: "run", Open: "open", Closed: true}); err != nil {
		t.Fatal(err)
	}
	open, closed, found, err := s.read("run")
	if err != nil || !found || !closed || open != "open" {
		t.Fatalf("read=(%q,%v,%v,%v)", open, closed, found, err)
	}
	if err := s.verify(); err != nil {
		t.Fatalf("untouched spill: %v", err)
	}
	if err := os.WriteFile(s.path("run"), []byte(`{"Run":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	clear(s.cache)
	if _, _, _, err := s.read("run"); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	if err := os.WriteFile(s.path("run"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.read("run"); err == nil {
		t.Fatal("malformed stored lifecycle accepted")
	}
}

func TestBoundedRunStoreDetectsMissingIdentity(t *testing.T) {
	s := &boundedRunStore{dir: t.TempDir()}
	if err := s.write(storedRun{Run: "run", Open: "open", Closed: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.verify(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path("run")); err != nil {
		t.Fatal(err)
	}
	if err := s.verify(); err == nil {
		t.Fatal("deleted lifecycle identity accepted")
	}
	clear(s.cache)
	if _, _, _, err := s.read("run"); err == nil {
		t.Fatal("missing identity looked like an unseen run")
	}
	if err := s.write(storedRun{Run: "run", Open: "new-open"}); err == nil {
		t.Fatal("recreated identity hid deletion")
	}
}

func TestHeadTrustedVerifierSpillFailureLatches(t *testing.T) {
	pub, priv := generateTestKey(t)
	key := hex.EncodeToString(pub)
	stream, err := NewHeadTrustedVerifier(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	chain := buildChain(t, priv, 1)
	if err := stream.Add(chain[0]); err != nil {
		t.Fatal(err)
	}
	stream.v.runStore.dir = t.TempDir()
	stream.v.runStore.files = 1
	if _, _, err := stream.Finish(); err == nil {
		t.Fatal("missing spill set released checkpoint")
	}
	if err := stream.Add(chain[0]); err == nil {
		t.Fatal("spill failure did not latch")
	}
}

func TestHeadTrustedVerifierFailureLatch(t *testing.T) {
	pub, priv := generateTestKey(t)
	key := hex.EncodeToString(pub)
	for _, tc := range []struct {
		name   string
		count  uint64
		mutate func([]Receipt)
	}{
		{name: "signature", mutate: func(chain []Receipt) { chain[1].ActionRecord.Target += "/changed" }},
		{name: "prefix_ahead", count: 4},
		{name: "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream, err := NewHeadTrustedVerifier(key, tc.count)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stream.Close() })
			chain := buildChain(t, priv, 3)
			if tc.mutate != nil {
				tc.mutate(chain)
			}
			if tc.name != "empty" {
				for _, r := range chain {
					_ = stream.Add(r)
				}
			}
			if _, _, err := stream.Finish(); err == nil {
				t.Fatal("invalid walk released summary")
			}
		})
	}
	if _, err := NewHeadTrustedVerifier("", 0); err == nil {
		t.Fatal("empty live trust key accepted")
	}
}

func TestBoundedRunStoreAuthenticationAndRollback(t *testing.T) {
	for _, change := range []string{"stale_mac", "authentic_old_state"} {
		t.Run(change, func(t *testing.T) {
			s := &boundedRunStore{dir: t.TempDir()}
			if err := s.write(storedRun{Run: "run", Open: "open"}); err != nil {
				t.Fatal(err)
			}
			old, err := os.ReadFile(s.path("run"))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.write(storedRun{Run: "run", Open: "open", Closed: true}); err != nil {
				t.Fatal(err)
			}
			if err := s.verify(); err != nil {
				t.Fatal(err)
			}
			if change == "stale_mac" {
				var disk diskRun
				if err := json.Unmarshal(old, &disk); err != nil {
					t.Fatal(err)
				}
				disk.Record = json.RawMessage(`{"Run":"run","Open":"changed","Closed":false}`)
				old, err = json.Marshal(disk)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(s.path("run"), old, 0o600); err != nil {
				t.Fatal(err)
			}
			clear(s.cache)
			if _, _, _, err := s.read("run"); err == nil {
				t.Fatal("mutated/replayed state was consumed")
			}
			if err := s.verify(); err == nil {
				t.Fatal("mutated/replayed set accepted")
			}
		})
	}
}

func TestWriteSpillFileReplacesPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "run")
	if err := os.Symlink(victim, target); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeSpillFile(dir, target, []byte("spill")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Clean(victim)); string(got) != "keep" {
		t.Fatalf("spill write followed a planted symlink; victim now %q", got)
	}
	info, err := os.Lstat(target)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("target still a symlink or missing: %v %v", info, err)
	}
}

func TestSweepStaleSpillDirs(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	stale := filepath.Join(root, spillDirPrefix+"stale")
	fresh := filepath.Join(root, spillDirPrefix+"fresh")
	other := filepath.Join(root, "unrelated-dir")
	for _, d := range []string{stale, fresh, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-2 * staleSpillAge)
	for _, d := range []string{stale, other} {
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	sweepStaleSpillDirs(root, now)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale spill dir not removed: %v", err)
	}
	for _, d := range []string{fresh, other} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("%s should survive: %v", d, err)
		}
	}
}

func TestBoundedRunStoreLookupReadsOnlyItsRun(t *testing.T) {
	s := &boundedRunStore{}
	t.Cleanup(func() { _ = s.close() })
	const runs = runCacheLimit + 40
	for i := range runs {
		if err := s.write(storedRun{Run: fmt.Sprintf("run-%03d", i), Open: fmt.Sprintf("open-%03d", i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if s.dir == "" {
		t.Fatal("store never spilled")
	}
	// Remove an unrelated run's file. A lookup for another run must not need
	// the whole set, but the final audit must still catch the deletion.
	if err := os.Remove(s.path("run-001")); err != nil {
		t.Fatal(err)
	}
	s.cache = nil
	open, _, found, err := s.read("run-090")
	if err != nil || !found || open != "open-090" {
		t.Fatalf("lookup touched more than its own run: open=%q found=%v err=%v", open, found, err)
	}
	if err := s.verify(); err == nil {
		t.Fatal("full-set audit missed a deleted lifecycle identity")
	}
}

func TestBoundedRunStoreLookupRejectsRolledBackFile(t *testing.T) {
	s := &boundedRunStore{}
	t.Cleanup(func() { _ = s.close() })
	for i := range runCacheLimit + 2 {
		if err := s.write(storedRun{Run: fmt.Sprintf("run-%03d", i), Open: "o"}); err != nil {
			t.Fatal(err)
		}
	}
	path := s.path("run-065")
	old, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.write(storedRun{Run: "run-065", Open: "o", Closed: true}); err != nil {
		t.Fatal(err)
	}
	// Restore the older, authentically MAC'd record: a rollback from closed to open.
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	s.cache = nil
	if _, _, _, err := s.read("run-065"); err == nil {
		t.Fatal("lookup accepted a rolled-back lifecycle record")
	}
}

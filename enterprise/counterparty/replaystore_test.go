//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	replayHashA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	replayHashB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	replayHashC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	replayHashD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	replayHashE = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func sampleEntry(nonce, transferPayload string) ReplayEntry {
	return ReplayEntry{
		NonceKey: NonceKey{SideRecordKeyID: "k", SenderIdentity: "a", ReceiverIdentity: "b", Nonce: nonce},
		TransferKey: TransferKey{
			SenderIdentity:     "a",
			ReceiverIdentity:   "b",
			PayloadHash:        transferPayload,
			SenderReceiptID:    "s",
			ReceiverReceiptID:  "r",
			SenderActionHash:   replayHashC,
			ReceiverActionHash: replayHashD,
		},
		RecordHash: replayHashE,
		Timestamp:  time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}
}

func TestFileReplayStoreRejectsDuplicateNonceAndTransfer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	entry := sampleEntry("nonce-1", replayHashA)
	if err := store.CommitIfNew(entry); err != nil {
		t.Fatalf("first CommitIfNew: %v", err)
	}
	if err := store.CommitIfNew(entry); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("duplicate nonce CommitIfNew error = %v, want ErrReplayConflict", err)
	}

	// Same transfer, new nonce -> transfer conflict.
	reSigned := sampleEntry("nonce-2", replayHashA)
	if err := store.CommitIfNew(reSigned); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("duplicate transfer CommitIfNew error = %v, want ErrReplayConflict", err)
	}

	// A genuinely new transfer + nonce succeeds.
	if err := store.CommitIfNew(sampleEntry("nonce-3", replayHashB)); err != nil {
		t.Fatalf("new entry CommitIfNew: %v", err)
	}
}

func TestFileReplayStoreDurableAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	entry := sampleEntry("nonce-1", replayHashA)
	if err := store.CommitIfNew(entry); err != nil {
		t.Fatalf("CommitIfNew: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("reopen OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.CommitIfNew(entry); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("committed entry not durable across reopen: err = %v, want ErrReplayConflict", err)
	}
}

func TestFileReplayStoreCorruptLineFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	if err := os.WriteFile(path, []byte("{not valid json\n"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, err := OpenFileReplayStore(path); err == nil {
		t.Fatal("OpenFileReplayStore accepted a corrupt line, want fail closed")
	}
}

func TestFileReplayStoreUnknownFieldFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	if err := os.WriteFile(path, []byte(`{"nonce_key":{},"transfer_key":{},"unexpected":true}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := OpenFileReplayStore(path); err == nil {
		t.Fatal("OpenFileReplayStore accepted an unknown field, want fail closed")
	}
}

func TestFileReplayStoreTrailingTokensFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	encoded, err := json.Marshal(sampleEntry("nonce-1", replayHashA))
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, []byte(` trailing-junk`+"\n")...), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := OpenFileReplayStore(path); err == nil {
		t.Fatal("OpenFileReplayStore accepted trailing tokens after an entry, want fail closed")
	}
}

func TestFileReplayStoreCommitAfterCloseFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = store.CommitIfNew(sampleEntry("nonce-1", replayHashA))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("CommitIfNew after Close error = %v, want a non-conflict fail-closed error", err)
	}
}

func TestOpenFileReplayStoreErrors(t *testing.T) {
	if _, err := OpenFileReplayStore(""); err == nil {
		t.Fatal("OpenFileReplayStore(empty path) = nil, want error")
	}
	// Parent path is a regular file, so MkdirAll for the store dir fails.
	dir := t.TempDir()
	fileAsParent := filepath.Join(dir, "afile")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := OpenFileReplayStore(filepath.Join(fileAsParent, "sub", "replay.jsonl")); err == nil {
		t.Fatal("OpenFileReplayStore(file-as-parent) = nil, want error")
	}
	// Path is an existing directory, so OpenFile fails.
	if _, err := OpenFileReplayStore(dir); err == nil {
		t.Fatal("OpenFileReplayStore(dir path) = nil, want error")
	}
}

// TestFileReplayStoreCrossProcessRejectsDuplicate proves the cross-process
// fail-open fix: two store handles on the same file (standing in for two
// processes, each with its own in-memory index) cannot both accept the same
// entry, because CommitIfNew re-indexes under an exclusive file lock first.
func TestFileReplayStoreCrossProcessRejectsDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	a, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	entry := sampleEntry("nonce-1", replayHashA)
	if err := a.CommitIfNew(entry); err != nil {
		t.Fatalf("A CommitIfNew: %v", err)
	}
	if err := b.CommitIfNew(entry); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("B CommitIfNew of A's entry = %v, want ErrReplayConflict (cross-process fail-open)", err)
	}
	// A genuinely new entry through B still succeeds after re-indexing A's line.
	if err := b.CommitIfNew(sampleEntry("nonce-2", replayHashB)); err != nil {
		t.Fatalf("B CommitIfNew new entry: %v", err)
	}
	if err := a.CommitIfNew(sampleEntry("nonce-2", replayHashB)); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("A CommitIfNew of B's entry = %v, want ErrReplayConflict", err)
	}
}

func TestFileReplayStoreTruncatedWhileRunningFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitIfNew(sampleEntry("nonce-1", replayHashA)); err != nil {
		t.Fatalf("first CommitIfNew: %v", err)
	}
	// Truncate the store out from under the running process.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	err = store.CommitIfNew(sampleEntry("nonce-2", replayHashB))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("CommitIfNew after truncation = %v, want a non-conflict fail-closed error", err)
	}
}

func TestValidateReplayEntryRejects(t *testing.T) {
	valid := sampleEntry("nonce-1", replayHashA)
	mutations := map[string]func(*ReplayEntry){
		"empty side key id":         func(e *ReplayEntry) { e.NonceKey.SideRecordKeyID = "" },
		"empty nonce sender":        func(e *ReplayEntry) { e.NonceKey.SenderIdentity = "" },
		"empty nonce receiver":      func(e *ReplayEntry) { e.NonceKey.ReceiverIdentity = "" },
		"empty nonce":               func(e *ReplayEntry) { e.NonceKey.Nonce = "" },
		"empty transfer sender":     func(e *ReplayEntry) { e.TransferKey.SenderIdentity = "" },
		"empty transfer receiver":   func(e *ReplayEntry) { e.TransferKey.ReceiverIdentity = "" },
		"bad payload hash":          func(e *ReplayEntry) { e.TransferKey.PayloadHash = "x" },
		"empty sender receipt id":   func(e *ReplayEntry) { e.TransferKey.SenderReceiptID = "" },
		"empty receiver receipt id": func(e *ReplayEntry) { e.TransferKey.ReceiverReceiptID = "" },
		"bad sender action hash":    func(e *ReplayEntry) { e.TransferKey.SenderActionHash = "x" },
		"bad receiver action hash":  func(e *ReplayEntry) { e.TransferKey.ReceiverActionHash = "x" },
		"bad record hash":           func(e *ReplayEntry) { e.RecordHash = "x" },
		"zero timestamp":            func(e *ReplayEntry) { e.Timestamp = time.Time{} },
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			e := valid
			mut(&e)
			if err := validateReplayEntry(e); err == nil {
				t.Fatalf("validateReplayEntry(%s) = nil, want error", name)
			}
		})
	}
	if err := validateReplayEntry(valid); err != nil {
		t.Fatalf("validateReplayEntry(valid) = %v", err)
	}
}

func TestFileReplayStoreEmptyEntryLineFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := OpenFileReplayStore(path); err == nil {
		t.Fatal("OpenFileReplayStore accepted a semantically empty entry, want fail closed")
	}
}

func TestFileReplayStoreIncompleteEntryLineFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	raw := []byte(`{"nonce_key":{"Nonce":"nonce-1"},"transfer_key":{"PayloadHash":"` + replayHashA + `"},"record_hash":"` + replayHashB + `"}` + "\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := OpenFileReplayStore(path); err == nil {
		t.Fatal("OpenFileReplayStore accepted an incomplete replay entry, want fail closed")
	}
}

func TestFileReplayStoreDuplicateKeyLineFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	if err := os.WriteFile(path, []byte(`{"record_hash":"sha256:aa","record_hash":"sha256:bb"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := OpenFileReplayStore(path); err == nil {
		t.Fatal("OpenFileReplayStore accepted a duplicate-key line, want fail closed")
	}
}

func TestFileReplayStoreIncompleteTrailingLineFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	encoded, err := json.Marshal(sampleEntry("nonce-1", replayHashA))
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	// A complete JSON object with NO trailing newline = a torn/partial write.
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := OpenFileReplayStore(path); err == nil {
		t.Fatal("OpenFileReplayStore accepted an incomplete trailing line, want fail closed")
	}
}

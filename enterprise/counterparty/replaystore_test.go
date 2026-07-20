//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
		RecordHash:        replayHashE,
		Timestamp:         time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
		TransferTimestamp: time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}
}

func sampleEntryAt(nonce, transferPayload string, ts time.Time) ReplayEntry {
	entry := sampleEntry(nonce, transferPayload)
	entry.Timestamp = ts
	entry.TransferTimestamp = ts
	return entry
}

func TestReplayStoreCompactRemovesOnlyEntriesOlderThanBefore(t *testing.T) {
	cutoff := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		open func(t *testing.T) CompactableReplayStore
	}{
		"mem": {
			open: func(t *testing.T) CompactableReplayStore {
				t.Helper()
				return NewMemReplayStore()
			},
		},
		"file": {
			open: func(t *testing.T) CompactableReplayStore {
				t.Helper()
				store, err := OpenFileReplayStore(filepath.Join(t.TempDir(), "replay.jsonl"))
				if err != nil {
					t.Fatalf("OpenFileReplayStore: %v", err)
				}
				t.Cleanup(func() { _ = store.Close() })
				return store
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			store := tc.open(t)
			old := sampleEntryAt("nonce-old", replayHashA, cutoff.Add(-time.Nanosecond))
			atCutoff := sampleEntryAt("nonce-cutoff", replayHashB, cutoff)
			recent := sampleEntryAt("nonce-recent", replayHashC, cutoff.Add(time.Nanosecond))
			for _, entry := range []ReplayEntry{old, atCutoff, recent} {
				if err := store.CommitIfNew(entry); err != nil {
					t.Fatalf("CommitIfNew(%s): %v", entry.NonceKey.Nonce, err)
				}
			}

			removed, err := store.Compact(cutoff)
			if err != nil {
				t.Fatalf("Compact: %v", err)
			}
			if removed != 1 {
				t.Fatalf("Compact removed %d entries, want 1", removed)
			}

			// This is correct only because VerifyCounterparty checks freshness
			// before CommitIfNew. The store intentionally allows a pruned,
			// aged nonce/transfer to be committed again.
			if err := store.CommitIfNew(old); err != nil {
				t.Fatalf("pruned old entry CommitIfNew = %v, want nil", err)
			}
			if err := store.CommitIfNew(atCutoff); !errors.Is(err, ErrReplayConflict) {
				t.Fatalf("cutoff survivor CommitIfNew = %v, want ErrReplayConflict", err)
			}
			if err := store.CommitIfNew(recent); !errors.Is(err, ErrReplayConflict) {
				t.Fatalf("recent survivor CommitIfNew = %v, want ErrReplayConflict", err)
			}
			if err := store.CommitIfNew(sampleEntryAt("nonce-new", replayHashD, cutoff.Add(time.Second))); err != nil {
				t.Fatalf("new entry after Compact CommitIfNew: %v", err)
			}
		})
	}
}

func TestReplayStoreCompactRetainsFreshTransferKeyWhenNonceTimestampIsOld(t *testing.T) {
	cutoff := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		open func(t *testing.T) CompactableReplayStore
	}{
		"mem": {
			open: func(t *testing.T) CompactableReplayStore {
				t.Helper()
				return NewMemReplayStore()
			},
		},
		"file": {
			open: func(t *testing.T) CompactableReplayStore {
				t.Helper()
				store, err := OpenFileReplayStore(filepath.Join(t.TempDir(), "replay.jsonl"))
				if err != nil {
					t.Fatalf("OpenFileReplayStore: %v", err)
				}
				t.Cleanup(func() { _ = store.Close() })
				return store
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			store := tc.open(t)
			original := sampleEntryAt("nonce-old", replayHashA, cutoff.Add(-time.Nanosecond))
			original.TransferTimestamp = cutoff.Add(time.Nanosecond)
			if err := store.CommitIfNew(original); err != nil {
				t.Fatalf("CommitIfNew original: %v", err)
			}
			removed, err := store.Compact(cutoff)
			if err != nil {
				t.Fatalf("Compact: %v", err)
			}
			if removed != 0 {
				t.Fatalf("Compact removed %d entries, want 0 while transfer key is still fresh", removed)
			}

			reSigned := sampleEntryAt("nonce-new", replayHashA, cutoff.Add(time.Second))
			reSigned.TransferTimestamp = original.TransferTimestamp
			if err := store.CommitIfNew(reSigned); !errors.Is(err, ErrReplayConflict) {
				t.Fatalf("same transfer after Compact = %v, want ErrReplayConflict", err)
			}
		})
	}
}

func TestReplayStoreCompactDoesNotDropFreshReusedNonce(t *testing.T) {
	cutoff := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		open func(t *testing.T) CompactableReplayStore
	}{
		"mem": {
			open: func(t *testing.T) CompactableReplayStore {
				t.Helper()
				return NewMemReplayStore()
			},
		},
		"file": {
			open: func(t *testing.T) CompactableReplayStore {
				t.Helper()
				store, err := OpenFileReplayStore(filepath.Join(t.TempDir(), "replay.jsonl"))
				if err != nil {
					t.Fatalf("OpenFileReplayStore: %v", err)
				}
				t.Cleanup(func() { _ = store.Close() })
				return store
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			store := tc.open(t)
			original := sampleEntryAt("nonce-reused", replayHashA, cutoff.Add(-time.Nanosecond))
			original.TransferTimestamp = cutoff.Add(time.Nanosecond)
			if err := store.CommitIfNew(original); err != nil {
				t.Fatalf("CommitIfNew original: %v", err)
			}
			if _, err := store.Compact(cutoff); err != nil {
				t.Fatalf("Compact original: %v", err)
			}

			reusedNonce := sampleEntryAt("nonce-reused", replayHashB, cutoff.Add(time.Second))
			if err := store.CommitIfNew(reusedNonce); err != nil {
				t.Fatalf("CommitIfNew fresh reused nonce: %v", err)
			}
			if _, err := store.Compact(cutoff); err != nil {
				t.Fatalf("Compact mixed entries: %v", err)
			}

			thirdTransferSameNonce := sampleEntryAt("nonce-reused", replayHashC, cutoff.Add(2*time.Second))
			if err := store.CommitIfNew(thirdTransferSameNonce); !errors.Is(err, ErrReplayConflict) {
				t.Fatalf("same fresh nonce after mixed-entry Compact = %v, want ErrReplayConflict", err)
			}
		})
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

func TestFileReplayStoreCompactDurableAcrossReopen(t *testing.T) {
	cutoff := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	old := sampleEntryAt("nonce-old", replayHashA, cutoff.Add(-time.Nanosecond))
	recent := sampleEntryAt("nonce-recent", replayHashB, cutoff.Add(time.Nanosecond))
	if err := store.CommitIfNew(old); err != nil {
		t.Fatalf("old CommitIfNew: %v", err)
	}
	if err := store.CommitIfNew(recent); err != nil {
		t.Fatalf("recent CommitIfNew: %v", err)
	}
	removed, err := store.Compact(cutoff)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if removed != 1 {
		t.Fatalf("Compact removed %d entries, want 1", removed)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("reopen OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.CommitIfNew(recent); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("recent survivor after reopen CommitIfNew = %v, want ErrReplayConflict", err)
	}
	// The pruned entry is outside the caller-guaranteed freshness window, so
	// freshness, not durable replay state, is what blocks replay of aged records.
	if err := reopened.CommitIfNew(old); err != nil {
		t.Fatalf("old pruned entry after reopen CommitIfNew = %v, want nil", err)
	}
}

func TestFileReplayStoreCompactPersistsPartiallyPrunedKeysAcrossReopen(t *testing.T) {
	cutoff := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}

	original := sampleEntryAt("nonce-old", replayHashA, cutoff.Add(-time.Nanosecond))
	original.TransferTimestamp = cutoff.Add(time.Nanosecond)
	if err := store.CommitIfNew(original); err != nil {
		t.Fatalf("CommitIfNew original: %v", err)
	}
	if _, err := store.Compact(cutoff); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("reopen OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	reusedPrunedNonce := sampleEntryAt("nonce-old", replayHashB, cutoff.Add(time.Second))
	if err := reopened.CommitIfNew(reusedPrunedNonce); err != nil {
		t.Fatalf("reused pruned nonce after reopen CommitIfNew = %v, want nil", err)
	}
	reSignedFreshTransfer := sampleEntryAt("nonce-new", replayHashA, cutoff.Add(time.Second))
	reSignedFreshTransfer.TransferTimestamp = original.TransferTimestamp
	if err := reopened.CommitIfNew(reSignedFreshTransfer); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("fresh transfer after reopen CommitIfNew = %v, want ErrReplayConflict", err)
	}
}

func TestFileReplayStoreCompactSkipsReplacementWhenNothingChanges(t *testing.T) {
	cutoff := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	entry := sampleEntryAt("nonce-recent", replayHashA, cutoff.Add(time.Nanosecond))
	if err := store.CommitIfNew(entry); err != nil {
		t.Fatalf("CommitIfNew: %v", err)
	}
	activeFile := store.file
	removed, err := store.Compact(cutoff)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if removed != 0 {
		t.Fatalf("Compact removed %d entries, want 0", removed)
	}
	if store.file != activeFile {
		t.Fatal("Compact replaced the store file for a no-op compaction")
	}
	if err := store.CommitIfNew(entry); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("survivor after no-op Compact = %v, want ErrReplayConflict", err)
	}
	newEntry := sampleEntryAt("nonce-new", replayHashB, cutoff.Add(time.Second))
	if err := store.CommitIfNew(newEntry); err != nil {
		t.Fatalf("CommitIfNew new entry after no-op Compact: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("reopen after no-op Compact and append: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.CommitIfNew(newEntry); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("new entry after reopen CommitIfNew = %v, want ErrReplayConflict", err)
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

func TestFileReplayStoreBackfillsLegacyTransferTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	entry := sampleEntry("nonce-legacy", replayHashA)
	legacy := struct {
		NonceKey    NonceKey    `json:"nonce_key"`
		TransferKey TransferKey `json:"transfer_key"`
		RecordHash  string      `json:"record_hash"`
		Timestamp   time.Time   `json:"ts"`
	}{
		NonceKey:    entry.NonceKey,
		TransferKey: entry.TransferKey,
		RecordHash:  entry.RecordHash,
		Timestamp:   entry.Timestamp,
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy entry: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatalf("seed legacy replay store: %v", err)
	}

	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore legacy entry: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitIfNew(entry); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("legacy entry CommitIfNew = %v, want ErrReplayConflict", err)
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

func TestFileReplayStoreCompactAfterCloseFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = store.Compact(time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("Compact after Close error = %v, want a non-conflict fail-closed error", err)
	}
}

func TestFileReplayStoreCloseWaitsForActiveOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}

	store.opMu.Lock()
	done := make(chan error, 1)
	go func() {
		done <- store.Close()
	}()
	select {
	case err := <-done:
		t.Fatalf("Close returned while operation lock was held: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	store.opMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after operation lock was released")
	}
}

func TestFileReplayStoreCompactTempCreateFailureFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-only directory semantics are platform-specific on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("chmod-based permission denial is ineffective when running as root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitIfNew(sampleEntry("nonce-1", replayHashA)); err != nil {
		t.Fatalf("CommitIfNew: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- test forces an unwritable dir to exercise temp-create failure
		t.Fatalf("chmod read-only dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- test cleanup restoring dir perms

	_, err = store.Compact(time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("Compact with unwritable temp dir = %v, want non-conflict fail-closed error", err)
	}
	err = store.CommitIfNew(sampleEntry("nonce-2", replayHashB))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("CommitIfNew after temp create failure = %v, want unhealthy non-conflict error", err)
	}
}

func TestFileReplayStoreCompactCorruptAppendedLineFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitIfNew(sampleEntry("nonce-1", replayHashA)); err != nil {
		t.Fatalf("CommitIfNew: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) // #nosec G304 -- test path from t.TempDir()
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err := f.WriteString(`{"record_hash":"sha256:aa","record_hash":"sha256:bb"}` + "\n"); err != nil {
		_ = f.Close()
		t.Fatalf("append corrupt line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close append: %v", err)
	}

	_, err = store.Compact(time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("Compact with corrupt appended line = %v, want non-conflict fail-closed error", err)
	}
	err = store.CommitIfNew(sampleEntry("nonce-2", replayHashB))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("CommitIfNew after failed Compact = %v, want unhealthy non-conflict error", err)
	}
}

func TestFileReplayStoreCompactRevalidatesAlreadyIndexedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitIfNew(sampleEntry("nonce-1", replayHashA)); err != nil {
		t.Fatalf("CommitIfNew: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- test path from t.TempDir()
	if err != nil {
		t.Fatalf("open corrupt rewrite: %v", err)
	}
	if _, err := f.WriteAt([]byte("["), 0); err != nil {
		_ = f.Close()
		t.Fatalf("corrupt already-indexed line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close corrupt rewrite: %v", err)
	}

	_, err = store.Compact(time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("Compact with corrupt already-indexed line = %v, want non-conflict fail-closed error", err)
	}
	err = store.CommitIfNew(sampleEntry("nonce-2", replayHashB))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("CommitIfNew after already-indexed corruption = %v, want unhealthy non-conflict error", err)
	}
}

func TestFileReplayStoreCompactRejectsAlreadyIndexedMissingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	store, err := OpenFileReplayStore(path)
	if err != nil {
		t.Fatalf("OpenFileReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitIfNew(sampleEntry("nonce-1", replayHashA)); err != nil {
		t.Fatalf("CommitIfNew: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat replay store: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- test path from t.TempDir()
	if err != nil {
		t.Fatalf("open newline rewrite: %v", err)
	}
	if _, err := f.WriteAt([]byte(" "), info.Size()-1); err != nil {
		_ = f.Close()
		t.Fatalf("remove already-indexed newline: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close newline rewrite: %v", err)
	}

	_, err = store.Compact(time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("Compact with missing already-indexed newline = %v, want non-conflict fail-closed error", err)
	}
	err = store.CommitIfNew(sampleEntry("nonce-2", replayHashB))
	if err == nil || errors.Is(err, ErrReplayConflict) {
		t.Fatalf("CommitIfNew after missing newline = %v, want unhealthy non-conflict error", err)
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
		"zero transfer timestamp":   func(e *ReplayEntry) { e.TransferTimestamp = time.Time{} },
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

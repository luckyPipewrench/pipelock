//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestLegalHoldStoreLifecycleAndPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "holds.json")
	store, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore: %v", err)
	}
	created := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if err := store.Add(LegalHold{ID: "hold-a", Scope: "agent-a", Reason: "active review", Created: created}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %#o, want 0600", got)
	}
	released := created.Add(time.Hour)
	if err := store.Release("hold-a", released); err != nil {
		t.Fatalf("Release: %v", err)
	}
	holds := store.List()
	if len(holds) != 1 || holds[0].Released == nil || !holds[0].Released.Equal(released) {
		t.Fatalf("holds = %+v, want released hold", holds)
	}
}

func TestLegalHoldStoreReturnedRecordsDoNotAliasInternalState(t *testing.T) {
	t.Parallel()

	store, err := OpenLegalHoldStore(filepath.Join(t.TempDir(), "holds.json"))
	if err != nil {
		t.Fatalf("OpenLegalHoldStore: %v", err)
	}
	created := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if err := store.Add(LegalHold{ID: "hold-a", Scope: "agent-a", Reason: "review", Created: created}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	released := created.Add(time.Hour)
	if err := store.Release("hold-a", released); err != nil {
		t.Fatalf("Release: %v", err)
	}
	returned := store.List()
	*returned[0].Released = released.Add(time.Hour)
	if got := store.List(); got[0].Released == nil || !got[0].Released.Equal(released) {
		t.Fatalf("List returned an alias that mutated internal state: %+v", got)
	}
}

func TestLegalHoldStoreConcurrentHandlesDoNotLoseWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "holds.json")
	const writers = 20
	stores := make([]*LegalHoldStore, writers)
	for i := range stores {
		var err error
		stores[i], err = OpenLegalHoldStore(path)
		if err != nil {
			t.Fatalf("OpenLegalHoldStore[%d]: %v", i, err)
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	for i := range stores {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errCh <- stores[i].Add(LegalHold{
				ID:      fmt.Sprintf("hold-%02d", i),
				Scope:   fmt.Sprintf("agent-%02d", i),
				Reason:  "concurrent review",
				Created: time.Date(2026, 7, 10, 12, i, 0, 0, time.UTC),
			})
		}(i)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent Add: %v", err)
		}
	}

	store, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore(final): %v", err)
	}
	if got := len(store.List()); got != writers {
		t.Fatalf("records = %d, want %d", got, writers)
	}
}

func TestLegalHoldStoreConcurrentAddAndReleaseDoNotLoseWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "holds.json")
	creator, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore(creator): %v", err)
	}
	created := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if err := creator.Add(LegalHold{ID: "hold-a", Scope: "agent-a", Reason: "review", Created: created}); err != nil {
		t.Fatalf("Add(initial): %v", err)
	}
	adder, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore(adder): %v", err)
	}
	releaser, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore(releaser): %v", err)
	}

	start := make(chan struct{})
	errCh := make(chan error, 2)
	go func() {
		<-start
		errCh <- adder.Add(LegalHold{ID: "hold-b", Scope: "agent-b", Reason: "review", Created: created})
	}()
	go func() {
		<-start
		errCh <- releaser.Release("hold-a", created.Add(time.Hour))
	}()
	close(start)
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent mutation: %v", err)
		}
	}

	final, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore(final): %v", err)
	}
	holds := final.List()
	if len(holds) != 2 || holds[0].ID != "hold-a" || holds[0].Released == nil || holds[1].ID != "hold-b" {
		t.Fatalf("holds = %+v, want released hold-a and active hold-b", holds)
	}
}

func TestLegalHoldStoreCorruptFileFailsClosed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		data string
	}{
		{name: "truncated", data: `{"id":`},
		{name: "null root", data: `null`},
		{name: "unknown field", data: `[{"id":"hold-a","scope":"agent-a","reason":"review","created":"2026-07-10T12:00:00Z","unexpected":true}]`},
		{name: "duplicate field", data: `[{"id":"hold-a","id":"hold-b","scope":"agent-a","reason":"review","created":"2026-07-10T12:00:00Z"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "holds.json")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := OpenLegalHoldStore(path); err == nil {
				t.Fatal("OpenLegalHoldStore accepted corrupt or ambiguous JSON")
			}
		})
	}
}

func TestOpenLegalHoldStoreRejectsInsecureOrNonRegularFile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "group readable", mode: os.FileMode(0o640)},
		{name: "world readable", mode: os.FileMode(0o644)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "holds.json")
			secureMode := os.FileMode(0o600)
			if err := os.WriteFile(path, []byte("[]"), secureMode); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			if _, err := OpenLegalHoldStore(path); err == nil {
				t.Fatalf("OpenLegalHoldStore accepted mode %#o", tc.mode)
			}
		})
	}

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "holds.json")
		dirMode := os.FileMode(0o700)
		if err := os.Mkdir(path, dirMode); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if _, err := OpenLegalHoldStore(path); err == nil {
			t.Fatal("OpenLegalHoldStore accepted a non-regular path")
		}
	})
}

func TestOpenLegalHoldStoreRejectsSymlinkAfterOpen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "holds.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLegalHoldStore(link); err == nil {
		t.Fatal("OpenLegalHoldStore accepted a symlink")
	}
}

func TestLegalHoldStoreSnapshotReloadsAndPostStartCorruptionFailsClosed(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "holds.json")
	reader, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore(reader): %v", err)
	}
	writer, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore(writer): %v", err)
	}
	if err := writer.Add(LegalHold{ID: "hold-a", Scope: "agent-a", Reason: "review", Created: time.Now().UTC()}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	holds, err := reader.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(holds) != 1 || holds[0].ID != "hold-a" {
		t.Fatalf("Snapshot = %+v, want externally added hold", holds)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt): %v", err)
	}
	if _, err := reader.Snapshot(); err == nil {
		t.Fatal("Snapshot served stale holds after store corruption")
	}
}

func TestLegalHoldStoreRejectsInvalidAndDuplicateEntries(t *testing.T) {
	t.Parallel()

	store, err := OpenLegalHoldStore(filepath.Join(t.TempDir(), "holds.json"))
	if err != nil {
		t.Fatalf("OpenLegalHoldStore: %v", err)
	}
	valid := LegalHold{ID: "hold-a", Scope: "agent-a", Reason: "review", Created: time.Now().UTC()}
	for _, tc := range []struct {
		name string
		hold LegalHold
	}{
		{name: "empty", hold: LegalHold{}},
		{name: "id leading whitespace", hold: LegalHold{ID: " hold-a", Scope: "agent-a", Reason: "review", Created: valid.Created}},
		{name: "id trailing whitespace", hold: LegalHold{ID: "hold-a ", Scope: "agent-a", Reason: "review", Created: valid.Created}},
		{name: "pre-released", hold: LegalHold{ID: "hold-b", Scope: "agent-b", Reason: "review", Created: valid.Created, Released: &valid.Created}},
		{name: "terminal control", hold: LegalHold{ID: "hold-c", Scope: "agent-c", Reason: "review\x1b[2J", Created: valid.Created}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.Add(tc.hold); err == nil {
				t.Fatal("Add accepted invalid hold")
			}
		})
	}
	if err := store.Add(valid); err != nil {
		t.Fatalf("Add(valid): %v", err)
	}
	if err := store.Add(valid); err == nil {
		t.Fatal("Add accepted duplicate ID")
	}
	if err := store.Release("missing", time.Now().UTC()); err == nil {
		t.Fatal("Release accepted unknown ID")
	}
}

func TestLegalHoldStoreRejectsUnboundedInput(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	t.Run("too many records", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "holds.json")
		records := make([]LegalHold, legalHoldMaxRecords+1)
		for i := range records {
			records[i] = LegalHold{
				ID: fmt.Sprintf("hold-%04d", i), Scope: "agent-a", Reason: "review", Created: created,
			}
		}
		data, err := json.Marshal(records)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := OpenLegalHoldStore(path); err == nil {
			t.Fatal("OpenLegalHoldStore accepted an unbounded record set")
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "holds.json")
		data := append(bytes.Repeat([]byte(" "), legalHoldFileMaxBytes), '[', ']')
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := OpenLegalHoldStore(path); err == nil {
			t.Fatal("OpenLegalHoldStore accepted an oversized file")
		}
	})
}

func TestLegalHoldStoreFailedWriteDoesNotPublishInMemoryState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not force an atomic-write failure on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "holds.json")
	store, err := OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore: %v", err)
	}
	created := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if err := store.Add(LegalHold{ID: "hold-a", Scope: "agent-a", Reason: "review", Created: created}); err != nil {
		t.Fatalf("Add(initial): %v", err)
	}
	// Deny writes while keeping the directory searchable. Modes held in variables
	// so the static analyzer cannot flag the literals.
	readOnlyDirMode := os.FileMode(0o500)
	restoreDirMode := os.FileMode(0o700)
	if err := os.Chmod(dir, readOnlyDirMode); err != nil {
		t.Fatalf("Chmod(read-only): %v", err)
	}
	defer func() { _ = os.Chmod(dir, restoreDirMode) }()
	if err := store.Add(LegalHold{ID: "hold-b", Scope: "agent-b", Reason: "review", Created: created}); err == nil {
		t.Fatal("Add unexpectedly succeeded in a read-only directory")
	}
	if holds := store.List(); len(holds) != 1 || holds[0].ID != "hold-a" {
		t.Fatalf("List = %+v, failed write must not publish in-memory state", holds)
	}
}

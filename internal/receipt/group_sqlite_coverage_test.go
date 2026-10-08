// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package receipt

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupScratchIndexesFailClosedWithoutTemporaryStorage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missing)
	open := ReceiptGroupOpen{GroupID: strings.Repeat("a", 32)}
	if err := verifyGroupAELInventoryMode(t.TempDir(), open, nil, false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inventory without scratch storage: %v", err)
	}
	index, err := newGroupAELBatchIndex(t.TempDir(), nil)
	if index != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("batch index without scratch storage: index=%v err=%v", index, err)
	}
}

func TestBatchIndexRejectsClosedDatabaseAndUnrelatedTornGroup(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "claims.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	index := &sqliteGroupAELBatchIndex{db: db}
	if err := index.build(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "database is closed") {
		t.Fatalf("closed batch build: %v", err)
	}
	open := ReceiptGroupOpen{GroupID: strings.Repeat("a", 32)}
	if err := index.Check(open, false); err == nil || !strings.Contains(err.Error(), "database is closed") {
		t.Fatalf("closed batch membership query: %v", err)
	}
	want := errors.New("foreign torn group")
	index.addTorn(groupBatchTorn{groupID: strings.Repeat("b", 32), err: want})
	index.addTorn(groupBatchTorn{groupID: strings.Repeat("b", 32), err: errors.New("duplicate should be ignored")})
	if len(index.torn) != 1 {
		t.Fatalf("duplicate torn group counted twice: %+v", index.torn)
	}
	if err := index.Check(open, false); !errors.Is(err, want) {
		t.Fatalf("foreign torn group accepted: %v", err)
	}
	index.torn = nil
	for _, prefix := range []string{"c", "d", "e", "f"} {
		index.addTorn(groupBatchTorn{groupID: strings.Repeat(prefix, 32), err: want})
	}
	if len(index.torn) != 3 {
		t.Fatalf("torn group sample exceeded bound: %d", len(index.torn))
	}
}

func TestBatchIndexRefusesConfigurationAndDamagedNativeInventory(t *testing.T) {
	dir := t.TempDir()
	want := errors.New("scratch configuration refused")
	index, err := newGroupAELBatchIndexWithConfigure(dir, nil, func(context.Context, *sql.DB) error { return want })
	if index != nil || !errors.Is(err, want) {
		t.Fatalf("scratch configuration index=%v err=%v", index, err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, run, want string
		directory       bool
	}{
		{"invalid name", "invalid-run", "invalid native AEL run directory", true},
		{"non-directory", strings.Repeat("a", 32), "not a real directory", false},
		{"orphan", strings.Repeat("b", 32), "no signed session owner", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "ael", tc.run)
			var err error
			if tc.directory {
				err = os.Mkdir(path, 0o750)
			} else {
				err = os.WriteFile(path, nil, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(path) })
			index, err := newGroupAELBatchIndex(dir, nil)
			if index != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("damaged native inventory index=%v err=%v, want %q", index, err, tc.want)
			}
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

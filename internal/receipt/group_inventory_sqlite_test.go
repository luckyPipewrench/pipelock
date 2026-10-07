// Copyright 2026 Josh Waldrep
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

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

func TestClaimInsertErrorReportsDuplicateRun(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "claims.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE claims(run TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	const run = "abababababababababababababababab"
	if _, err := db.ExecContext(ctx, `INSERT INTO claims(run) VALUES (?)`, run); err != nil {
		t.Fatal(err)
	}
	_, insertErr := db.ExecContext(ctx, `INSERT INTO claims(run) VALUES (?)`, run)
	if insertErr == nil {
		t.Fatal("duplicate claim insert succeeded")
	}
	got := claimInsertError(insertErr, run)
	if got == nil || !strings.Contains(got.Error(), "duplicate signed native AEL run") {
		t.Fatalf("claimInsertError = %v, want duplicate run error", got)
	}
	if errors.Is(got, evidencename.ErrAmbiguousSeqStart) {
		t.Fatalf("duplicate run reported as ambiguous sequence start: %v", got)
	}
	if claimInsertError(nil, run) != nil {
		t.Fatal("nil insert error became non-nil")
	}
	other := errors.New("disk full")
	if !errors.Is(claimInsertError(other, run), other) {
		t.Fatal("unrelated insert error was rewritten")
	}
}

func TestBatchIndexCheckRejectsUnlistedSessionClaim(t *testing.T) {
	open := ReceiptGroupOpen{GroupID: strings.Repeat("1", 32), Shards: []ReceiptGroupShard{
		{SessionID: "proxy.run." + strings.Repeat("a", 32)},
		{SessionID: "proxy.run." + strings.Repeat("b", 32)},
	}}
	for _, tc := range []struct {
		name     string
		sessions []string
		want     string
	}{
		{"complete", []string{open.Shards[0].SessionID, open.Shards[1].SessionID}, ""},
		{"foreign", []string{open.Shards[0].SessionID, "proxy.run." + strings.Repeat("c", 32)}, "outside signed shard membership"},
		{"duplicate", []string{open.Shards[0].SessionID, open.Shards[0].SessionID}, "duplicate claims"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "claims.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			if _, err := db.Exec(`CREATE TABLE claims (session TEXT NOT NULL, group_id TEXT NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			for _, session := range tc.sessions {
				if _, err := db.Exec(`INSERT INTO claims(session, group_id) VALUES (?, ?)`, session, open.GroupID); err != nil {
					t.Fatal(err)
				}
			}
			index := &sqliteGroupAELBatchIndex{db: db}
			err = index.Check(open, false)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("batch membership = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestConfigureScratchSQLiteWrapsSetupFailure(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "claims.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = configureScratchSQLite(ctx, db)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "configure scratch inventory database") {
		t.Fatalf("SQLite setup error = %v, want wrapped cancellation", err)
	}
}

func TestBatchIndexRemovesScratchDatabaseAfterSetupFailure(t *testing.T) {
	scratchParent := t.TempDir()
	t.Setenv("TMPDIR", scratchParent)
	setupFailure := errors.New("injected scratch setup failure")
	index, err := newGroupAELBatchIndexWithConfigure(t.TempDir(), nil, func(ctx context.Context, db *sql.DB) error {
		if _, err := db.ExecContext(ctx, `CREATE TABLE scratch_probe (id INTEGER)`); err != nil {
			t.Fatal(err)
		}
		return setupFailure
	})
	if index != nil || !errors.Is(err, setupFailure) {
		t.Fatalf("failed SQLite index = %v, %v", index, err)
	}
	entries, err := os.ReadDir(scratchParent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("scratch database remained after setup failure: %v", entries)
	}
}

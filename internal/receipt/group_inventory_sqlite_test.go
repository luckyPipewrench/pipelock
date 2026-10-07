// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package receipt

import (
	"context"
	"database/sql"
	"errors"
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

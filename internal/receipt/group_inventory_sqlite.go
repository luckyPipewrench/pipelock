// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package receipt

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	_ "modernc.org/sqlite"
)

// verifyGroupAELInventory indexes signed session_open claims in a temporary
// disk database, then checks every native AEL run for one claimant. SQLite
// keeps heap use bounded across years of historical legacy runs.
func verifyGroupAELInventory(dir string, open ReceiptGroupOpen, trusted []string) error {
	return verifyGroupAELInventoryMode(dir, open, trusted, false)
}

func verifyGroupAELInventoryMode(dir string, open ReceiptGroupOpen, trusted []string, incomplete bool) error {
	tmp, err := os.MkdirTemp("", "pipelock-group-inventory-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	db, err := sql.Open("sqlite", filepath.Join(tmp, "claims.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE claims (run TEXT PRIMARY KEY, session TEXT NOT NULL, group_id TEXT NOT NULL, signer TEXT NOT NULL, completed INTEGER NOT NULL)`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE runs (run TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE evidence_names (session TEXT NOT NULL, seq TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY(session, seq))`); err != nil {
		return err
	}
	if err := walkInventoryNames(dir, func(name string) error {
		session, seq, ok := evidencename.Parse(name)
		if !ok {
			return nil
		}
		seqText := fmt.Sprint(seq)
		var prior string
		err := db.QueryRowContext(ctx, `SELECT name FROM evidence_names WHERE session = ? AND seq = ?`, session, seqText).Scan(&prior)
		if err == nil {
			return fmt.Errorf("%w: %s and %s both start session %q at sequence %d", evidencename.ErrAmbiguousSeqStart, prior, name, session, seq)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO evidence_names(session, seq, name) VALUES (?, ?, ?)`, session, seqText, name); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	// Reject ambiguous names before any chain walker chooses an ordering.
	if err := walkInventoryNames(dir, func(name string) error {
		session, seq, ok := evidencename.Parse(name)
		if !ok || seq != 0 {
			return nil
		}
		currentGroupID := ""
		if incomplete {
			currentGroupID = open.GroupID
		}
		return indexAELClaimsForSession(dir, session, currentGroupID, open.PreviousGroupID, trusted, func(run, session, groupID, signer string, completed bool) error {
			_, err := db.ExecContext(ctx, `INSERT INTO claims(run, session, group_id, signer, completed) VALUES (?, ?, ?, ?, ?)`, run, session, groupID, signer, completed)
			if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: claims.run") {
				return fmt.Errorf("duplicate signed native AEL run %q", run)
			}
			return err
		})
	}); err != nil {
		return err
	}
	if err := walkInventoryNames(filepath.Join(dir, "ael"), func(name string) error {
		if !groupHex(name, 32) {
			return fmt.Errorf("invalid native AEL run directory %q", name)
		}
		info, err := os.Lstat(filepath.Join(dir, "ael", name))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native AEL run %q is not a real directory", name)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO runs(run) VALUES (?)`, name); err != nil {
			return fmt.Errorf("duplicate native AEL run %q: %w", name, err)
		}
		return nil
	}); err != nil {
		return err
	}
	var orphan string
	err = db.QueryRowContext(ctx, `SELECT runs.run FROM runs LEFT JOIN claims USING(run) WHERE claims.run IS NULL LIMIT 1`).Scan(&orphan)
	if err == nil {
		return fmt.Errorf("native AEL run %q has no signed session owner", orphan)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var missing string
	err = db.QueryRowContext(ctx, `SELECT claims.run FROM claims LEFT JOIN runs USING(run) WHERE runs.run IS NULL LIMIT 1`).Scan(&missing)
	if err == nil {
		return fmt.Errorf("native AEL run %q claimed by a signed session_open is missing", missing)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Completion comes from authenticated recorder data, never from a group
	// close artifact. A close may be missing after a completed stream.
	rows, err := db.QueryContext(ctx, `SELECT runs.run, claims.signer, claims.group_id, claims.completed FROM runs JOIN claims USING(run)`)
	if err != nil {
		return err
	}
	openTail := false
	neighborOpenTail := false
	for rows.Next() {
		var run, signer, groupID string
		var completed bool
		if err := rows.Scan(&run, &signer, &groupID, &completed); err != nil {
			_ = rows.Close()
			return err
		}
		var verifyErr error
		if completed {
			_, verifyErr = ael.VerifyRun(dir, run, signer)
		} else {
			_, verifyErr = ael.VerifyPresentRun(dir, run, signer)
		}
		if verifyErr != nil {
			_ = rows.Close()
			return fmt.Errorf("native AEL run %q invalid: %w", run, verifyErr)
		}
		if !completed {
			if groupID == open.GroupID {
				openTail = true
			} else {
				neighborOpenTail = true
			}
			continue
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	var groupClaims int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM claims WHERE group_id = ?`, open.GroupID).Scan(&groupClaims); err != nil {
		return err
	}
	if groupClaims > len(open.Shards) || !incomplete && groupClaims != len(open.Shards) {
		return fmt.Errorf("receipt group native AEL claims = %d, want %d", groupClaims, len(open.Shards))
	}
	if openTail {
		return errGroupAELOpenTail
	}
	if neighborOpenTail {
		return errGroupAELNeighborOpenTail
	}
	return nil
}

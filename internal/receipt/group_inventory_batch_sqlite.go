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

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	_ "modernc.org/sqlite"
)

type sqliteGroupAELBatchIndex struct {
	db             *sql.DB
	tmp            string
	torn           []groupBatchTorn
	openTailCounts map[string]int
	totalOpenTails int
}

func newGroupAELBatchIndex(dir string, trusted []string) (groupAELBatchIndex, error) {
	tmp, err := os.MkdirTemp("", "pipelock-group-inventory-")
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(tmp, "claims.db"))
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := configureScratchSQLite(context.Background(), db); err != nil {
		_ = db.Close()
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	index := &sqliteGroupAELBatchIndex{db: db, tmp: tmp, openTailCounts: make(map[string]int)}
	if err := index.build(dir, trusted); err != nil {
		_ = index.Close()
		return nil, err
	}
	return index, nil
}

func (index *sqliteGroupAELBatchIndex) Close() error {
	return errors.Join(index.db.Close(), os.RemoveAll(index.tmp))
}

func (index *sqliteGroupAELBatchIndex) build(dir string, trusted []string) error {
	ctx := context.Background()
	for _, query := range []string{
		`CREATE TABLE claims (run TEXT PRIMARY KEY, group_id TEXT NOT NULL, signer TEXT NOT NULL, completed INTEGER NOT NULL)`,
		`CREATE TABLE runs (run TEXT PRIMARY KEY)`,
		`CREATE TABLE evidence_names (session TEXT NOT NULL, seq TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY(session, seq))`,
	} {
		if _, err := index.db.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	if err := walkInventoryNames(dir, func(name string) error {
		session, seq, ok := evidencename.Parse(name)
		if !ok {
			return nil
		}
		seqText := fmt.Sprint(seq)
		var prior string
		err := index.db.QueryRowContext(ctx, `SELECT name FROM evidence_names WHERE session = ? AND seq = ?`, session, seqText).Scan(&prior)
		if err == nil {
			return fmt.Errorf("%w: %s and %s both start session %q at sequence %d", evidencename.ErrAmbiguousSeqStart, prior, name, session, seq)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = index.db.ExecContext(ctx, `INSERT INTO evidence_names(session, seq, name) VALUES (?, ?, ?)`, session, seqText, name)
		return err
	}); err != nil {
		return err
	}
	if err := walkInventoryNames(dir, func(name string) error {
		session, seq, ok := evidencename.Parse(name)
		if !ok || seq != 0 {
			return nil
		}
		return indexAELClaimsForSessionBatch(dir, session, "", "", trusted, func(run, _, groupID, signer string, completed bool) error {
			_, err := index.db.ExecContext(ctx, `INSERT INTO claims(run, group_id, signer, completed) VALUES (?, ?, ?, ?)`, run, groupID, signer, completed)
			return claimInsertError(err, run)
		}, index.addTorn)
	}); err != nil {
		return err
	}
	if err := walkInventoryNames(filepath.Join(dir, "ael"), func(run string) error {
		if !groupHex(run, 32) {
			return fmt.Errorf("invalid native AEL run directory %q", run)
		}
		info, err := os.Lstat(filepath.Join(dir, "ael", run))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native AEL run %q is not a real directory", run)
		}
		if _, err := index.db.ExecContext(ctx, `INSERT INTO runs(run) VALUES (?)`, run); err != nil {
			return fmt.Errorf("duplicate native AEL run %q: %w", run, err)
		}
		var signer, groupID string
		var completed bool
		err = index.db.QueryRowContext(ctx, `SELECT signer, group_id, completed FROM claims WHERE run = ?`, run).Scan(&signer, &groupID, &completed)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("native AEL run %q has no signed session owner", run)
		}
		if err != nil {
			return err
		}
		if completed {
			_, err = ael.VerifyRun(dir, run, signer)
		} else {
			_, err = ael.VerifyPresentRun(dir, run, signer)
			index.openTailCounts[groupID]++
			index.totalOpenTails++
		}
		if err != nil {
			return fmt.Errorf("native AEL run %q invalid: %w", run, err)
		}
		return nil
	}); err != nil {
		return err
	}
	var missing string
	err := index.db.QueryRowContext(ctx, `SELECT claims.run FROM claims LEFT JOIN runs USING(run) WHERE runs.run IS NULL LIMIT 1`).Scan(&missing)
	if err == nil {
		return fmt.Errorf("native AEL run %q claimed by a signed session_open is missing", missing)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = index.db.ExecContext(ctx, `CREATE INDEX claims_group_id_idx ON claims(group_id)`)
	return err
}

func (index *sqliteGroupAELBatchIndex) addTorn(torn groupBatchTorn) {
	for _, prior := range index.torn {
		if prior.groupID == torn.groupID {
			return
		}
	}
	if len(index.torn) < 3 {
		index.torn = append(index.torn, torn)
	}
}

func (index *sqliteGroupAELBatchIndex) Check(open ReceiptGroupOpen, incomplete bool) error {
	for _, torn := range index.torn {
		if torn.groupID != open.PreviousGroupID && (!incomplete || torn.groupID != open.GroupID) {
			return torn.err
		}
	}
	var claims int
	if err := index.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM claims WHERE group_id = ?`, open.GroupID).Scan(&claims); err != nil {
		return err
	}
	if claims > len(open.Shards) || !incomplete && claims != len(open.Shards) {
		return fmt.Errorf("receipt group native AEL claims = %d, want %d", claims, len(open.Shards))
	}
	if index.openTailCounts[open.GroupID] > 0 {
		return errGroupAELOpenTail
	}
	if index.totalOpenTails > index.openTailCounts[open.GroupID] {
		return errGroupAELNeighborOpenTail
	}
	return nil
}

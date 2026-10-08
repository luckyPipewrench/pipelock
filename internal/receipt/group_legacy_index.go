// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package receipt

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

// indexRecorderFilesExcludingGroupsSpill orders filenames on disk before
// classifying each session. A directory read has no ordering guarantee, and
// os.ReadDir retains every historical group filename in memory.
func indexRecorderFilesExcludingGroupsSpill(dir string) (evidenceIndex, error) {
	tmp, err := os.MkdirTemp("", "pipelock-legacy-index-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	db, err := sql.Open("sqlite", filepath.Join(tmp, "files.db"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE files (session TEXT NOT NULL, seq TEXT NOT NULL, name TEXT NOT NULL)`); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO files(session, seq, name) VALUES (?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	err = walkInventoryNames(dir, func(name string) error {
		session, seq, ok := evidencename.Parse(name)
		if !ok {
			return nil
		}
		// Decimal text preserves the recorder's uint64 sequence range.
		_, execErr := stmt.ExecContext(ctx, session, fmt.Sprintf("%020d", seq), name)
		return execErr
	})
	_ = stmt.Close()
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT session, name FROM files ORDER BY session, seq, name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	index := make(evidenceIndex)
	current := ""
	var shards []indexedRecorderShard
	flush := func() {
		if current != "" && len(shards) > 0 && !isGroupSessionShards(shards) {
			files := make([]string, 0, len(shards))
			for _, shard := range shards {
				files = append(files, shard.path)
			}
			index[current] = files
		}
		current, shards = "", nil
	}
	for rows.Next() {
		var session, name string
		if err := rows.Scan(&session, &name); err != nil {
			return nil, err
		}
		if current != "" && current != session {
			flush()
		}
		current = session
		_, seq, _ := evidencename.Parse(name)
		shards = append(shards, indexedRecorderShard{path: filepath.Join(filepath.Clean(dir), name), base: name, seqStart: seq})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	flush()
	return index, nil
}

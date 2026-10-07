// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package receipt

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

type wasmGroupAELClaim struct {
	session   string
	groupID   string
	signer    string
	completed bool
}

type wasmEvidenceNameKey struct {
	session string
	seq     uint64
}

// verifyGroupAELInventory uses an in-memory index because modernc SQLite does
// not support js/wasm. The browser caller supplies a ZIP capped at 32 MiB
// uncompressed, which bounds this index independently of historical host data.
func verifyGroupAELInventory(dir string, open ReceiptGroupOpen, trusted []string) error {
	return verifyGroupAELInventoryMode(dir, open, trusted, false)
}

func verifyGroupAELInventoryMode(dir string, open ReceiptGroupOpen, trusted []string, incomplete bool) error {
	claims := make(map[string]wasmGroupAELClaim)
	evidenceNames := make(map[wasmEvidenceNameKey]string)
	if err := walkInventoryNames(dir, func(name string) error {
		session, seq, ok := evidencename.Parse(name)
		if !ok {
			return nil
		}
		key := wasmEvidenceNameKey{session: session, seq: seq}
		if prior, exists := evidenceNames[key]; exists {
			return fmt.Errorf("%w: %s and %s both start session %q at sequence %d", evidencename.ErrAmbiguousSeqStart, prior, name, session, seq)
		}
		evidenceNames[key] = name
		return nil
	}); err != nil {
		return err
	}
	// Refuse duplicate roots before a chain walker selects either file.
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
			if _, exists := claims[run]; exists {
				return fmt.Errorf("duplicate signed native AEL run %q", run)
			}
			claims[run] = wasmGroupAELClaim{session: session, groupID: groupID, signer: signer, completed: completed}
			return nil
		})
	}); err != nil {
		return err
	}
	groupClaims := 0
	openTail := false
	neighborOpenTail := false
	if err := walkInventoryNames(filepath.Join(dir, "ael"), func(name string) error {
		if !groupHex(name, 32) {
			return fmt.Errorf("invalid native AEL run directory %q", name)
		}
		info, err := os.Lstat(filepath.Join(dir, "ael", name))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native AEL run %q is not a real directory", name)
		}
		claim, ok := claims[name]
		if !ok {
			return fmt.Errorf("native AEL run %q has no signed session owner", name)
		}
		if claim.groupID == open.GroupID {
			groupClaims++
		}
		if !claim.completed {
			if _, err := ael.VerifyPresentRun(dir, name, claim.signer); err != nil {
				return fmt.Errorf("native AEL run %q invalid: %w", name, err)
			}
			if claim.groupID == open.GroupID {
				openTail = true
			} else {
				neighborOpenTail = true
			}
			return nil
		}
		_, err = ael.VerifyRun(dir, name, claim.signer)
		if err != nil {
			return fmt.Errorf("native AEL run %q invalid: %w", name, err)
		}
		return nil
	}); err != nil {
		return err
	}
	for run := range claims {
		info, err := os.Lstat(filepath.Join(dir, "ael", run))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native AEL run %q claimed by a signed session_open is missing", run)
		}
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

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

type wasmGroupAELBatchIndex struct {
	claims         map[string]wasmGroupAELClaim
	sessions       map[string][]string
	tailCounts     map[string]int
	totalOpenTails int
	torn           []groupBatchTorn
}

func newGroupAELBatchIndex(dir string, trusted []string) (groupAELBatchIndex, error) {
	index := &wasmGroupAELBatchIndex{
		claims: make(map[string]wasmGroupAELClaim), sessions: make(map[string][]string),
		tailCounts: make(map[string]int),
	}
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
		return nil, err
	}
	if err := walkInventoryNames(dir, func(name string) error {
		session, seq, ok := evidencename.Parse(name)
		if !ok || seq != 0 {
			return nil
		}
		return indexAELClaimsForSessionBatch(dir, session, "", "", trusted, func(run, session, groupID, signer string, completed bool) error {
			if _, exists := index.claims[run]; exists {
				return fmt.Errorf("duplicate signed native AEL run %q", run)
			}
			index.claims[run] = wasmGroupAELClaim{session: session, groupID: groupID, signer: signer, completed: completed}
			index.sessions[groupID] = append(index.sessions[groupID], session)
			return nil
		}, index.addTorn)
	}); err != nil {
		return nil, err
	}
	if err := walkInventoryNames(filepath.Join(dir, "ael"), func(run string) error {
		if !groupHex(run, 32) {
			return fmt.Errorf("invalid native AEL run directory %q", run)
		}
		info, err := os.Lstat(filepath.Join(dir, "ael", run))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native AEL run %q is not a real directory", run)
		}
		claim, ok := index.claims[run]
		if !ok {
			return fmt.Errorf("native AEL run %q has no signed session owner", run)
		}
		if claim.completed {
			_, err = ael.VerifyRun(dir, run, claim.signer)
		} else {
			_, err = ael.VerifyPresentRun(dir, run, claim.signer)
			index.tailCounts[claim.groupID]++
			index.totalOpenTails++
		}
		if err != nil {
			return fmt.Errorf("native AEL run %q invalid: %w", run, err)
		}
		delete(index.claims, run)
		return nil
	}); err != nil {
		return nil, err
	}
	for run := range index.claims {
		return nil, fmt.Errorf("native AEL run %q claimed by a signed session_open is missing", run)
	}
	return index, nil
}

func (index *wasmGroupAELBatchIndex) addTorn(torn groupBatchTorn) {
	for _, prior := range index.torn {
		if prior.groupID == torn.groupID {
			return
		}
	}
	if len(index.torn) < 3 {
		index.torn = append(index.torn, torn)
	}
}

func (index *wasmGroupAELBatchIndex) Check(open ReceiptGroupOpen, incomplete bool) error {
	for _, torn := range index.torn {
		if torn.groupID != open.PreviousGroupID && (!incomplete || torn.groupID != open.GroupID) {
			return torn.err
		}
	}
	membership := newGroupAELMembership(open)
	for _, session := range index.sessions[open.GroupID] {
		if err := membership.Add(session); err != nil {
			return err
		}
	}
	if err := membership.Finish(incomplete); err != nil {
		return err
	}
	if index.tailCounts[open.GroupID] > 0 {
		return errGroupAELOpenTail
	}
	if index.totalOpenTails > index.tailCounts[open.GroupID] {
		return errGroupAELNeighborOpenTail
	}
	return nil
}

func (index *wasmGroupAELBatchIndex) Close() error { return nil }

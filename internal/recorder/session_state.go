// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

// SessionState is the mutable chain/file/checkpoint state of one acquired
// receipt shard. The directory ceremony and signer remain on Recorder.
type SessionState struct {
	writeMu             sync.Mutex
	sessionID           string
	seq                 uint64
	prevHash            string
	writer              *bufio.Writer
	file                *os.File
	runPresence         *os.File
	evidenceDir         os.FileInfo
	fileEntryCount      int
	fileSeqStart        uint64
	fileGeneration      uint64
	checkpointThreshold uint64
	sinceCheckpoint     uint64
	firstSeqInSpan      uint64
	durableBatch        *durableBatch
	durableSyncing      bool
	durablePending      map[uint64]int
}

// GroupGateEntryType marks the first entry of each grouped run session.
const GroupGateEntryType = "receipt_group_v1"

func (r *Recorder) saveSessionStateLocked(state *SessionState) {
	state.sessionID = r.sessionID
	state.seq = r.seq
	state.prevHash = r.prevHash
	state.writer = r.writer
	state.file = r.file
	state.runPresence = r.runPresence
	state.evidenceDir = r.evidenceDir
	state.fileEntryCount = r.fileEntryCount
	state.fileSeqStart = r.fileSeqStart
	state.fileGeneration = r.fileGeneration
	state.checkpointThreshold = r.checkpointThreshold
	state.sinceCheckpoint = r.sinceCheckpoint
	state.firstSeqInSpan = r.firstSeqInSpan
	state.durableBatch = r.durableBatch
	state.durableSyncing = r.durableSyncing
	state.durablePending = r.durablePending
}

func (r *Recorder) loadSessionStateLocked(state *SessionState) {
	r.activeGroupState = state
	r.sessionID = state.sessionID
	r.seq = state.seq
	r.prevHash = state.prevHash
	r.writer = state.writer
	r.file = state.file
	r.runPresence = state.runPresence
	r.evidenceDir = state.evidenceDir
	r.fileEntryCount = state.fileEntryCount
	r.fileSeqStart = state.fileSeqStart
	r.fileGeneration = state.fileGeneration
	r.checkpointThreshold = state.checkpointThreshold
	r.sinceCheckpoint = state.sinceCheckpoint
	r.firstSeqInSpan = state.firstSeqInSpan
	r.durableBatch = state.durableBatch
	r.durableSyncing = state.durableSyncing
	r.durablePending = state.durablePending
}

func (r *Recorder) clearSessionStateLocked() {
	r.activeGroupState = nil
	r.sessionID = ""
	r.seq = 0
	r.prevHash = GenesisHash
	r.writer = nil
	r.file = nil
	r.runPresence = nil
	r.evidenceDir = r.ceremonyDir
	r.fileEntryCount = 0
	r.fileSeqStart = 0
	r.fileGeneration = 0
	r.checkpointThreshold = safeUint64(r.cfg.CheckpointInterval, 1)
	r.sinceCheckpoint = 0
	r.firstSeqInSpan = 0
	r.durableBatch = nil
	r.durableSyncing = false
	r.durablePending = make(map[uint64]int)
}

func validGroupRunSession(session string) bool {
	base, suffix, ok := strings.Cut(session, evidencename.RunInfix)
	if !ok || strings.Contains(suffix, evidencename.RunInfix) || evidencename.ValidateOperatorSessionID(base) != nil || len(suffix) != 32 {
		return false
	}
	for _, ch := range []byte(suffix) {
		if ch < '0' || (ch > '9' && ch < 'a') || ch > 'f' {
			return false
		}
	}
	return true
}

// AcquireGroupSessions binds the one directory owner to a fixed set of run
// sessions before any entry is written. It never lazily accepts a new member.
func (r *Recorder) AcquireGroupSessions(sessions []string) error {
	if r == nil || r.nop {
		return errors.New("recorder: group sessions require a persistent recorder")
	}
	if len(sessions) < 2 || len(sessions) > 32 {
		return errors.New("recorder: group requires 2 to 32 sessions")
	}
	r.groupMu.Lock()
	defer r.groupMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.legacyStarted || r.sessionID != "" || r.groupSessions != nil {
		return errors.New("recorder: session ownership already established")
	}
	owner, err := acquireGroupOwner(r.cfg.Dir)
	if err != nil {
		return fmt.Errorf("recorder: acquire receipt group owner: %w", err)
	}
	r.groupOwner = owner
	states := make(map[string]*SessionState, len(sessions))
	rollback := func() {
		for _, state := range states {
			if state.runPresence != nil {
				_ = unlockEvidenceFile(state.runPresence)
				_ = state.runPresence.Close()
			}
		}
		r.clearSessionStateLocked()
		_ = r.releaseGroupOwner()
	}
	for _, session := range sessions {
		if !validGroupRunSession(session) {
			rollback()
			return fmt.Errorf("recorder: invalid group run session %q", session)
		}
		if _, exists := states[session]; exists {
			rollback()
			return fmt.Errorf("recorder: duplicate group run session %q", session)
		}
		if err := r.resumeSessionLocked(session); err != nil {
			rollback()
			return fmt.Errorf("recorder: resume group session %q: %w", session, err)
		}
		presence, err := acquireRunPresence(r.cfg.Dir, session)
		if err != nil {
			rollback()
			return fmt.Errorf("recorder: acquire group writer %q: %w", session, err)
		}
		r.runPresence = presence
		state := new(SessionState)
		r.saveSessionStateLocked(state)
		states[session] = state
		r.clearSessionStateLocked()
	}
	r.groupSessions = states
	r.groupOrder = append([]string(nil), sessions...)
	r.loadSessionStateLocked(states[sessions[0]])
	return nil
}

func acquireGroupOwner(dir string) (*os.File, error) {
	path := filepath.Join(filepath.Clean(dir), "writer-receipt-group-owner.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|evidenceReadNoFollowFlag, 0o600)
	if err != nil {
		return nil, err
	}
	locked, err := tryLockEvidenceFileForExpiry(f)
	if err != nil || !locked {
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("another receipt group writer owns the evidence directory")
	}
	if err := f.Chmod(0o600); err != nil {
		_ = unlockEvidenceFile(f)
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (r *Recorder) releaseGroupOwner() error {
	if r.groupOwner == nil {
		return nil
	}
	err := errors.Join(unlockEvidenceFile(r.groupOwner), r.groupOwner.Close())
	r.groupOwner = nil
	return err
}

// withGroupSessionLocked swaps the active file state while groupMu excludes
// acquisition and close. Scan preflight runs before callers take groupMu.
func (r *Recorder) withGroupSessionLocked(session string, write func() error) error {
	r.mu.Lock()
	state, ok := r.groupSessions[session]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("recorder: session %q is not an acquired group member", session)
	}
	r.loadSessionStateLocked(state)
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.saveSessionStateLocked(state)
		r.loadSessionStateLocked(r.groupSessions[r.groupOrder[0]])
		r.mu.Unlock()
	}()
	return write()
}

// RecordGroupGate writes the first group entry and its covering signed
// checkpoint before any shard emitter can open. Both entries are synced before
// success; a failed sync leaves the group incomplete and startup must stop.
func (r *Recorder) RecordGroupGate(e Entry) error {
	if r == nil || r.nop || e.Type != GroupGateEntryType || e.SessionID == "" || e.Detail == nil {
		return errors.New("recorder: invalid group gate entry")
	}
	scan, err := r.PreflightSignedReceiptDetail(e.Detail)
	if err != nil {
		return fmt.Errorf("preflight group gate: %w", err)
	}
	r.groupMu.Lock()
	defer r.groupMu.Unlock()
	return r.withGroupSessionLocked(e.SessionID, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed || !r.cfg.SignCheckpoints || r.seq != 0 || r.fileEntryCount != 0 {
			return errors.New("recorder: group gate requires a fresh signed shard")
		}
		written, err := r.prepareAndWriteEntryWithScanLocked(e, false, &scan)
		if err != nil {
			return fmt.Errorf("record group gate: %w", err)
		}
		r.prevHash = written.Hash
		r.seq++
		r.sinceCheckpoint++
		r.fileEntryCount++
		if err := r.fileSync(r.file); err != nil {
			return fmt.Errorf("sync group gate: %w", err)
		}
		if err := r.checkpointLocked(); err != nil {
			return fmt.Errorf("checkpoint group gate: %w", err)
		}
		if err := r.fileSync(r.file); err != nil {
			return fmt.Errorf("sync group gate checkpoint: %w", err)
		}
		return nil
	})
}

// FinalizeGroupSessions closes and syncs every acquired shard while retaining
// their run-presence locks and the directory ceremony. The caller publishes
// the signed group close under that ownership, then calls Close to release it.
// Once finalization starts, any failure leaves the group incomplete; Close
// performs cleanup without writing more evidence.
func (r *Recorder) FinalizeGroupSessions() error {
	if r == nil || r.nop {
		return errors.New("recorder: no persistent group to finalize")
	}
	r.groupMu.Lock()
	if r.groupClosing {
		r.groupMu.Unlock()
		return errors.New("recorder: receipt group is already closing")
	}
	r.groupClosing = true
	r.groupMu.Unlock()
	r.groupWrites.Wait()
	r.groupMu.Lock()
	defer r.groupMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groupSessions == nil || r.closed || r.groupFinalizing {
		return errors.New("recorder: no open group to finalize")
	}
	r.groupFinalizing = true
	r.closed = true
	for _, session := range r.groupOrder {
		state := r.groupSessions[session]
		r.loadSessionStateLocked(state)
		if r.file != nil {
			if err := r.fileSync(r.file); err != nil {
				r.saveSessionStateLocked(state)
				return fmt.Errorf("finalize group shard %q pre-checkpoint sync: %w", session, err)
			}
		}
		if r.sinceCheckpoint > 0 {
			r.waitDurableForCurrentFileLocked()
			if r.sinceCheckpoint > 0 {
				if err := r.checkpointLocked(); err != nil {
					r.saveSessionStateLocked(state)
					return fmt.Errorf("finalize group shard %q checkpoint: %w", session, err)
				}
			}
		}
		if r.file != nil {
			if err := r.fileSync(r.file); err != nil {
				r.saveSessionStateLocked(state)
				return fmt.Errorf("finalize group shard %q sync: %w", session, err)
			}
		}
		if err := r.closeFile(); err != nil {
			r.saveSessionStateLocked(state)
			return fmt.Errorf("finalize group shard %q close: %w", session, err)
		}
		r.saveSessionStateLocked(state)
	}
	r.loadSessionStateLocked(r.groupSessions[r.groupOrder[0]])
	return nil
}

func (r *Recorder) closeGroup() (retErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, session := range r.groupOrder {
		state := r.groupSessions[session]
		r.loadSessionStateLocked(state)
		if !r.groupFinalizing && r.sinceCheckpoint > 0 {
			r.waitDurableForCurrentFileLocked()
			if r.sinceCheckpoint > 0 {
				retErr = errors.Join(retErr, r.checkpointLocked())
			}
		}
		retErr = errors.Join(retErr, r.closeFile())
		if r.runPresence != nil {
			retErr = errors.Join(retErr, unlockEvidenceFile(r.runPresence), r.runPresence.Close())
			r.runPresence = nil
		}
		r.saveSessionStateLocked(state)
	}
	r.clearSessionStateLocked()
	retErr = errors.Join(retErr, r.releaseGroupOwner())
	retErr = errors.Join(retErr, r.releaseEvidenceWriterCeremonyLock())
	return retErr
}

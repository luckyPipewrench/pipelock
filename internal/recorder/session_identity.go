// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

// IsNop reports whether this recorder is a no-op (persistence disabled, or
// nil). A nop recorder discards every Record call and owns no session; the
// zero value on a nil receiver is also nop, so callers can check this before
// dereferencing.
func (r *Recorder) IsNop() bool {
	return r == nil || r.nop
}

// AcquireSession explicitly binds this recorder to one session ID before any
// entry is written, rather than letting the first Record call decide it
// implicitly. Calling it again with the SAME session ID is a no-op (repeat
// acquisition by the same run is fine); calling it with a DIFFERENT session
// ID than the one already bound is refused, surfacing the same "one session
// per recorder" contract that Record already enforces per-entry, but at
// startup rather than at first write, so a caller can react before doing any
// work under an unintended session.
//
// It performs the recorder's normal resume: it reads any existing shards
// for sessionID and continues their sequence and hash-chain tail, exactly as
// the first Record call would have. For a fresh run session (see
// NewRunSessionID) there are never existing shards, so this always resumes
// at genesis for a run session; the resume path still matters for the
// legacy plain "<base>" session that an older binary may have written and
// that a caller wants to inspect (see the predecessor-claim logic in the
// receipt emitter, which reads other sessions' tails through the query
// path, not by acquiring them).
func (r *Recorder) AcquireSession(sessionID string) error {
	if r == nil || r.nop {
		return nil
	}
	if sessionID == "" {
		return errors.New("recorder: session_id required")
	}
	if strings.ContainsAny(sessionID, `/\`) {
		return fmt.Errorf("recorder: session_id contains path separator")
	}
	if !utf8.ValidString(sessionID) {
		return fmt.Errorf("recorder: session_id is not valid UTF-8")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessionID == sessionID {
		return nil
	}
	if r.sessionID != "" {
		return fmt.Errorf("recorder: already bound to session %q, cannot acquire %q", r.sessionID, sessionID)
	}
	if err := r.resumeSessionLocked(sessionID); err != nil {
		return fmt.Errorf("recorder: resume chain state: %w", err)
	}
	if strings.Contains(sessionID, ".run.") {
		presence, err := acquireRunPresence(r.cfg.Dir, sessionID)
		if err != nil {
			r.sessionID = ""
			return fmt.Errorf("recorder: acquire run presence: %w", err)
		}
		r.runPresence = presence
	}
	return nil
}

// AcquireRunSession is the process-startup entry point that combines run
// session minting with recorder binding. For a nop or nil recorder it
// returns base unchanged and performs no writes and no acquisition, matching
// how every other recorder operation already treats a disabled recorder: a
// disabled recorder has no chain to fork, so there is nothing to protect and
// nothing to bind. For a real recorder it mints a fresh run session (see
// NewRunSessionID) and binds the recorder to it, so the caller receives back
// the exact session ID it must now use for every Record call.
func AcquireRunSession(r *Recorder, base string) (string, error) {
	if r.IsNop() {
		return base, nil
	}
	runSession, err := NewRunSessionID(base)
	if err != nil {
		return "", err
	}
	if err := r.AcquireSession(runSession); err != nil {
		return "", err
	}
	return runSession, nil
}

// runSessionRandomBytes is the amount of crypto/rand entropy in a run-session
// suffix. 16 bytes (128 bits) makes an accidental collision between two
// concurrently started processes unreachable in practice, matching the
// existing escrow filename token size in this package.
const runSessionRandomBytes = 16

// NewRunSessionID mints a fresh, process-start-scoped recorder session ID of
// the form "<base>.run.<32 lowercase hex characters>".
//
// Every Pipelock process that opens a recorder for evidence generates one of
// these exactly once, at startup, and never reopens it. That is the fix for
// the hash-chain fork that a shared literal session ID (historically the bare
// string "proxy") produces when multiple processes point at the same
// recorder directory: a hash chain admits exactly one predecessor per
// sequence, and two writers resuming from the same tail both claim the next
// one. A run session is unique per process start, so it is never resumed by
// a second writer and the fork cannot occur at the recorder layer. What
// happens instead is a fresh chain per run; continuity across runs is
// re-established explicitly by the predecessor-claim and chain_link
// mechanism layered on top (see the receipt emitter), not by silently
// resuming the same file.
//
// base defaults the way callers already default the literal session name
// (historically "proxy"); it must itself already satisfy
// evidencename.ValidateOperatorSessionID; a base carrying the reserved
// ".run." infix or a path separator is refused rather than silently
// stripped or double-suffixed.
func NewRunSessionID(base string) (string, error) {
	if err := evidencename.ValidateOperatorSessionID(base); err != nil {
		return "", fmt.Errorf("run session base: %w", err)
	}
	var buf [runSessionRandomBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generating run session id: %w", err)
	}
	return base + evidencename.RunInfix + hex.EncodeToString(buf[:]), nil
}

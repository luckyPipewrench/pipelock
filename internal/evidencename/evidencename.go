// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package evidencename parses recorder evidence shard filenames.
//
// It exists as a leaf package, below both the recorder and the contract
// verifier, because deciding which shards belong to a session is
// security-relevant and both of those trees need the same answer. When the
// logic lived in two places they could disagree about membership, and one of
// them adopting another session's shard is a cross-session chain
// contamination. A parity test can only detect that drift after it happens;
// one definition prevents it.
//
// The package deliberately has no dependencies so anything can import it.
package evidencename

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	prefix = "evidence-"
	suffix = ".jsonl"
)

// RunInfix marks a per-process-start recorder session, e.g.
// "proxy.run.3a7c...". It is reserved: a run session is minted internally
// (see recorder.NewRunSessionID) from crypto/rand and must never collide with
// an operator-chosen session ID, because two writers landing on the same
// session name is exactly the hash-chain fork this reservation exists to
// prevent. ValidateOperatorSessionID refuses any operator-supplied ID that
// contains it.
const RunInfix = ".run."

// ErrReservedSessionID means an operator-supplied session ID is unusable
// because it collides with reserved recorder session-naming syntax.
var ErrReservedSessionID = errors.New("session id uses reserved recorder syntax")

// ValidateOperatorSessionID refuses a session ID reachable from operator
// input (CLI flags, config, environment) that could collide with or subvert
// recorder session naming:
//
//   - the reserved run-session infix ".run.", which is minted only by
//     recorder.NewRunSessionID from crypto/rand and must stay unambiguous;
//   - a path separator ("/" or "\"), which the recorder never expects inside
//     a session ID (evidence filenames embed the session as one path
//     component) and which a malicious or mistaken value could otherwise use
//     to escape the evidence directory the writer computes it into;
//   - an empty ID, which is not a valid session or base name.
//
// It fails closed: an operator session ID that trips any of these is
// refused, with a message that names exactly what to change, rather than
// silently rewritten or accepted and left to fail later in a less legible
// way.
func ValidateOperatorSessionID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: session id must not be empty", ErrReservedSessionID)
	}
	if strings.Contains(id, RunInfix) {
		return fmt.Errorf("%w: session id %q contains the reserved run-session infix %q; "+
			"choose a session id that does not contain %q", ErrReservedSessionID, id, RunInfix, RunInfix)
	}
	if strings.ContainsAny(id, "/\\") {
		return fmt.Errorf("%w: session id %q contains a path separator; "+
			"choose a session id with no %q or %q characters", ErrReservedSessionID, id, "/", "\\")
	}
	return nil
}

// Parse splits a recorder evidence shard filename into its session ID and
// starting sequence. It accepts a bare name or a full path.
//
// Callers MUST compare the returned sessionID for equality rather than testing
// the filename against an "evidence-<session>-" prefix. The two are not the
// same: for session "s", the name "evidence-s-evil-999.jsonl" satisfies that
// prefix but belongs to session "s-evil", and it sorts above the real tail.
//
// The session is everything between the prefix and the LAST dash, so session
// IDs containing dashes round-trip. A non-numeric trailing segment yields a
// sequence of 0 with ok true, matching the writer's historical tolerance;
// callers that order by sequence should break ties on the basename, because
// several such names can collapse to the same value.
func Parse(name string) (sessionID string, seqStart uint64, ok bool) {
	name = filepath.Base(name)
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return "", 0, false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	lastDash := strings.LastIndex(rest, "-")
	if lastDash < 0 {
		return "", 0, false
	}
	n, err := strconv.ParseUint(rest[lastDash+1:], 10, 64)
	if err != nil {
		n = 0
	}
	return rest[:lastDash], n, true
}

// SeqStart returns only the parsed sequence, or 0 when the name is not a
// recorder evidence shard.
func SeqStart(name string) uint64 {
	_, seq, ok := Parse(name)
	if !ok {
		return 0
	}
	return seq
}

// ErrAmbiguousSeqStart reports two distinct shard names that parse to the same
// session and sequence start.
var ErrAmbiguousSeqStart = errors.New("ambiguous evidence shard sequence start")

// CheckNoDuplicateSeqStart refuses a shard set in which two distinct filenames
// parse to the same sequence start.
//
// The writer derives a shard name entirely from session plus sequence, so two
// names for one sequence cannot legitimately exist; the directory holds
// something this writer did not produce, and there is no principled way to pick
// between them. Every consumer of this directory contract applies the same rule,
// because the alternative is each one silently tie-breaking its own way: the
// recorder would choose one chain head, the emitter another, and verification a
// third, from the same bytes. Disagreement between those is worse than a refusal.
//
// names must already be ordered by sequence start; adjacent equality is what is
// checked. Ordering direction does not matter.
func CheckNoDuplicateSeqStart(names []string) error {
	for i := 1; i < len(names); i++ {
		prev, cur := filepath.Base(names[i-1]), filepath.Base(names[i])
		if prev == cur {
			continue
		}
		prevSession, prevSeq, prevOK := Parse(prev)
		curSession, curSeq, curOK := Parse(cur)
		// Compare the (session, sequence) PAIR, not the sequence alone. Callers
		// pass a single session's shards today, but a sequence-only comparison
		// would false-positive the moment one did not, and a spurious refusal
		// here stops receipt emission.
		if prevOK && curOK && prevSession == curSession && prevSeq == curSeq {
			return fmt.Errorf("%w: %s and %s both start session %q at sequence %d",
				ErrAmbiguousSeqStart, prev, cur, curSession, curSeq)
		}
	}
	return nil
}

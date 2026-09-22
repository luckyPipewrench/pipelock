// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

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

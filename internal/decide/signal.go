// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// RecordSignal is a nil-safe wrapper around RecordEscalation. It handles
// the common guard (nil recorder = no-op) shared by all proxy and MCP
// transports, then delegates to RecordEscalation for escalation tracking,
// audit logging, and metrics gauge updates. Returns true if an escalation
// transition occurred.
func RecordSignal(rec session.Recorder, sig session.SignalType, p EscalationParams) bool {
	if rec == nil {
		return false
	}
	return RecordEscalation(rec, sig, p)
}

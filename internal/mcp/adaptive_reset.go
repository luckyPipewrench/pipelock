// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"sync/atomic"
)

// adaptiveResetter clears one adaptive-enforcement session without importing
// the proxy package into MCP.
type adaptiveResetter interface {
	Reset() (prevScore float64, prevLevel int)
}

// consumeAdaptiveResetFile and consumeToolDriftResetFile deliberately share
// the same signed-delegation gate. File owner and mode are no longer authority.
func consumeAdaptiveResetFile(path string, authority *ResetAuthority, epoch *atomic.Uint64, logW io.Writer) ResetAuthorityDecision {
	return consumeMCPResetDelegation(path, authority, ResetKindAdaptive, newResetAtomicEpoch(epoch), logW)
}

func consumeToolDriftResetFile(path string, authority *ResetAuthority, epoch ResetEpoch, logW io.Writer) ResetAuthorityDecision {
	return consumeMCPResetDelegation(path, authority, ResetKindDrift, epoch, logW)
}

func consumeMCPResetDelegation(path string, authority *ResetAuthority, kind ResetKind, epoch ResetEpoch, logW io.Writer) ResetAuthorityDecision {
	if authority == nil {
		return ResetAuthorityDecision{Result: ResetAuthorityUnreadable}
	}
	decision := authority.ConsumeFile(path, kind, epoch)
	logResetAuthorityDecision(logW, decision)
	return decision
}

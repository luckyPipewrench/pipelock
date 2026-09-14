// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package ceereason holds the client-visible reasons and the receipt block
// kinds for cross-request exfiltration (CEE) denials. Both the MCP and the
// HTTP proxy transports deny through these values, so one deny reads the same
// everywhere and the two copies cannot drift apart. The client text is
// deliberately neutral: it names neither a tunable, a budget number, nor the
// matched pattern, because the untrusted agent reads it. The operator log and
// audit record carry the detail.
package ceereason

// Client-visible reasons. Each names the class of denial and nothing else.
const (
	// ClientFragmentMatch is returned when reassembled fragments matched a
	// secret pattern.
	ClientFragmentMatch = "cross-request exfiltration attempt blocked"
	// ClientEntropyBudget is returned when the per-window entropy budget was
	// exceeded.
	ClientEntropyBudget = "cross-request entropy budget exceeded"
	// ClientInspectionDepth is returned when a request nested too deeply for
	// safe field partitioning.
	ClientInspectionDepth = "cross-request inspection depth exceeded"
	// ClientSessionCapacity is returned when the fragment buffer has no room
	// to inspect the request safely.
	ClientSessionCapacity = "cross-request inspection capacity exhausted"
	// ClientOwnerMismatch is returned when a fragment stream would join
	// bytes from two identities.
	ClientOwnerMismatch = "cross-request inspection identity mismatch"
)

// Block kinds are the stable tokens a signed receipt carries in its Pattern
// field for a denial that matched no DLP pattern. A fragment match carries
// the matched pattern name instead.
const (
	KindEntropyBudget   = "entropy_budget"
	KindInspectionDepth = "inspection_depth"
	KindSessionCapacity = "session_capacity"
	KindOwnerMismatch   = "fragment_owner_mismatch"
)

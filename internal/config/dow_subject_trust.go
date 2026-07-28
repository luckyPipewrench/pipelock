// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

// DoWSubjectTrust grades how well a denial-of-wallet subject is identified.
//
// Protocol revision 2026-07-28 removes protocol-level sessions, so the proxy can
// no longer require server-minted session evidence before billing a subject: a
// conforming client has no session to present. Grading the identification and
// letting the operator declare the weakest grade they will bill against
// replaces that check without either refusing conforming traffic or silently
// billing every client to one shared bucket.
//
// Grades are ordered. Higher is better identified.
type DoWSubjectTrust int

const (
	// DoWTrustNetwork identifies the subject by transport peer address alone.
	// Always available and not client-assertable, but every client behind one
	// NAT or shared ingress collapses to a single subject.
	DoWTrustNetwork DoWSubjectTrust = iota

	// DoWTrustAgent adds an agent identity that Pipelock bound or configured
	// itself. A request-supplied agent name never reaches this grade; see
	// identitykey.CEESafeAgent, which exists to stop a client minting a fresh
	// budget bucket per claimed name.
	DoWTrustAgent

	// DoWTrustPrincipal identifies the subject by an authenticated principal,
	// such as an OAuth subject or an mTLS client identity. This is the only
	// grade that separates clients sharing a network path.
	DoWTrustPrincipal
)

// DoWSubjectTrustValues lists the accepted configuration spellings, weakest
// first. Used by validation and by operator-facing error text.
var DoWSubjectTrustValues = []string{"network", "agent", "principal"}

// String renders the grade using the operator-facing configuration spelling.
func (t DoWSubjectTrust) String() string {
	switch t {
	case DoWTrustPrincipal:
		return "principal"
	case DoWTrustAgent:
		return "agent"
	case DoWTrustNetwork:
		return "network"
	default:
		return "unknown"
	}
}

// Meets reports whether this grade satisfies an operator-declared minimum.
func (t DoWSubjectTrust) Meets(minimum DoWSubjectTrust) bool {
	return t >= minimum
}

// ParseDoWSubjectTrust maps a configuration spelling to a grade. An empty value
// yields the weakest grade: enabling budgets must not, by itself, begin
// refusing traffic that Pipelock can already account for. An unrecognised value
// reports false so validation can reject it at load rather than silently
// applying a weaker policy than the operator wrote.
func ParseDoWSubjectTrust(value string) (DoWSubjectTrust, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "network":
		return DoWTrustNetwork, true
	case "agent":
		return DoWTrustAgent, true
	case "principal":
		return DoWTrustPrincipal, true
	default:
		return DoWTrustNetwork, false
	}
}

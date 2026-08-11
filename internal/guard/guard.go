// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package guard turns a validated guard manifest into an enforced filesystem
// restriction. It is deliberately separate from internal/sandbox: that package
// implements a best-effort defence-in-depth layer whose contract tolerates a
// downgrade, while Guard's contract is that what it reports as enforced was
// enforced. Sharing an adapter would force one of those two contracts to bend,
// and the one that would bend in practice is this one.
//
// Nothing here is wired to a command yet. Guard remains unenforced as a product
// surface until the execution surface consumes this package; config validation
// still refuses a runtime guard declaration.
package guard

import (
	"errors"
	"fmt"
)

// RequiredABI is the minimum Landlock ABI version Guard will enforce on.
//
// Nine, not the highest the kernel happens to offer, and not the lowest that
// returns a ruleset. ABI 9 is the first version in which connect(2) and
// sendmsg(2) on pathname Unix sockets are mediated by filesystem rules at all.
// Below it, a path grant does not merely fail to cover sockets -- sockets are
// outside the model entirely, so a workload restricted to one state directory
// can still connect to any Unix socket on the host whose path it knows,
// including an SSH agent. Reproduced on Linux 7.1.5 / ABI 9: under a V5 ruleset
// a connect to a socket in a directory that was never granted SUCCEEDED, while
// a read of a file in that same directory was correctly denied. The restriction
// was active; sockets simply were not part of it.
//
// That is why this is a floor rather than a preference. Enforcing on ABI 8 and
// reporting success would be a true statement about files and a false statement
// about the isolation Guard is being trusted to provide.
const RequiredABI = 9

var (
	// ErrUnsupportedPlatform is returned when Guard enforcement has no
	// implementation for the running platform.
	ErrUnsupportedPlatform = errors.New("guard enforcement is not implemented on this platform")

	// ErrABITooOld is returned when Landlock is present but predates the
	// mediation Guard's claim depends on.
	ErrABITooOld = errors.New("landlock ABI below the minimum guard requires")

	// ErrLandlockUnavailable is returned when Landlock is absent entirely.
	ErrLandlockUnavailable = errors.New("landlock is unavailable on this kernel")

	// ErrManifestIncomplete is returned when at least one declared path could
	// not be granted. It is a distinct error because the correct response is a
	// refusal to launch, not a narrower grant: a declared path is a statement
	// that the workload needs it, and silently running without it produces a
	// failure the operator cannot trace back to Guard.
	ErrManifestIncomplete = errors.New("guard manifest could not be fully prepared")
)

// AccessKind is the grant a manifest entry asks for.
type AccessKind string

const (
	AccessReadFile       AccessKind = "read_only"
	AccessReadDirectory  AccessKind = "read_only_directories"
	AccessWriteFile      AccessKind = "read_write"
	AccessWriteDirectory AccessKind = "read_write_directories"
)

// IsDirectory reports whether the grant covers a subtree.
func (a AccessKind) IsDirectory() bool {
	return a == AccessReadDirectory || a == AccessWriteDirectory
}

// IsWrite reports whether the grant confers modification rights.
func (a AccessKind) IsWrite() bool {
	return a == AccessWriteFile || a == AccessWriteDirectory
}

// PathState is what actually happened to one declared path.
//
// The distinction between Withheld and Refused is load-bearing and is the
// reason this is not a bool. Refused means the compiled floor rejected the
// declaration and no amount of provisioning will change that. Withheld means
// the declaration is legitimate but the object is absent, which an operator
// can fix. Collapsing them would either present a floor refusal as a
// provisioning problem, inviting an operator to "fix" it by creating
// credential-adjacent state, or present a missing directory as a policy
// violation.
type PathState string

const (
	// StateGranted: the object existed and was pinned as declared.
	StateGranted PathState = "granted"
	// StateCreated: an absent read-write directory leaf was created by Guard
	// and then pinned.
	StateCreated PathState = "created"
	// StateWithheld: the object is absent and Guard will not create it.
	StateWithheld PathState = "withheld_missing"
	// StateRefused: the compiled floor rejected this declaration.
	StateRefused PathState = "refused"
)

// Granted reports whether this outcome produced an actual rule.
func (s PathState) Granted() bool { return s == StateGranted || s == StateCreated }

// PathOutcome records the disposition of one declared path. Every declared
// path produces exactly one of these, including the ones that produced no
// rule, so an operator reading the result can tell the difference between a
// path that was covered and one that silently was not.
type PathOutcome struct {
	DeclaredPath string     `json:"declared_path"`
	ResolvedPath string     `json:"resolved_path,omitempty"`
	Access       AccessKind `json:"access"`
	State        PathState  `json:"state"`
	Reason       string     `json:"reason,omitempty"`
}

// EnforcementState is the outcome of an enforcement attempt.
type EnforcementState string

const (
	// EnforcementEnforced: the restriction was applied at the required ABI.
	EnforcementEnforced EnforcementState = "enforced"
	// EnforcementUnenforcedAccepted: enforcement was impossible and an
	// operator explicitly accepted running without it.
	EnforcementUnenforcedAccepted EnforcementState = "unenforced_accepted"
	// EnforcementRefused: enforcement was impossible and Guard refused.
	EnforcementRefused EnforcementState = "refused"
)

// EnforcementRecord is the durable statement of what Guard actually did.
//
// It is a struct rather than a bool because a bool is exactly what gets
// dropped. The failure this shape exists to prevent is a caller receiving
// "true" from a call that silently downgraded, then writing "enforced" into
// evidence. ObservedABI is a pointer so that "no reading was taken" is
// distinguishable from "the reading was zero"; conflating them would let an
// unread value present as the worst case and then be argued away as a default.
type EnforcementRecord struct {
	State            EnforcementState `json:"state"`
	Mechanism        string           `json:"mechanism"`
	RequiredABI      int              `json:"required_abi"`
	ObservedABI      *int             `json:"observed_abi"`
	Reason           string           `json:"reason,omitempty"`
	ManifestComplete bool             `json:"manifest_complete"`
	Outcomes         []PathOutcome    `json:"outcomes"`
}

// Enforced reports whether the workload is actually constrained. Callers must
// route every "is this enforced" question through here rather than testing
// State themselves, so a future state cannot be silently read as enforced.
func (r EnforcementRecord) Enforced() bool { return r.State == EnforcementEnforced }

// Describe renders the record for an operator. An unenforced run says so in
// the first clause; the reason follows rather than leads, because a reason
// reads as an excuse and the state is the fact.
func (r EnforcementRecord) Describe() string {
	observed := "unread"
	if r.ObservedABI != nil {
		observed = fmt.Sprintf("%d", *r.ObservedABI)
	}
	switch r.State {
	case EnforcementEnforced:
		return fmt.Sprintf("ENFORCED via %s (ABI %s, required %d)", r.Mechanism, observed, r.RequiredABI)
	case EnforcementUnenforcedAccepted:
		return fmt.Sprintf("NOT ENFORCED, explicitly accepted by the operator (ABI %s, required %d): %s", observed, r.RequiredABI, r.Reason)
	default:
		return fmt.Sprintf("REFUSED, not enforced and not run (ABI %s, required %d): %s", observed, r.RequiredABI, r.Reason)
	}
}

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
	"strings"
)

// Landlock ABI thresholds Guard cares about. Each names a capability rather
// than a kernel release, because the capability is what a claim depends on.
//
// The original design required ABI 9 outright, on the reasoning that below it
// pathname Unix sockets are outside the filesystem model entirely and a
// "restricted" workload can still reach an SSH agent socket. That reasoning is
// correct and is measured: on Linux 7.1.5 under a V5 ruleset, a connect to a
// socket in a never-granted directory SUCCEEDED while a read of a file in that
// same directory was denied.
//
// But a flat ABI 9 floor refuses essentially every kernel in service today,
// which is its own failure direction: a control an operator cannot run is a
// control an operator turns off. The resolution is not to lower the bar and
// keep the claim, it is to keep the bar per-capability and make the RECORD say
// exactly which mediation is in force. Guard never reports coverage it does not
// have; it is willing to report less coverage honestly.
const (
	// MinimumABI is the floor for the full filesystem right set, through
	// ioctl_dev. Below this Guard cannot express its grants and refuses.
	MinimumABI = 5

	// IPCScopeABI adds scoping for abstract Unix sockets and signals. Below it,
	// a restricted workload can still signal and speak to abstract-socket peers
	// outside its domain.
	IPCScopeABI = 6

	// ThreadSyncABI adds kernel-side thread synchronisation, which in-process
	// enforcement requires. The userspace alternative enumerates /proc/self/task
	// and is denied by Guard's own ruleset, leaving the process half-restricted,
	// so there is no safe in-process path below this.
	ThreadSyncABI = 8

	// SocketMediationABI adds connect(2) and sendmsg(2) mediation for pathname
	// Unix sockets. This is the one that decides whether a filesystem grant can
	// bound IPC at all.
	SocketMediationABI = 9
)

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

	// ErrPolicyNarrowed is returned when the restriction applied but a declared
	// path is unreachable under it, meaning something outside this ruleset --
	// most often an ancestor landlock domain -- is narrowing the policy. The
	// manifest is not in force as declared, so this is a refusal, not a caveat.
	ErrPolicyNarrowed = errors.New("guard policy is narrowed by an outer restriction")

	// ErrAlreadyApplied is returned when a prepared manifest is applied twice.
	// Landlock restrictions stack and cannot be lifted, so a second application
	// would intersect the policy with itself and narrow it for good.
	ErrAlreadyApplied = errors.New("guard manifest has already been applied")
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
	// EnforcementRefused: enforcement was impossible and Guard refused. The
	// process was not modified.
	EnforcementRefused EnforcementState = "refused"
	// EnforcementAppliedNarrowed: the restriction WAS applied and the process is
	// permanently constrained, but the manifest is not in force as declared
	// because something outside this policy narrows it.
	//
	// This state exists because the alternative was a false record. A failed
	// post-enforcement check used to return Refused, whose wording is "not
	// enforced and not run" -- while the process was already irreversibly
	// restricted and no_new_privs was already set. Refusing and having applied
	// nothing is a different situation from having applied a restriction that
	// does not match the declaration, and an operator reading the record has to
	// be able to tell them apart. Neither is a success.
	EnforcementAppliedNarrowed EnforcementState = "applied_narrowed"
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
	Coverage         Coverage         `json:"coverage"`
	// Unmediated names each capability the kernel could not mediate at the
	// observed ABI. It is a list rather than a flag because "enforced" with an
	// empty caveat list and "enforced" with sockets unmediated are different
	// security postures, and an operator reading evidence months later needs to
	// see which one they had.
	Unmediated []string `json:"unmediated,omitempty"`
	// Unverified names declared paths whose grant could not be confirmed after
	// enforcement, as distinct from paths confirmed to be narrowed. A
	// filesystem that cannot answer the question is not evidence of a problem
	// and is not evidence of correctness either, so it is reported as its own
	// thing rather than folded into either.
	Unverified []string      `json:"unverified,omitempty"`
	Outcomes   []PathOutcome `json:"outcomes"`
}

// Coverage says how much of Guard's intended mediation the kernel supplied.
type Coverage string

const (
	// CoverageUnknown is the zero value: no enforcement was attempted.
	CoverageUnknown Coverage = ""
	// CoverageFull: every capability Guard relies on is mediated.
	CoverageFull Coverage = "full"
	// CoveragePartial: the filesystem grants are enforced, but at least one
	// capability in Unmediated is not covered.
	CoveragePartial Coverage = "partial"
)

// Enforced reports whether the workload is actually constrained. Callers must
// route every "is this enforced" question through here rather than testing
// State themselves, so a future state cannot be silently read as enforced.
//
// This is deliberately true for partial coverage: the filesystem grants ARE in
// force. Anything that turns on the difference must ask FullyMediated, so that
// the weaker posture has to be looked at rather than inherited by accident.
func (r EnforcementRecord) Enforced() bool { return r.State == EnforcementEnforced }

// FullyMediated reports whether every capability Guard relies on is covered.
// A claim about isolation, as opposed to about files, belongs behind this.
func (r EnforcementRecord) FullyMediated() bool {
	return r.State == EnforcementEnforced && r.Coverage == CoverageFull
}

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
		if r.Coverage == CoverageFull {
			return fmt.Sprintf("ENFORCED via %s, full mediation (ABI %s)", r.Mechanism, observed)
		}
		// The caveat is part of the headline, not a footnote. An operator who
		// reads only the first line must not come away believing sockets were
		// covered when they were not.
		return fmt.Sprintf("ENFORCED via %s, PARTIAL mediation (ABI %s): not mediated: %s",
			r.Mechanism, observed, strings.Join(r.Unmediated, ", "))
	case EnforcementAppliedNarrowed:
		// The leading clause says the process IS restricted, because it is, and
		// an operator who reads only the first line must not conclude the run
		// was left untouched.
		return fmt.Sprintf("RESTRICTION APPLIED BUT NARROWED, the process is constrained and the manifest is NOT in force as declared (ABI %s): %s", observed, r.Reason)
	case EnforcementUnenforcedAccepted:
		return fmt.Sprintf("NOT ENFORCED, explicitly accepted by the operator (ABI %s, required %d): %s", observed, r.RequiredABI, r.Reason)
	default:
		return fmt.Sprintf("REFUSED, not enforced and not run (ABI %s, required %d): %s", observed, r.RequiredABI, r.Reason)
	}
}

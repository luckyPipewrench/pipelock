// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"fmt"
	"runtime"
	"strings"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// handledAccessFS is the set of operations the ruleset MEDIATES.
//
// This mask, not the per-path grants, is what decides whether an operation is
// governed at all. An operation absent from here is unrestricted no matter what
// the path rules say, which is the single easiest way to build a ruleset that
// looks strict and enforces nothing. Two entries are here specifically because
// they are never granted to any path:
//
//   - ResolveUnix: handled so connect(2) and sendmsg(2) on pathname Unix
//     sockets are denied everywhere. This is the bit whose absence at ABI 5
//     leaves an SSH agent socket reachable from a fully restricted process.
//   - IoctlDev: handled so device ioctls are denied even on a granted path.
//
// MakeChar and MakeBlock are handled and never granted, so device-node
// creation is denied outright.
const baseAccessFS = llsys.AccessFSExecute |
	llsys.AccessFSWriteFile |
	llsys.AccessFSReadFile |
	llsys.AccessFSReadDir |
	llsys.AccessFSRemoveDir |
	llsys.AccessFSRemoveFile |
	llsys.AccessFSMakeChar |
	llsys.AccessFSMakeDir |
	llsys.AccessFSMakeReg |
	llsys.AccessFSMakeSock |
	llsys.AccessFSMakeFifo |
	llsys.AccessFSMakeBlock |
	llsys.AccessFSMakeSym |
	llsys.AccessFSRefer |
	llsys.AccessFSTruncate |
	llsys.AccessFSIoctlDev

// scopedIPC severs abstract Unix sockets and signals to processes outside the
// restricted domain. Pathname sockets are covered by the handled access mask;
// abstract sockets have no path, so they need this instead.
const scopedIPC = llsys.ScopeAbstractUnixSocket | llsys.ScopeSignal

// capabilitiesFor returns the ruleset masks the observed ABI can actually
// express, plus the human-readable list of what it cannot.
//
// Requesting a right the kernel does not know is not a soft failure: it makes
// LandlockCreateRuleset reject the whole ruleset, so the mask has to be built
// from the observed version rather than from the ideal one. The critical part
// is the third return value. Trimming the mask silently is precisely what
// BestEffort does, and precisely what turns an unavailable protection into a
// successful call, so every trimmed capability is named and carried into the
// record instead.
func capabilitiesFor(abi int) (accessFS, scoped uint64, unmediated []string) {
	accessFS = baseAccessFS
	if abi >= SocketMediationABI {
		accessFS |= llsys.AccessFSResolveUnix
	} else {
		unmediated = append(unmediated,
			"connect(2) and sendmsg(2) on pathname unix sockets, including agent sockets")
	}
	if abi >= IPCScopeABI {
		scoped = scopedIPC
	} else {
		unmediated = append(unmediated,
			"abstract unix sockets and signals to processes outside the restriction")
	}
	return accessFS, scoped, unmediated
}

// Apply enforces the prepared manifest on the calling process. It is
// irreversible and inherited by every child.
//
// It refuses rather than downgrades. go-landlock's BestEffort would accept an
// older kernel by quietly dropping the rights it cannot express and returning
// no error, which for Guard would turn "the socket restriction is unavailable"
// into a successful call that a caller then records as enforced.
//
// The returned record is the only permitted source of truth about what
// happened; a nil error alone does not mean enforced.
func (p *PreparedManifest) Apply() (EnforcementRecord, error) {
	return p.apply(llsys.LandlockGetABIVersion)
}

func (p *PreparedManifest) apply(getABI func() (int, error)) (EnforcementRecord, error) {
	record := EnforcementRecord{
		State:            EnforcementRefused,
		Mechanism:        "landlock",
		RequiredABI:      ThreadSyncABI,
		ManifestComplete: p.complete,
		Outcomes:         p.Outcomes(),
	}

	abi, err := getABI()
	if err != nil {
		record.Reason = fmt.Sprintf("landlock is unavailable: %v", err)
		return record, fmt.Errorf("%w: %w", ErrLandlockUnavailable, err)
	}
	record.ObservedABI = &abi
	if abi < MinimumABI {
		record.Reason = fmt.Sprintf(
			"kernel landlock ABI %d is below the minimum %d; the full filesystem right set cannot be expressed, so the declared grants cannot be enforced as written",
			abi, MinimumABI)
		return record, fmt.Errorf("%w: have %d, need %d", ErrABITooOld, abi, MinimumABI)
	}
	// In-process enforcement additionally needs kernel-side thread sync. That is
	// a limitation of restricting an already-running multi-threaded process, not
	// of the policy: applying the same ruleset in a single-threaded child
	// between fork and exec needs only MinimumABI, which is the route the
	// execution surface should take.
	if abi < ThreadSyncABI {
		record.Reason = fmt.Sprintf(
			"kernel landlock ABI %d is below %d, so this ruleset cannot be applied to every thread of this process atomically; apply it in a single-threaded child before exec instead",
			abi, ThreadSyncABI)
		return record, fmt.Errorf("%w: have %d, need %d for in-process application", ErrABITooOld, abi, ThreadSyncABI)
	}

	handledAccessFS, scoped, unmediated := capabilitiesFor(abi)
	record.Unmediated = unmediated
	record.Coverage = CoverageFull
	if len(unmediated) > 0 {
		record.Coverage = CoveragePartial
	}

	// An incomplete manifest is refused here rather than at the call site, so
	// no caller can enforce a partial policy by forgetting to check. A declared
	// path that could not be granted is a denied grant, and a denied grant that
	// the workload was told it had is a failure the operator cannot diagnose.
	if !p.complete {
		record.Reason = "at least one declared path could not be granted; refusing to enforce a partial manifest"
		return record, ErrManifestIncomplete
	}

	rulesetFD, err := llsys.LandlockCreateRuleset(&llsys.RulesetAttr{
		HandledAccessFS: handledAccessFS,
		Scoped:          scoped,
	}, 0)
	if err != nil {
		record.Reason = fmt.Sprintf("creating landlock ruleset: %v", err)
		return record, fmt.Errorf("creating landlock ruleset: %w", err)
	}
	defer func() { _ = unix.Close(rulesetFD) }()

	for _, rule := range p.rules {
		attr := llsys.PathBeneathAttr{
			AllowedAccess: rule.access,
			ParentFd:      rule.fd,
		}
		if err := llsys.LandlockAddPathBeneathRule(rulesetFD, &attr, 0); err != nil {
			record.Reason = fmt.Sprintf("adding rule for %q: %v", rule.declared, err)
			return record, fmt.Errorf("adding landlock rule for %q: %w", rule.declared, err)
		}
	}

	// Landlock restricts a THREAD, not a process, and the Go runtime schedules
	// goroutines across many OS threads. Restricting only the calling thread
	// would leave every other thread unrestricted while returning no error at
	// all, which is the same silent partial enforcement this package exists to
	// eliminate, reached from the opposite direction. Driving the raw syscall
	// layer to pin descriptors means owning that problem rather than inheriting
	// the high-level helper's answer to it.
	//
	// The answer is TSYNC: the kernel applies the ruleset to every thread of
	// the process atomically. It is available from ABI 8, and Guard already
	// requires 9, so it is always the path taken here.
	//
	// The userspace alternative -- enumerate /proc/self/task and restrict each
	// thread -- is not merely slower, it is self-defeating for Guard. That walk
	// needs to read /proc, and a Guard ruleset grants only the manifest's paths,
	// so the enumeration is denied by the very restriction it is applying. It
	// fails partway through with the process already half-restricted. That is
	// not theoretical: it is what this code did before, and the enforcement
	// test caught it as a killed child rather than a wrong answer.
	//
	// LockOSThread pins this goroutine for the call so it cannot migrate to
	// another thread between the prctl and the restrict.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		record.Reason = fmt.Sprintf("setting no_new_privs: %v", err)
		return record, fmt.Errorf("setting no_new_privs: %w", err)
	}

	if err := llsys.LandlockRestrictSelf(rulesetFD, llsys.FlagRestrictSelfTSync); err != nil {
		record.Reason = fmt.Sprintf("applying landlock restriction: %v", err)
		return record, fmt.Errorf("applying landlock restriction: %w", err)
	}

	// Verify the manifest is actually in force before claiming it is.
	//
	// Landlock rulesets STACK: if this process already sits inside an ancestor
	// domain, the effective policy is the intersection of the two, and a path
	// this manifest grants can still be unreachable. Nothing reports that. The
	// syscalls above all succeeded, the record would read "enforced", and the
	// workload would then be denied a path its own manifest says it has, with
	// no way to trace the denial back to the ancestor.
	//
	// There is no syscall or /proc file that reports the ancestor domain, so
	// asking "am I nested" is not available. Measuring the thing that actually
	// matters is: after restricting, try to reach each granted path. Every
	// right set Guard issues includes read on the object, so a denial here means
	// something outside this ruleset is narrowing us.
	//
	// This fails CLOSED. A narrowed policy is reported and refused rather than
	// presented as the declared one.
	if narrowed := p.unreachableGrants(); len(narrowed) > 0 {
		record.State = EnforcementRefused
		record.Reason = fmt.Sprintf(
			"the restriction applied, but %d declared path(s) are unreachable under it (%s); an ancestor landlock domain or another restriction is narrowing this policy, so the manifest is not in force as declared",
			len(narrowed), strings.Join(narrowed, ", "))
		return record, fmt.Errorf("%w: %s", ErrPolicyNarrowed, strings.Join(narrowed, ", "))
	}

	record.State = EnforcementEnforced
	return record, nil
}

// unreachableGrants returns the declared paths that cannot be reached after the
// restriction was applied.
//
// It re-resolves by NAME rather than reusing the pinned descriptors, and that
// is the whole point: a descriptor opened before enforcement stays usable
// afterwards, so probing through one would report success no matter how
// narrowed the policy is. That would be a vacuous check dressed as a
// verification.
func (p *PreparedManifest) unreachableGrants() []string {
	var narrowed []string
	for _, rule := range p.rules {
		if !reopenGrant(rule, unix.O_RDONLY) {
			narrowed = append(narrowed, rule.declared)
			continue
		}
		// Opening an exact file O_WRONLY asks the kernel for WriteFile but
		// does not write or truncate it. A read-only outer domain can therefore
		// not make a declared read-write file look reachable just because the
		// old read probe succeeded.
		if rule.kind == AccessWriteFile && !reopenGrant(rule, unix.O_WRONLY) {
			narrowed = append(narrowed, rule.declared)
		}
	}
	return narrowed
}

// reopenGrant tests an operation against the post-restriction pathname and
// closes it immediately. The access mode is deliberately part of the probe:
// O_RDONLY checks that every grant is reachable, while O_WRONLY checks an exact
// writable file's WriteFile right without changing the file.
func reopenGrant(rule preparedRule, access int) bool {
	flags := access | unix.O_CLOEXEC
	if rule.isDir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(rule.resolved, flags, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

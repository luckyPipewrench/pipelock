// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
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
	return p.applyMode(getABI, true)
}

// ApplyForExec enforces the manifest on the calling thread for an immediate
// exec. The caller must perform no concurrent application work and must replace
// the process image after this returns. The exec'd program inherits the domain,
// and every thread it later creates inherits it too, so base Landlock ABI 5 is
// sufficient; kernel thread synchronization is only required by Apply's
// already-multithreaded in-process contract.
func (p *PreparedManifest) ApplyForExec() (EnforcementRecord, error) {
	return p.applyWithOperations(kernelRulesetOperations(), false)
}

func (p *PreparedManifest) applyMode(getABI func() (int, error), threadSync bool) (EnforcementRecord, error) {
	ops := kernelRulesetOperations()
	ops.getABI = getABI
	return p.applyWithOperations(ops, threadSync)
}

type rulesetOperations struct {
	getABI        func() (int, error)
	createRuleset func(*llsys.RulesetAttr, int) (int, error)
	addPathRule   func(int, *llsys.PathBeneathAttr, int) error
	restrictSelf  func(int, uint32) error
	setNoNewPrivs func() error
	closeFD       func(int) error
}

func kernelRulesetOperations() rulesetOperations {
	return rulesetOperations{
		getABI:        llsys.LandlockGetABIVersion,
		createRuleset: llsys.LandlockCreateRuleset,
		addPathRule:   llsys.LandlockAddPathBeneathRule,
		restrictSelf:  llsys.LandlockRestrictSelf,
		setNoNewPrivs: func() error { return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
		closeFD:       unix.Close,
	}
}

func (p *PreparedManifest) applyWithOperations(ops rulesetOperations, threadSync bool) (EnforcementRecord, error) {
	// Held for the whole call. Close writes -1 over each descriptor, so a
	// concurrent Close could otherwise leave rule construction handing a stale
	// descriptor NUMBER to the kernel, and a freed number can be reused by any
	// other open in the process, which would grant an unrelated object.
	p.mu.Lock()
	defer p.mu.Unlock()

	record := EnforcementRecord{
		State:            EnforcementRefused,
		Mechanism:        "landlock",
		RequiredABI:      MinimumABI,
		ManifestComplete: p.complete,
		Outcomes:         p.Outcomes(),
	}

	// Checked before anything else, because applying twice is a caller mistake
	// whatever the kernel supports. Landlock restrictions stack and cannot be
	// lifted, so a second application intersects the policy with itself and
	// narrows it for good.
	if p.applied {
		record.Reason = "this manifest was already applied; landlock restrictions are irreversible and stack, so applying again would narrow the policy for good"
		return record, ErrAlreadyApplied
	}

	abi, err := ops.getABI()
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
	if threadSync && abi < ThreadSyncABI {
		record.Reason = fmt.Sprintf(
			"kernel landlock ABI %d is below %d, so this ruleset cannot be applied to every thread of this process atomically; apply it in a single-threaded child before exec instead",
			abi, ThreadSyncABI)
		return record, fmt.Errorf("%w: have %d, need %d for in-process application", ErrABITooOld, abi, ThreadSyncABI)
	}
	if threadSync {
		record.RequiredABI = ThreadSyncABI
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
		missing := make([]string, 0)
		for _, outcome := range p.outcomes {
			if outcome.State.Granted() {
				continue
			}
			missing = append(missing, fmt.Sprintf("%s (%s: %s)", outcome.DeclaredPath, outcome.State, outcome.Reason))
		}
		record.Reason = "at least one declared path could not be granted; refusing to enforce a partial manifest: " + strings.Join(missing, "; ")
		return record, ErrManifestIncomplete
	}

	rulesetFD, err := ops.createRuleset(&llsys.RulesetAttr{
		HandledAccessFS: handledAccessFS,
		Scoped:          scoped,
	}, 0)
	if err != nil {
		record.Reason = fmt.Sprintf("creating landlock ruleset: %v", err)
		return record, fmt.Errorf("creating landlock ruleset: %w", err)
	}
	defer func() { _ = ops.closeFD(rulesetFD) }()

	for _, rule := range p.rules {
		attr := llsys.PathBeneathAttr{
			AllowedAccess: rule.access,
			ParentFd:      rule.fd,
		}
		if err := ops.addPathRule(rulesetFD, &attr, 0); err != nil {
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
	// the process atomically. It is available from ABI 8, which is exactly what
	// ThreadSyncABI requires above, so it is always the path taken here.
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
	// another thread between the prctl and the restrict. The optional TSYNC
	// flag synchronizes existing threads only for the in-process Apply path.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ops.setNoNewPrivs(); err != nil {
		record.Reason = fmt.Sprintf("setting no_new_privs: %v", err)
		return record, fmt.Errorf("setting no_new_privs: %w", err)
	}

	flags := uint32(0)
	if threadSync {
		flags = llsys.FlagRestrictSelfTSync
	}
	if err := ops.restrictSelf(rulesetFD, flags); err != nil {
		record.Reason = fmt.Sprintf("applying landlock restriction: %v", err)
		return record, fmt.Errorf("applying landlock restriction: %w", err)
	}
	// Set here rather than on the success path: the process is constrained from
	// this point on whatever the verification below concludes.
	p.applied = true

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
	narrowed, unverified := p.unreachableGrants()
	// Recorded before the narrowed return, not after. A manifest can have both
	// outcomes, and returning early on the narrowed one used to drop every
	// unverified path from the record -- losing exactly the information an
	// operator needs to know how much of the policy was actually confirmed.
	record.Unverified = unverified
	if len(narrowed) > 0 {
		// Applied, not refused. By this point the ruleset is in force and
		// no_new_privs is set, and neither can be undone. Reporting Refused
		// here would tell an operator the process was left alone when it is
		// permanently constrained.
		record.State = EnforcementAppliedNarrowed
		record.Reason = fmt.Sprintf(
			"the restriction applied, but %d declared path(s) are not in force under it (%s); an ancestor landlock domain or another restriction is narrowing this policy, so the manifest is not in force as declared",
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
func (p *PreparedManifest) unreachableGrants() ([]string, []string) {
	var narrowed, unverified []string
	for _, rule := range p.rules {
		if !reopenGrant(rule, unix.O_RDONLY) {
			narrowed = append(narrowed, rule.declared)
			continue
		}
		switch rule.kind {
		case AccessWriteFile:
			// Opening an exact file O_WRONLY asks the kernel for WriteFile but
			// does not write or truncate it.
			if !reopenGrant(rule, unix.O_WRONLY) {
				narrowed = append(narrowed, rule.declared)
			}
		case AccessWriteDirectory:
			switch writableDirectory(rule.resolved) {
			case dirWriteDenied:
				narrowed = append(narrowed, rule.declared)
			case dirWriteUnsupported:
				unverified = append(unverified, rule.declared)
			}
		}
	}
	return narrowed, unverified
}

// dirWriteResult is the outcome of probing a directory for write access.
type dirWriteResult int

const (
	dirWriteOK dirWriteResult = iota
	dirWriteDenied
	dirWriteUnsupported
)

// writableDirectory reports whether the workload can still write inside a
// declared directory, without leaving anything behind.
//
// O_TMPFILE creates an UNNAMED inode in the directory. It requires write
// permission, it never links a name, and closing the descriptor frees it, so
// the directory is byte-for-byte unchanged. That matters because the honest
// alternative was creating and deleting a probe file inside the workload's own
// state, which races with the workload and leaves debris when it dies between
// the two steps.
//
// Measured on Linux 7.1.5 against an outer read-only rule on a declared
// read-write directory: the O_RDONLY probe SUCCEEDS (so a read-only check
// cannot see this narrowing at all) while O_TMPFILE is denied, and zero files
// appear in either directory.
//
// faccessat2(W_OK) is NOT a substitute and must not be swapped in for looking
// cheaper: Landlock does not mediate it. In that same measurement it returned
// success on the narrowed directory, which is a fail-open.
//
// A filesystem that does not implement O_TMPFILE reports unsupported rather
// than denied. Refusing a correct policy because the filesystem cannot answer
// the question is an availability failure, and Guard reports what it could not
// verify instead of inventing a verdict.
func writableDirectory(path string) dirWriteResult {
	fd, err := unix.Open(path, unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
	if err == nil {
		_ = unix.Close(fd)
		return dirWriteOK
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
		return dirWriteDenied
	}
	// EOPNOTSUPP and EISDIR are what a filesystem without O_TMPFILE support
	// returns. Anything else unexpected is also treated as "could not verify"
	// rather than as a denial, for the same availability reason.
	return dirWriteUnsupported
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

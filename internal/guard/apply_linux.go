// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"fmt"
	"runtime"

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
const handledAccessFS = llsys.AccessFSExecute |
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
	llsys.AccessFSIoctlDev |
	llsys.AccessFSResolveUnix

// scopedIPC additionally severs abstract Unix sockets and signals to processes
// outside the restricted domain. Pathname sockets are covered by the handled
// access mask above; abstract sockets have no path, so they need this instead.
const scopedIPC = llsys.ScopeAbstractUnixSocket | llsys.ScopeSignal

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
		RequiredABI:      RequiredABI,
		ManifestComplete: p.complete,
		Outcomes:         p.Outcomes(),
	}

	abi, err := getABI()
	if err != nil {
		record.Reason = fmt.Sprintf("landlock is unavailable: %v", err)
		return record, fmt.Errorf("%w: %w", ErrLandlockUnavailable, err)
	}
	record.ObservedABI = &abi
	if abi < RequiredABI {
		record.Reason = fmt.Sprintf(
			"kernel landlock ABI %d is below the minimum %d; below ABI %d, connect(2) on pathname unix sockets is not mediated, so a filesystem restriction cannot bound IPC",
			abi, RequiredABI, RequiredABI)
		return record, fmt.Errorf("%w: have %d, need %d", ErrABITooOld, abi, RequiredABI)
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
		Scoped:          scopedIPC,
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

	record.State = EnforcementEnforced
	return record, nil
}

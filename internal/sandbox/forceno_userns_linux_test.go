// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// applyUserNSDenyFilter makes unprivileged user-namespace creation fail for this
// process and everything it execs, and does nothing else.
//
// The best-effort fallback proof needs exactly one condition: probeUserNamespace
// must fail, so the sandbox takes its no-namespace path. It previously got that
// by calling ApplySeccomp, the real production filter. That works, but seccomp
// is inherited across fork AND exec, so the whole tree under test inherited it:
// the Pipelock proxy, sandbox-init, and the CPython target all then ran under a
// filter built for a confined child, including SECCOMP_RET_KILL_PROCESS rules
// and denials for socket, personality and clone3.
//
// That is a far wider blast radius than the test intends, and it made the proof
// intermittent: the target exited without writing a response, the proxy reported
// a subprocess exit, and the failure appeared only under machine load, which is
// when the Go runtime creates the most threads and touches the most of that
// surface. An intermittent failure in this specific test is expensive, because
// it is the ONLY one that supplies independent evidence for the dumpability
// hardening. Default and strict modes are over-determined by the user-namespace
// boundary, which denies the read whether or not the hardening works.
//
// A test-only environment override on the probe was considered and rejected.
// Forcing "no namespaces" makes the sandbox weaker, so a knob that does it is a
// capability-reducing bypass living in the process environment, which is exactly
// the surface the surrounding work exists to protect.
func applyUserNSDenyFilter(t *testing.T) {
	t.Helper()

	if err := SetNoNewPrivs(); err != nil {
		t.Fatalf("set no_new_privs before user-namespace deny filter: %v", err)
	}

	// clone3 is deliberately NOT denied. probeUserNamespace issues a raw
	// SYS_CLONE, so denying namespace flags on clone is sufficient, and the Go
	// runtime creates OS threads with clone3: denying it kills the runtime
	// rather than the probe, which is a crash, not a fallback.
	filter := []unix.SockFilter{
		bpfLoad(offsetNR),
		// clone: inspect flags, deny only when a CLONE_NEW* bit is set.
		bpfJumpEq(unix.SYS_CLONE, 0, 3),
		bpfLoad(offsetArgs0),
		bpfJumpSet(cloneNewMask, 0, 1),
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)),
		bpfRet(unix.SECCOMP_RET_ALLOW),
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)), // #nosec G115 -- fixed small filter, length is a compile-time constant
		Filter: &filter[0],
	}
	if failedThread, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&prog)), // #nosec G103 -- required by the seccomp syscall ABI
	); errno != 0 {
		t.Fatalf("install user-namespace deny filter: %v", errno)
	} else if failedThread != 0 {
		t.Fatalf("install user-namespace deny filter: thread synchronization failed at thread %d", failedThread)
	}
}

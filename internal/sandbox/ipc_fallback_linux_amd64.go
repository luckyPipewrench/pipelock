// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"fmt"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// startSandboxTarget preserves Unix socket access in the trusted bridge on
// kernels without pathname socket mediation. The target inherits a stricter
// filter from the exact thread which forks it. That thread is retired when
// the goroutine exits; it must never return to the runtime's worker pool.
func startSandboxTarget(cmd *exec.Cmd, filesystem LayerStatus) error {
	if filesystem.Active && filesystem.Version >= 9 {
		return cmd.Start()
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately no UnlockOSThread: this permanently restricted thread
		// must not later execute bridge work.
		if err := restrictTargetUnixSockets(); err != nil {
			done <- err
			return
		}
		done <- cmd.Start()
	}()
	return <-done
}

// restrictTargetUnixSockets installs a thread-local, inherited filter. Its
// caller must remain pinned until exec/fork or retire the thread. Datagram
// socketpairs are denied because they can be redirected to a pathname address.
// Connected stream and sequenced-packet pairs remain available for stdio and
// runtime signal self-pipes; they cannot connect to a different peer.
// All recvmsg/recvmmsg calls are denied: classic BPF cannot inspect msghdr to
// distinguish ordinary messages from ancillary descriptor imports. Inherited
// Unix descriptors can still send; this filter does not revoke existing fds.
func restrictTargetUnixSockets() error {
	filter := targetUnixSocketFilter()
	// #nosec G115 -- the fixed filter below is far shorter than 65536 entries.
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := SetNoNewPrivs(); err != nil {
		return fmt.Errorf("unix socket isolation prerequisite: %w", err)
	}
	// #nosec G103 -- the kernel copies the filter during this synchronous call.
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return fmt.Errorf("unix socket isolation filter: %w", errno)
	}
	return nil
}

func targetUnixSocketFilter() []unix.SockFilter {
	return []unix.SockFilter{
		bpfLoad(offsetArch),
		bpfJumpEq(unix.AUDIT_ARCH_X86_64, 1, 0),
		bpfRet(unix.SECCOMP_RET_KILL_PROCESS),
		bpfLoad(offsetNR),
		bpfJumpSet(0x40000000, 0, 1), // x32 uses the same audit architecture.
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)),
		bpfJumpEq(unix.SYS_RECVMSG, 0, 1),
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)),
		bpfJumpEq(unix.SYS_RECVMMSG, 0, 1),
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)),
		bpfJumpEq(unix.SYS_SOCKET, 0, 3),
		bpfLoad(offsetArgs0),
		bpfJumpEq(unix.AF_UNIX, 0, 1),
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)),
		bpfJumpEq(unix.SYS_SOCKETPAIR, 0, 5),
		bpfLoad(offsetArgs0 + 8),
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0xf}, // Strip SOCK_CLOEXEC and SOCK_NONBLOCK.
		bpfJumpEq(unix.SOCK_STREAM, 2, 0),
		bpfJumpEq(unix.SOCK_SEQPACKET, 1, 0),
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)),
		bpfRet(unix.SECCOMP_RET_ALLOW),
	}
}

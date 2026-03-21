// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccomp_data offsets for BPF instructions (struct seccomp_data layout).
const (
	offsetNR    = 0  // offsetof(struct seccomp_data, nr)
	offsetArch  = 4  // offsetof(struct seccomp_data, arch)
	offsetArgs0 = 16 // offsetof(struct seccomp_data, args[0]) — low 32 bits on little-endian
)

// cloneNewMask combines all CLONE_NEW* flags that could be used to create
// new namespaces and potentially escape containment layers.
const cloneNewMask = 0x7E020000 // CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET

// afVSOCK is the AF_VSOCK socket family (40), used for VM host-guest
// communication. Blocked because it could bypass network namespace isolation.
const afVSOCK = 40

// ApplySeccomp installs a seccomp BPF filter that restricts the calling
// process to a safe set of syscalls. Dangerous syscalls (ptrace, mount,
// io_uring, kernel module loading, etc.) are blocked.
//
// MUST be called after PR_SET_NO_NEW_PRIVS. The filter is permanent and
// inherited by all children (fork + exec).
func ApplySeccomp() (LayerStatus, error) {
	status := LayerStatus{Name: LayerSeccomp}

	filter := buildSeccompFilter()

	prog := unix.SockFprog{
		Len:    uint16(len(filter)), //nolint:gosec // G115: filter length is always < 4096 instructions
		Filter: &filter[0],
	}

	// Install the BPF filter. Requires no_new_privs already set.
	// TSYNC synchronizes the filter across all threads in the thread group.
	// Without this, Go's runtime threads could remain unfiltered.
	_, _, errno := unix.RawSyscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog)), //nolint:gosec // G103: required by seccomp syscall ABI
	)
	if errno != 0 {
		status.Reason = fmt.Sprintf("seccomp install failed: %v", errno)
		return status, fmt.Errorf("installing seccomp filter: %w", errno)
	}

	status.Active = true
	status.Version = len(filter) // report filter size as "version" for diagnostics
	return status, nil
}

// SetNoNewPrivs sets the PR_SET_NO_NEW_PRIVS flag, which is required
// before installing a seccomp filter without CAP_SYS_ADMIN. This is
// permanent and prevents privilege escalation via suid/sgid binaries.
func SetNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// buildSeccompFilter constructs a BPF filter program that:
// 1. Validates architecture is x86_64 (KILL on mismatch — prevents 32-bit ABI bypass)
// 2. Kills the process on critical violations (kexec, kernel modules, io_uring)
// 3. Applies argument-level filtering for clone, personality, and socket
// 4. Allows a curated set of ~130 syscalls (Go + Python + Node.js compatible)
// 5. Returns EPERM for other blocked syscalls.
func buildSeccompFilter() []unix.SockFilter {
	allow := allowedSyscalls()
	kill := killSyscalls()

	killSet := make(map[uint32]bool, len(kill))
	for _, nr := range kill {
		killSet[nr] = true
	}

	// Syscalls handled by argument-level conditional blocks (not the flat allowlist).
	conditionalSet := map[uint32]bool{
		unix.SYS_CLONE:       true,
		unix.SYS_SOCKET:      true,
		unix.SYS_PERSONALITY: true,
	}

	var prog []unix.SockFilter

	// Step 1: Load and check architecture.
	prog = append(prog, bpfLoad(offsetArch))
	prog = append(prog, bpfJumpEq(unix.AUDIT_ARCH_X86_64, 1, 0))
	prog = append(prog, bpfRet(unix.SECCOMP_RET_KILL_PROCESS)) // wrong arch = kill

	// Step 2: Load syscall number.
	prog = append(prog, bpfLoad(offsetNR))

	// Step 3: Kill-on-match for critical syscalls.
	for _, nr := range kill {
		prog = append(prog, bpfJumpEq(nr, 0, 1))
		prog = append(prog, bpfRet(unix.SECCOMP_RET_KILL_PROCESS))
	}

	// Step 4: Conditional argument filtering.
	// Each block is self-contained: if the syscall matches, it inspects args
	// and returns ALLOW or EPERM. If the syscall doesn't match, it skips
	// the block and the accumulator (syscall number) is preserved.
	prog = append(prog, cloneConditional()...)
	prog = append(prog, socketConditional()...)
	prog = append(prog, personalityConditional()...)

	// Reload syscall number after conditional blocks (accumulator may have
	// been overwritten by arg loads in a conditional that matched).
	prog = append(prog, bpfLoad(offsetNR))

	// Step 5: Allow-on-match for safe syscalls (flat allowlist).
	for _, nr := range allow {
		if killSet[nr] || conditionalSet[nr] {
			continue // already handled above
		}
		prog = append(prog, bpfJumpEq(nr, 0, 1))
		prog = append(prog, bpfRet(unix.SECCOMP_RET_ALLOW))
	}

	// Step 6: Default deny — return EPERM.
	prog = append(prog, bpfRet(unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)))

	return prog
}

// cloneConditional generates BPF instructions that allow clone but block
// CLONE_NEW* flags which could create new namespaces.
//
// Note: clone3 takes a pointer to struct clone_args, which BPF cannot
// dereference. clone3 is handled via the flat allowlist (no arg filtering).
// This is mitigated by: (1) Landlock restrictions survive namespace creation,
// (2) mount is blocked by seccomp, (3) no_new_privs prevents suid escalation.
func cloneConditional() []unix.SockFilter {
	return []unix.SockFilter{
		bpfJumpEq(unix.SYS_CLONE, 0, 4),                     // if clone, check args; else skip 4
		bpfLoad(offsetArgs0),                                // load clone flags (low 32 bits)
		bpfJumpSet(cloneNewMask, 0, 1),                      // if CLONE_NEW* bits set: deny; else: allow
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)), // deny: namespace creation blocked
		bpfRet(unix.SECCOMP_RET_ALLOW),                      // allow: clone without new namespaces
	}
}

// socketConditional generates BPF instructions that allow socket but block
// AF_VSOCK (family 40) which could bypass network namespace isolation in
// VM environments.
func socketConditional() []unix.SockFilter {
	return []unix.SockFilter{
		bpfJumpEq(unix.SYS_SOCKET, 0, 4),                    // if socket, check args; else skip 4
		bpfLoad(offsetArgs0),                                // load domain/family (low 32 bits)
		bpfJumpEq(afVSOCK, 0, 1),                            // if AF_VSOCK: deny; else: allow
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)), // deny: VM socket blocked
		bpfRet(unix.SECCOMP_RET_ALLOW),                      // allow: other socket families
	}
}

// personalityConditional generates BPF instructions that restrict the
// personality syscall to known-safe values. Unexpected personality values
// could alter syscall behavior in ways that weaken containment.
func personalityConditional() []unix.SockFilter {
	const (
		personalityQuery      = 0xFFFFFFFF // query current personality
		addrNoRandomize       = 0x00000008 // ADDR_NO_RANDOMIZE
		perLinux32            = 0x00020000 // PER_LINUX32
		perLinux32NoRandomize = 0x00020008 // PER_LINUX32 | ADDR_NO_RANDOMIZE
	)
	return []unix.SockFilter{
		bpfJumpEq(unix.SYS_PERSONALITY, 0, 8),               // if personality, check args; else skip 8
		bpfLoad(offsetArgs0),                                // load personality value
		bpfJumpEq(0, 5, 0),                                  // 0 (PER_LINUX) → allow
		bpfJumpEq(addrNoRandomize, 4, 0),                    // ADDR_NO_RANDOMIZE → allow
		bpfJumpEq(perLinux32, 3, 0),                         // PER_LINUX32 → allow
		bpfJumpEq(perLinux32NoRandomize, 2, 0),              // PER_LINUX32 | ADDR_NO_RANDOMIZE → allow
		bpfJumpEq(personalityQuery, 1, 0),                   // 0xFFFFFFFF (query) → allow
		bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)), // deny: unexpected personality value
		bpfRet(unix.SECCOMP_RET_ALLOW),                      // allow: valid personality
	}
}

// BPF instruction helpers.

func bpfLoad(offset uint32) unix.SockFilter {
	return unix.SockFilter{
		Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS,
		K:    offset,
	}
}

func bpfJumpEq(val uint32, jTrue, jFalse uint8) unix.SockFilter {
	return unix.SockFilter{
		Code: unix.BPF_JMP | 0x10 | unix.BPF_K, // BPF_JEQ = 0x10
		K:    val,
		Jt:   jTrue,
		Jf:   jFalse,
	}
}

func bpfRet(val uint32) unix.SockFilter {
	return unix.SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    val,
	}
}

func bpfJumpSet(val uint32, jTrue, jFalse uint8) unix.SockFilter {
	return unix.SockFilter{
		Code: unix.BPF_JMP | 0x40 | unix.BPF_K, // BPF_JSET = 0x40
		K:    val,
		Jt:   jTrue,
		Jf:   jFalse,
	}
}

// allowedSyscalls returns the set of syscall numbers allowed by the sandbox.
// This covers Go runtime, Python, and Node.js requirements.
// Organized by category for auditability.
func allowedSyscalls() []uint32 {
	return []uint32{
		// Memory management
		unix.SYS_BRK, unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MREMAP,
		unix.SYS_MPROTECT, unix.SYS_MADVISE, unix.SYS_MINCORE,
		unix.SYS_MLOCK, unix.SYS_MLOCK2, unix.SYS_MUNLOCK,
		unix.SYS_MLOCKALL, unix.SYS_MUNLOCKALL, unix.SYS_MSYNC,
		unix.SYS_MEMFD_CREATE, unix.SYS_MEMBARRIER,
		unix.SYS_PKEY_ALLOC, unix.SYS_PKEY_FREE, unix.SYS_PKEY_MPROTECT,

		// File I/O
		unix.SYS_READ, unix.SYS_WRITE, unix.SYS_OPENAT, unix.SYS_CLOSE,
		unix.SYS_LSEEK, unix.SYS_PREAD64, unix.SYS_PWRITE64,
		unix.SYS_READV, unix.SYS_WRITEV, unix.SYS_PREADV, unix.SYS_PWRITEV,
		unix.SYS_PREADV2, unix.SYS_PWRITEV2,
		unix.SYS_FSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STATX,
		unix.SYS_FSTATFS, unix.SYS_STATFS,
		unix.SYS_READLINKAT, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2,
		unix.SYS_FTRUNCATE, unix.SYS_TRUNCATE, unix.SYS_FALLOCATE,
		unix.SYS_FADVISE64, unix.SYS_FCNTL, unix.SYS_FLOCK,
		unix.SYS_IOCTL, unix.SYS_DUP, unix.SYS_DUP2, unix.SYS_DUP3,
		unix.SYS_GETDENTS64, unix.SYS_COPY_FILE_RANGE,
		unix.SYS_SPLICE, unix.SYS_TEE, unix.SYS_SENDFILE,
		unix.SYS_READAHEAD,
		unix.SYS_FCHMOD, unix.SYS_FCHMODAT,
		unix.SYS_FCHOWN, unix.SYS_FCHOWNAT,
		unix.SYS_MKDIRAT, unix.SYS_UNLINKAT,
		unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2,
		unix.SYS_SYMLINKAT, unix.SYS_LINKAT,
		unix.SYS_UMASK, unix.SYS_GETCWD, unix.SYS_CHDIR, unix.SYS_FCHDIR,

		// Network (SYS_SOCKET handled by socketConditional — AF_VSOCK blocked)
		unix.SYS_SOCKETPAIR,
		unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4,
		unix.SYS_CONNECT,
		unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME,
		unix.SYS_GETSOCKOPT, unix.SYS_SETSOCKOPT,
		unix.SYS_SHUTDOWN,
		unix.SYS_SENDTO, unix.SYS_RECVFROM,
		unix.SYS_SENDMSG, unix.SYS_RECVMSG,
		unix.SYS_SENDMMSG, unix.SYS_RECVMMSG,

		// Epoll / event loop (Go netpoll + Node.js libuv)
		unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL,
		unix.SYS_EPOLL_WAIT, unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_PWAIT2,
		unix.SYS_EVENTFD, unix.SYS_EVENTFD2,
		unix.SYS_TIMERFD_CREATE, unix.SYS_TIMERFD_SETTIME, unix.SYS_TIMERFD_GETTIME,
		unix.SYS_SIGNALFD4,
		unix.SYS_INOTIFY_INIT1, unix.SYS_INOTIFY_ADD_WATCH, unix.SYS_INOTIFY_RM_WATCH,
		unix.SYS_POLL, unix.SYS_PPOLL, unix.SYS_PSELECT6, unix.SYS_SELECT,

		// Process management (SYS_CLONE handled by cloneConditional — CLONE_NEW* blocked).
		// KNOWN LIMITATION: clone3 takes a pointer to struct clone_args which BPF
		// cannot dereference. clone3 with CLONE_NEWUSER is not filtered by seccomp.
		// Mitigations: (1) Landlock restrictions survive namespace creation and are
		// inherited by all descendants, (2) mount is blocked by seccomp, (3)
		// no_new_privs prevents suid escalation in the new namespace.
		unix.SYS_CLONE3,
		unix.SYS_FORK, unix.SYS_VFORK,
		unix.SYS_EXECVE, unix.SYS_EXECVEAT,
		unix.SYS_WAIT4, unix.SYS_WAITID,
		unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
		unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_GETPID, unix.SYS_GETPPID, unix.SYS_GETTID,
		unix.SYS_GETPGRP, unix.SYS_GETPGID, unix.SYS_SETPGID,
		unix.SYS_SETSID,
		unix.SYS_PRCTL, unix.SYS_PRLIMIT64,
		unix.SYS_GETRLIMIT, unix.SYS_SETRLIMIT,
		unix.SYS_GETRUSAGE,
		unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY, unix.SYS_SCHED_SETAFFINITY,
		unix.SYS_SCHED_GETSCHEDULER, unix.SYS_SCHED_SETSCHEDULER,
		unix.SYS_SCHED_GETPARAM, unix.SYS_SCHED_SETPARAM,
		unix.SYS_SCHED_GET_PRIORITY_MAX, unix.SYS_SCHED_GET_PRIORITY_MIN,

		// Signals
		unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN,
		unix.SYS_RT_SIGPENDING, unix.SYS_RT_SIGSUSPEND,
		unix.SYS_RT_SIGTIMEDWAIT, unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO,
		unix.SYS_SIGALTSTACK,

		// Timers / clock (Go runtime)
		unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_GETRES, unix.SYS_CLOCK_NANOSLEEP,
		unix.SYS_NANOSLEEP, unix.SYS_SETITIMER, unix.SYS_GETITIMER,
		unix.SYS_TIMER_CREATE, unix.SYS_TIMER_SETTIME, unix.SYS_TIMER_GETTIME,
		unix.SYS_TIMER_GETOVERRUN, unix.SYS_TIMER_DELETE,
		unix.SYS_GETTIMEOFDAY, unix.SYS_TIMES, unix.SYS_ALARM,

		// Thread setup
		unix.SYS_ARCH_PRCTL, unix.SYS_SET_TID_ADDRESS,
		unix.SYS_SET_ROBUST_LIST, unix.SYS_GET_ROBUST_LIST,
		unix.SYS_FUTEX, unix.SYS_RSEQ,
		unix.SYS_PIPE, unix.SYS_PIPE2,

		// Identity / credentials
		unix.SYS_GETUID, unix.SYS_GETGID, unix.SYS_GETEUID, unix.SYS_GETEGID,
		unix.SYS_GETGROUPS, unix.SYS_GETRESUID, unix.SYS_GETRESGID,
		unix.SYS_SETUID, unix.SYS_SETGID, unix.SYS_SETREUID, unix.SYS_SETREGID,
		unix.SYS_SETRESUID, unix.SYS_SETRESGID, unix.SYS_SETFSUID, unix.SYS_SETFSGID,
		unix.SYS_SETGROUPS, unix.SYS_CAPGET, unix.SYS_CAPSET,

		// IPC (Python multiprocessing)
		unix.SYS_SHMGET, unix.SYS_SHMAT, unix.SYS_SHMDT, unix.SYS_SHMCTL,
		unix.SYS_SEMGET, unix.SYS_SEMOP, unix.SYS_SEMCTL, unix.SYS_SEMTIMEDOP,
		unix.SYS_MSGGET, unix.SYS_MSGSND, unix.SYS_MSGRCV, unix.SYS_MSGCTL,
		unix.SYS_MQ_OPEN, unix.SYS_MQ_UNLINK,
		unix.SYS_MQ_TIMEDSEND, unix.SYS_MQ_TIMEDRECEIVE,
		unix.SYS_MQ_NOTIFY, unix.SYS_MQ_GETSETATTR,

		// Misc / system info
		unix.SYS_GETRANDOM, unix.SYS_UNAME, unix.SYS_SYSINFO, unix.SYS_GETCPU,
		unix.SYS_SECCOMP, // allow nested seccomp (additional restrictions only)
	}
}

// killSyscalls returns syscall numbers that trigger KILL_PROCESS when
// invoked. These represent the most critical escape vectors.
func killSyscalls() []uint32 {
	return []uint32{
		// Kernel manipulation (container escape / privilege escalation)
		unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,

		// io_uring (bypasses seccomp entirely — 60% of Google's 2022 kernel bugs)
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,

		// Reboot
		unix.SYS_REBOOT,
	}
}

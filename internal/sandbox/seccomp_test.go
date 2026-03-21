// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const seccompTestEnv = "__SANDBOX_SECCOMP_TEST"

func init() {
	// If we're the seccomp test child, run the operation and exit.
	if op := os.Getenv(seccompTestEnv); op != "" {
		runSeccompTestChild(op)
		os.Exit(0) // should not reach here
	}
}

func runSeccompTestChild(op string) {
	// Apply no_new_privs + seccomp filter.
	if err := SetNoNewPrivs(); err != nil {
		_, _ = os.Stderr.WriteString("no_new_privs: " + err.Error() + "\n")
		os.Exit(2)
	}

	status, err := ApplySeccomp()
	if err != nil {
		_, _ = os.Stderr.WriteString("seccomp: " + err.Error() + "\n")
		os.Exit(2)
	}
	if !status.Active {
		_, _ = os.Stderr.WriteString("seccomp not active: " + status.Reason + "\n")
		os.Exit(2)
	}

	switch op {
	case "ptrace":
		// ptrace should return EPERM.
		err := syscall.PtraceAttach(os.Getppid())
		if errors.Is(err, syscall.EPERM) {
			os.Exit(0) // expected: blocked
		}
		_, _ = os.Stderr.WriteString("ptrace returned: " + err.Error() + "\n")
		os.Exit(1) // bad: should have been EPERM

	case "mount":
		// mount should return EPERM.
		err := syscall.Mount("none", "/tmp", "tmpfs", 0, "")
		if errors.Is(err, syscall.EPERM) {
			os.Exit(0) // expected: blocked
		}
		_, _ = os.Stderr.WriteString("mount returned: " + err.Error() + "\n")
		os.Exit(1)

	case "file-io":
		// Normal file I/O should work.
		f, err := os.CreateTemp("", "seccomp-test-*")
		if err != nil {
			_, _ = os.Stderr.WriteString("create temp: " + err.Error() + "\n")
			os.Exit(1)
		}
		if _, err := f.WriteString("hello"); err != nil {
			_, _ = os.Stderr.WriteString("write: " + err.Error() + "\n")
			os.Exit(1)
		}
		_ = f.Close()
		_ = os.Remove(f.Name())
		os.Exit(0) // expected: allowed

	case "goroutine":
		// Goroutines require clone3/futex — verify Go runtime still works.
		ch := make(chan int, 1)
		go func() { ch <- 42 }()
		if v := <-ch; v != 42 {
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "exec-child":
		// fork+exec should work (clone + execve are allowed).
		ctx := context.Background()
		cmd := exec.CommandContext(ctx, "echo", "child-ok")
		out, err := cmd.Output()
		if err != nil {
			_, _ = os.Stderr.WriteString("exec: " + err.Error() + "\n")
			os.Exit(1)
		}
		if strings.TrimSpace(string(out)) != "child-ok" {
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "network":
		// Socket creation should work (network calls are allowed;
		// network ISOLATION is handled by namespace, not seccomp).
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			_, _ = os.Stderr.WriteString("socket: " + err.Error() + "\n")
			os.Exit(1)
		}
		_ = syscall.Close(fd)
		os.Exit(0) // expected: allowed

	case "getrandom":
		// crypto/rand needs getrandom.
		buf := make([]byte, 32)
		_, err := unix.Getrandom(buf, 0)
		if err != nil {
			_, _ = os.Stderr.WriteString("getrandom: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0) // expected: allowed

	case "clone-newuser":
		// clone with CLONE_NEWUSER should be blocked by arg filtering.
		_, _, errno := unix.RawSyscall6(
			unix.SYS_CLONE,
			uintptr(syscall.CLONE_NEWUSER|syscall.SIGCHLD),
			0, 0, 0, 0, 0,
		)
		if errno == syscall.EPERM {
			os.Exit(0) // expected: blocked
		}
		// If clone succeeded, reap the child and report failure.
		_, _ = os.Stderr.WriteString("clone CLONE_NEWUSER returned: " + errno.Error() + "\n")
		os.Exit(1)

	case "clone-normal":
		// clone without CLONE_NEW* flags should work (basic fork).
		r, _, errno := unix.RawSyscall6(
			unix.SYS_CLONE,
			uintptr(syscall.SIGCHLD), // no CLONE_NEW* flags
			0, 0, 0, 0, 0,
		)
		if errno != 0 {
			_, _ = os.Stderr.WriteString("clone normal: " + errno.Error() + "\n")
			os.Exit(1)
		}
		if r == 0 {
			os.Exit(0) // child: exit immediately
		}
		// Parent: reap child.
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(int(r), &ws, 0, nil) //nolint:gosec // G115: clone returns pid
		os.Exit(0)                                // expected: allowed

	case "socket-vsock":
		// AF_VSOCK (family 40) should be blocked.
		fd, err := syscall.Socket(afVSOCK, syscall.SOCK_STREAM, 0)
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				os.Exit(0) // expected: blocked by seccomp
			}
			// EAFNOSUPPORT is also acceptable (kernel has no vsock module).
			if errors.Is(err, syscall.EAFNOSUPPORT) {
				os.Exit(0) // no vsock support, also acceptable
			}
			_, _ = os.Stderr.WriteString("socket AF_VSOCK: " + err.Error() + "\n")
			os.Exit(1)
		}
		_ = syscall.Close(fd)
		_, _ = os.Stderr.WriteString("socket AF_VSOCK succeeded unexpectedly\n")
		os.Exit(1)

	case "socket-inet":
		// AF_INET should be allowed (normal network socket).
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			_, _ = os.Stderr.WriteString("socket AF_INET: " + err.Error() + "\n")
			os.Exit(1)
		}
		_ = syscall.Close(fd)
		os.Exit(0) // expected: allowed

	default:
		_, _ = os.Stderr.WriteString("unknown operation: " + op + "\n")
		os.Exit(1)
	}
}

func runSeccompChild(t *testing.T, op string) (string, int) {
	t.Helper()
	if runtime.GOOS != osLinux {
		t.Skip("seccomp requires linux")
	}

	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^$")
	cmd.Env = append(os.Environ(), seccompTestEnv+"="+op)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}
	return string(out), exitCode
}

func TestSeccomp_BlocksPtrace(t *testing.T) {
	out, code := runSeccompChild(t, "ptrace")
	if code != 0 {
		t.Errorf("expected exit 0 (ptrace blocked with EPERM), got %d: %s", code, out)
	}
}

func TestSeccomp_BlocksMount(t *testing.T) {
	out, code := runSeccompChild(t, "mount")
	if code != 0 {
		t.Errorf("expected exit 0 (mount blocked with EPERM), got %d: %s", code, out)
	}
}

func TestSeccomp_AllowsFileIO(t *testing.T) {
	out, code := runSeccompChild(t, "file-io")
	if code != 0 {
		t.Errorf("expected exit 0 (file I/O allowed), got %d: %s", code, out)
	}
}

func TestSeccomp_AllowsGoroutines(t *testing.T) {
	out, code := runSeccompChild(t, "goroutine")
	if code != 0 {
		t.Errorf("expected exit 0 (goroutines work), got %d: %s", code, out)
	}
}

func TestSeccomp_AllowsExecChild(t *testing.T) {
	out, code := runSeccompChild(t, "exec-child")
	if code != 0 {
		t.Errorf("expected exit 0 (fork+exec allowed), got %d: %s", code, out)
	}
}

func TestSeccomp_AllowsNetwork(t *testing.T) {
	out, code := runSeccompChild(t, "network")
	if code != 0 {
		t.Errorf("expected exit 0 (socket creation allowed), got %d: %s", code, out)
	}
}

func TestSeccomp_AllowsGetrandom(t *testing.T) {
	out, code := runSeccompChild(t, "getrandom")
	if code != 0 {
		t.Errorf("expected exit 0 (getrandom allowed), got %d: %s", code, out)
	}
}

func TestSeccomp_BlocksCloneNewUser(t *testing.T) {
	out, code := runSeccompChild(t, "clone-newuser")
	if code != 0 {
		t.Errorf("expected exit 0 (clone CLONE_NEWUSER blocked), got %d: %s", code, out)
	}
}

func TestSeccomp_AllowsCloneNormal(t *testing.T) {
	out, code := runSeccompChild(t, "clone-normal")
	if code != 0 {
		t.Errorf("expected exit 0 (normal clone allowed), got %d: %s", code, out)
	}
}

func TestSeccomp_BlocksSocketVSOCK(t *testing.T) {
	out, code := runSeccompChild(t, "socket-vsock")
	if code != 0 {
		t.Errorf("expected exit 0 (AF_VSOCK blocked or unsupported), got %d: %s", code, out)
	}
}

func TestSeccomp_AllowsSocketINET(t *testing.T) {
	out, code := runSeccompChild(t, "socket-inet")
	if code != 0 {
		t.Errorf("expected exit 0 (AF_INET allowed), got %d: %s", code, out)
	}
}

func TestBuildSeccompFilter_NonEmpty(t *testing.T) {
	filter := buildSeccompFilter(false)
	// Minimum: arch check (3 insns) + default deny (1 insn) = 4
	if len(filter) < 4 {
		t.Errorf("filter too short: %d instructions", len(filter))
	}
}

func TestBuildSeccompFilter_StrictBlocksClone3(t *testing.T) {
	strict := buildSeccompFilter(true)
	// In strict mode, clone3 should return EPERM.
	// Scan filter for a JEQ matching SYS_CLONE3 followed by RET EPERM.
	foundClone3Deny := false
	for i := 0; i < len(strict)-1; i++ {
		insn := strict[i]
		next := strict[i+1]
		isJEQ := insn.Code == (unix.BPF_JMP|0x10|unix.BPF_K) && insn.K == unix.SYS_CLONE3
		isDeny := next.Code == (unix.BPF_RET|unix.BPF_K) && next.K == (unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM))
		if isJEQ && isDeny {
			foundClone3Deny = true
			break
		}
	}
	if !foundClone3Deny {
		t.Error("strict filter should deny clone3 with EPERM")
	}

	// Best-effort should allow clone3.
	bestEffort := buildSeccompFilter(false)
	foundClone3Allow := false
	for i := 0; i < len(bestEffort)-1; i++ {
		insn := bestEffort[i]
		next := bestEffort[i+1]
		isJEQ := insn.Code == (unix.BPF_JMP|0x10|unix.BPF_K) && insn.K == unix.SYS_CLONE3
		isAllow := next.Code == (unix.BPF_RET|unix.BPF_K) && next.K == unix.SECCOMP_RET_ALLOW
		if isJEQ && isAllow {
			foundClone3Allow = true
			break
		}
	}
	if !foundClone3Allow {
		t.Error("best-effort filter should allow clone3")
	}
}

func TestConditionalFilters_Structure(t *testing.T) {
	// Verify each conditional block is self-contained and has the right length.
	clone := cloneConditional()
	if len(clone) != 5 {
		t.Errorf("cloneConditional: expected 5 instructions, got %d", len(clone))
	}
	sock := socketConditional()
	if len(sock) != 5 {
		t.Errorf("socketConditional: expected 5 instructions, got %d", len(sock))
	}
	pers := personalityConditional()
	if len(pers) != 9 {
		t.Errorf("personalityConditional: expected 9 instructions, got %d", len(pers))
	}
}

func TestCloneNewMask_IncludesAllNamespaceFlags(t *testing.T) {
	// Verify the mask covers all CLONE_NEW* flags.
	flags := []struct {
		name string
		val  uint32
	}{
		{"CLONE_NEWNS", 0x00020000},
		{"CLONE_NEWCGROUP", 0x02000000},
		{"CLONE_NEWUTS", 0x04000000},
		{"CLONE_NEWIPC", 0x08000000},
		{"CLONE_NEWUSER", 0x10000000},
		{"CLONE_NEWPID", 0x20000000},
		{"CLONE_NEWNET", 0x40000000},
	}
	for _, f := range flags {
		if cloneNewMask&f.val == 0 {
			t.Errorf("cloneNewMask missing %s (0x%08x)", f.name, f.val)
		}
	}
}

func TestAllowedSyscalls_ContainsGoRuntime(t *testing.T) {
	allowed := allowedSyscalls()
	set := make(map[uint32]bool, len(allowed))
	for _, nr := range allowed {
		set[nr] = true
	}

	// Critical Go runtime syscalls that MUST be in the allowlist.
	// Note: clone3 is now in the conditional set (allowed in best-effort,
	// blocked in strict). It's not in the flat allowlist.
	critical := map[string]uint32{
		"futex":         unix.SYS_FUTEX,
		"mmap":          unix.SYS_MMAP,
		"epoll_create1": unix.SYS_EPOLL_CREATE1,
		"rt_sigaction":  unix.SYS_RT_SIGACTION,
		"clock_gettime": unix.SYS_CLOCK_GETTIME,
	}
	for name, nr := range critical {
		if !set[nr] {
			t.Errorf("missing critical Go runtime syscall: %s (%d)", name, nr)
		}
	}
}

func TestKillSyscalls_ContainsCritical(t *testing.T) {
	kill := killSyscalls()
	set := make(map[uint32]bool, len(kill))
	for _, nr := range kill {
		set[nr] = true
	}

	// These MUST be in the kill list.
	critical := map[string]uint32{
		"io_uring_setup": unix.SYS_IO_URING_SETUP,
		"kexec_load":     unix.SYS_KEXEC_LOAD,
		"init_module":    unix.SYS_INIT_MODULE,
		"reboot":         unix.SYS_REBOOT,
	}
	for name, nr := range critical {
		if !set[nr] {
			t.Errorf("missing critical kill syscall: %s (%d)", name, nr)
		}
	}
}

func TestSetNoNewPrivs_InProcess(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("linux only")
	}
	// Safe to call in-process — only prevents suid escalation.
	if err := SetNoNewPrivs(); err != nil {
		t.Fatalf("SetNoNewPrivs: %v", err)
	}
}

// unix_SYS_CLONE3 is SYS_CLONE3 — referenced via variable to avoid
// potential cross-compilation issues with the constant.
const unix_SYS_CLONE3 = 435

func TestApplyRlimits_InProcess(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("rlimits require linux")
	}
	// Only test RLIMIT_CORE in-process (setting NPROC would break
	// subsequent child-spawning tests). Full verification in child process.
	rlim := unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &rlim); err != nil {
		t.Fatalf("setrlimit CORE: %v", err)
	}
	var got unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &got); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if got.Cur != 0 {
		t.Errorf("RLIMIT_CORE = %d, want 0", got.Cur)
	}
}

func TestApplyRlimits_ChildVerifiesAll(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("rlimits require linux")
	}
	// Child process verifies all four limits.
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^$")
	cmd.Env = append(os.Environ(), "__SANDBOX_RLIMIT_TEST=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("rlimit test child failed: %v\n%s", err, out)
	}
}

func init() {
	if os.Getenv("__SANDBOX_RLIMIT_TEST") == "1" {
		if err := ApplyRlimits(); err != nil {
			_, _ = os.Stderr.WriteString("rlimits: " + err.Error() + "\n")
			os.Exit(1)
		}
		// Verify all four limits are applied.
		checks := []struct {
			resource int
			name     string
			want     uint64
		}{
			{syscall.RLIMIT_CORE, "RLIMIT_CORE", 0},
			{unix.RLIMIT_NPROC, "RLIMIT_NPROC", 1024},
			{syscall.RLIMIT_NOFILE, "RLIMIT_NOFILE", 4096},
			{unix.RLIMIT_FSIZE, "RLIMIT_FSIZE", 1 << 30},
		}
		for _, c := range checks {
			var rlim syscall.Rlimit
			if err := syscall.Getrlimit(c.resource, &rlim); err != nil {
				_, _ = os.Stderr.WriteString("getrlimit " + c.name + ": " + err.Error() + "\n")
				os.Exit(1)
			}
			if rlim.Cur != c.want {
				_, _ = os.Stderr.WriteString(c.name + " cur=" + strconv.FormatUint(rlim.Cur, 10) + " want=" + strconv.FormatUint(c.want, 10) + "\n")
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
}

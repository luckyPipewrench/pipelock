// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestTargetUnixSocketFilter(t *testing.T) {
	deny := uint32(unix.SECCOMP_RET_ERRNO | unix.EPERM)
	for _, tc := range []struct {
		name string
		nr   uint32
		arg  uint64
		want uint32
	}{
		{"pathname or abstract socket", unix.SYS_SOCKET, unix.AF_UNIX, deny},
		{"redirectable pair", unix.SYS_SOCKETPAIR, unix.AF_UNIX, deny},
		{"ancillary descriptors", unix.SYS_RECVMSG, 0, deny},
		{"batched ancillary descriptors", unix.SYS_RECVMMSG, 0, deny},
		{"x32 socket", 0x40000000 | unix.SYS_SOCKET, unix.AF_UNIX, deny},
		{"TCP bridge", unix.SYS_SOCKET, unix.AF_INET, unix.SECCOMP_RET_ALLOW},
		{"IPv6", unix.SYS_SOCKET, unix.AF_INET6, unix.SECCOMP_RET_ALLOW},
		{"pipe", unix.SYS_PIPE2, 0, unix.SECCOMP_RET_ALLOW},
		{"read", unix.SYS_READ, 0, unix.SECCOMP_RET_ALLOW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evaluateThreadFilter(t, targetUnixSocketFilter(), tc.nr, [6]uint64{tc.arg}); got != tc.want {
				t.Fatalf("action %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestTargetUnixSocketInstallationFailure(t *testing.T) {
	if !Detect().Seccomp {
		t.Skip("kernel lacks seccomp support")
	}
	const helperEnv = "__PIPELOCK_TEST_IPC_FILTER_FAILURE"
	if denied := os.Getenv(helperEnv); denied != "" {
		runtime.LockOSThread()
		if err := SetNoNewPrivs(); err != nil {
			t.Fatal(err)
		}
		number, err := strconv.ParseUint(denied, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		filter := []unix.SockFilter{
			bpfLoad(offsetNR), bpfJumpEq(uint32(number), 0, 1), // #nosec G115 -- ParseUint above is limited to 32 bits.
			bpfRet(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)), bpfRet(unix.SECCOMP_RET_ALLOW),
		}
		prog := unix.SockFprog{Len: 4, Filter: &filter[0]}
		// #nosec G103 -- fixed test filter copied synchronously by the kernel.
		_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
		if errno != 0 {
			t.Fatal(errno)
		}
		if err := restrictTargetUnixSockets(); !errors.Is(err, unix.EPERM) {
			t.Fatalf("filter installation did not fail closed: %v", err)
		}
		cmd := exec.CommandContext(t.Context(), "/usr/bin/true")
		if err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 8}); !errors.Is(err, unix.EPERM) || cmd.Process != nil {
			t.Fatalf("target started without IPC filter: %v", err)
		}
		return // this helper process exits with its restrictive test filter
	}
	for _, nr := range []int{unix.SYS_PRCTL, unix.SYS_SECCOMP} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTargetUnixSocketInstallationFailure$") // #nosec G204 G702 -- reexec this test binary with a fixed test selector, no external command input.
		for _, arg := range os.Args[1:] {
			if strings.HasPrefix(arg, "-test.gocoverdir=") {
				cmd.Args = append(cmd.Args, arg)
			}
		}
		cmd.Env = append(os.Environ(), helperEnv+"="+strconv.Itoa(nr), "PIPELOCK_MCP_ENVIRON_PROOF_HELPER=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("denied syscall %d: %v: %s", nr, err, out)
		}
	}
}

func TestTargetUnixSocketFallback(t *testing.T) {
	if !Detect().Seccomp {
		t.Skip("kernel lacks seccomp support")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for kernel seccomp integration")
	}
	probe := `import socket,errno
for make in (lambda: socket.socket(socket.AF_UNIX), lambda: socket.socketpair(type=socket.SOCK_DGRAM)):
 try:
  make()
 except OSError as e:
  assert e.errno == errno.EPERM, e
 else:
  raise AssertionError("Unix socket creation allowed")
socket.socket(socket.AF_INET).close()
print("isolated")
`
	for _, version := range []int{0, 5, 6, 8} {
		var out bytes.Buffer
		cmd := exec.CommandContext(t.Context(), python, "-c", probe) // #nosec G204 -- fixed Python executable and in-process isolation probe
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := startSandboxTarget(cmd, LayerStatus{Active: version > 0, Version: version}); err != nil {
			if errors.Is(err, unix.ENOSYS) {
				t.Skip("kernel has no seccomp syscall")
			}
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("ABI %d: %v: %s", version, err, out.String())
		}
		if out.String() != "isolated\n" {
			t.Fatalf("unexpected probe output: %s", out.String())
		}
		// Installing on the spawning thread must not restrict the bridge's
		// Go runtime or any future goroutine using its worker pool.
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatalf("bridge lost Unix access: %v", err)
		}
		_ = unix.Close(fd)
	}
	modern := exec.CommandContext(t.Context(), "/usr/bin/true")
	if err := startSandboxTarget(modern, LayerStatus{Active: true, Version: 9}); err != nil {
		t.Fatal(err)
	}
	if err := modern.Wait(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "/nonexistent/pipelock-test-command")
	if err := startSandboxTarget(cmd, LayerStatus{Active: true, Version: 8}); err == nil {
		t.Fatal("missing executable accepted")
	}
}

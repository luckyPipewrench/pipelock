// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package mcp

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestCleanupCapability_KernelDenial runs in a separate process because its
// seccomp policy and the production capability cache last for that process's
// lifetime. It tests a real host-policy denial without replacing the probe.
func TestCleanupCapability_KernelDenial(t *testing.T) {
	const helperEnv = "PIPELOCK_TEST_CLEANUP_KERNEL_DENIAL"
	if os.Getenv(helperEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCleanupCapability_KernelDenial$")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("kernel-denial helper: %v (context: %v)\n%s", err, ctx.Err(), out)
		}
		return
	}

	// Linux seccomp_data has the syscall number at byte 0 and args[0] at
	// byte 16. On amd64 the low word is first. Deny only the subreaper
	// setting; other prctl operations and the child's I/O remain available.
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_PRCTL, Jf: 3},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.PR_SET_CHILD_SUBREAPER, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	// no_new_privs initially applies to the calling thread. Keep the same
	// thread until the synchronized filter has propagated the restriction.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatalf("set no_new_privs: %v", err)
	}
	prog := unix.SockFprog{Len: 6, Filter: &filter[0]}
	thread, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog))) //nolint:gosec // G103: seccomp syscall ABI requires the filter pointer.
	if errno != 0 || thread != 0 {
		t.Fatalf("install synchronized seccomp policy: errno=%v thread=%d", errno, thread)
	}
	if _, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil {
		t.Fatalf("control prctl unexpectedly denied: %v", err)
	}
	if err := enableSubreaper(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("policy did not deny the real subreaper probe: %v", err)
	}

	var log strings.Builder
	capability := ReportCleanupCapability(&log, false)
	if capability.State != CleanupDenied || !errors.Is(capability.Err, unix.EPERM) {
		t.Fatalf("startup capability = %+v, want denied EPERM", capability)
	}
	if !strings.Contains(log.String(), "cleanup degraded") || strings.Contains(log.String(), "Run with strict mode") {
		t.Fatalf("plain stdio startup report = %q", log.String())
	}
	opts := testOpts(testScannerWithAction(t, config.ActionWarn))
	opts.StartupCleanupReported = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cat")
	if err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, &log, opts, true); !errors.Is(err, unix.EPERM) {
		t.Fatalf("strict launch = %v, want kernel refusal", err)
	}
	if cmd.Process != nil {
		t.Fatal("strict launch started the child despite the denied capability")
	}
	if err := RunProxy(ctx, strings.NewReader(""), io.Discard, &log, []string{"cat"}, opts); err != nil {
		t.Fatalf("plain stdio must preserve best-effort launch: %v", err)
	}
	if strings.Count(log.String(), "cleanup degraded") != 1 {
		t.Fatalf("startup report was repeated during launch: %q", log.String())
	}
}

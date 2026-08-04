// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/luckyPipewrench/pipelock/internal/mcp/integrity"
	"golang.org/x/sys/unix"
)

const fdExecHelperArg = "__pipelock_internal_fd_exec"

var descriptorHelperPath = "/proc/self/exe"

func init() {
	if len(os.Args) < 3 || os.Args[1] != fdExecHelperArg {
		return
	}
	unix.CloseOnExec(3)
	if err := execveat(3, os.Args[2:], os.Environ()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pipelock: descriptor exec failed: %v\n", err)
		os.Exit(127)
	}
}

func descriptorCommand(ctx context.Context, command []string, prepared *integrity.PreparedCommand) (*exec.Cmd, error) {
	if _, err := os.Stat(descriptorHelperPath); err != nil {
		return nil, fmt.Errorf("descriptor exec requires %s: %w", descriptorHelperPath, err)
	}
	args := append([]string(nil), command...)
	extraFiles := []*os.File{prepared.Executable}
	helperArgs := append([]string{fdExecHelperArg}, args...)
	cmd := exec.CommandContext(ctx, descriptorHelperPath, helperArgs...) //nolint:gosec // production path is fixed /proc/self/exe; tests override it to prove fail-closed handling
	cmd.ExtraFiles = extraFiles
	return cmd, nil
}

func execveat(fd int, argv, envv []string) error { //nolint:gosec // audited raw syscall wrapper; Go validates NULs before unsafe pointer conversion
	if len(argv) == 0 {
		return fmt.Errorf("empty argv")
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return fmt.Errorf("building argv: %w", err)
	}
	envp, err := syscall.SlicePtrFromStrings(envv)
	if err != nil {
		return fmt.Errorf("building environment: %w", err)
	}
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return fmt.Errorf("building empty path: %w", err)
	}
	_, _, errno := syscall.Syscall6( //nolint:gosec // audited execveat needs raw argv/env pointers; inputs came from Go's NUL-validating constructors
		unix.SYS_EXECVEAT,
		uintptr(fd),
		uintptr(unsafe.Pointer(empty)),     //nolint:gosec // syscall requires a validated C string pointer
		uintptr(unsafe.Pointer(&argvp[0])), //nolint:gosec // syscall requires validated argv pointers
		uintptr(unsafe.Pointer(&envp[0])),  //nolint:gosec // syscall requires validated environment pointers
		unix.AT_EMPTY_PATH,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("execveat: %w", errno)
	}
	return nil
}

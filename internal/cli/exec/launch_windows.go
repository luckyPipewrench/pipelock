// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// consoleHandler stays referenced so the callback isn't collected while the
// child is running. Ctrl+C and Ctrl+Break belong to the child; closing the
// console still uses the default handler, which exits this process and lets
// the job's kill-on-close limit stop descendants.
var (
	consoleHandlerOnce    sync.Once
	consoleHandler        uintptr
	setConsoleCtrlHandler = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
)

func keepConsoleInterruptsOnChild() {
	consoleHandlerOnce.Do(func() {
		consoleHandler = syscall.NewCallback(consoleInterruptHandled)
		// A process with no console returns failure here. Ignore it: there is
		// no console interrupt to steal, and the job still owns the child.
		_, _, _ = setConsoleCtrlHandler.Call(consoleHandler, 1)
	})
}

func consoleInterruptHandled(ctrl uint32) uintptr {
	if ctrl == windows.CTRL_C_EVENT || ctrl == windows.CTRL_BREAK_EVENT {
		return 1
	}
	return 0
}

func launch(cmd *cobra.Command, args, environment []string) error {
	keepConsoleInterruptsOnChild()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create command job: %w", err)
	}
	defer func() { _ = windows.CloseHandle(job) }()
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("configure command job: %w", err)
	}
	child := exec.CommandContext(cmd.Context(), args[0], args[1:]...)
	child.Env = environment
	// Assign the job before executing any child code or allowing descendants.
	child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(child.Process.Pid)) // #nosec G115 -- Windows process IDs are uint32
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		_ = windows.CloseHandle(process)
	}
	if err == nil {
		err = resumeChild(uint32(child.Process.Pid)) // #nosec G115 -- Windows process IDs are uint32
	}
	if err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		return fmt.Errorf("assign command to kill-on-close job: %w", err)
	}
	err = child.Wait()
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return cliutil.ExitCodeError(exited.ExitCode(), err)
	}
	return err
}

func resumeChild(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return err
		}
		_, err = windows.ResumeThread(thread)
		_ = windows.CloseHandle(thread)
		return err
	}
	return fmt.Errorf("find suspended command thread: %w", err)
}

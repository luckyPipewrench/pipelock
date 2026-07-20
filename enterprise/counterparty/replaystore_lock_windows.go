//go:build enterprise && windows

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	lockfileExclusiveLock   = 0x00000002
	lockfileFailImmediately = 0x00000001
	fileShareDelete         = 0x00000004
	windowsLockViolation    = syscall.Errno(33)
)

var (
	kernel32Proc     = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32Proc.NewProc("LockFileEx")
	procUnlockFileEx = kernel32Proc.NewProc("UnlockFileEx")
)

// acquireReplayStoreLock takes an exclusive, cross-process byte-range lock on the
// OPEN store handle so two processes sharing one store cannot both accept the
// same entry. Locking the handle (not a path-derived sibling) ties the lock to
// the same file the store reads and writes. Lock acquisition is bounded so
// verification fails closed instead of hanging indefinitely behind a wedged peer.
func acquireReplayStoreLock(f *os.File) (func(), error) {
	handle := syscall.Handle(f.Fd())
	overlapped := &syscall.Overlapped{}
	deadline := time.Now().Add(replayStoreLockTimeout)
	for {
		err := lockFileEx(handle, lockfileExclusiveLock|lockfileFailImmediately, 0xffffffff, 0xffffffff, overlapped)
		if err == nil {
			return func() { _ = unlockFileEx(handle, 0xffffffff, 0xffffffff, overlapped) }, nil
		}
		if !errors.Is(err, windowsLockViolation) {
			return nil, fmt.Errorf("acquire replay store lock: %w", err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("acquire replay store lock: timed out after %s: %w", replayStoreLockTimeout, err)
		}
		time.Sleep(replayStoreLockRetryInterval)
	}
}

// verifyStorePathInode fails closed if the configured path no longer resolves to
// the open file's identity (volume serial + file index), the Windows equivalent
// of the Unix dev+inode check. Any inability to obtain the identity is treated
// as a mismatch and fails closed rather than silently accepting a split store.
func verifyStorePathInode(f *os.File, path string) error {
	openID, err := windowsFileIdentity(syscall.Handle(f.Fd()))
	if err != nil {
		return fmt.Errorf("replay store handle identity: %w", err)
	}
	pathp, err := syscall.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("encode replay store path: %w", err)
	}
	h, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|fileShareDelete,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("open replay store path for identity check: %w", err)
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	pathID, err := windowsFileIdentity(h)
	if err != nil {
		return fmt.Errorf("replay store path identity: %w", err)
	}
	if openID != pathID {
		return errors.New("replay store path no longer resolves to the open store file")
	}
	return nil
}

type windowsFileID struct {
	volumeSerial uint32
	indexHigh    uint32
	indexLow     uint32
}

func windowsFileIdentity(h syscall.Handle) (windowsFileID, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return windowsFileID{}, err
	}
	return windowsFileID{
		volumeSerial: info.VolumeSerialNumber,
		indexHigh:    info.FileIndexHigh,
		indexLow:     info.FileIndexLow,
	}, nil
}

func lockFileEx(handle syscall.Handle, flags, lowBytes, highBytes uint32, overlapped *syscall.Overlapped) error {
	r1, _, err := procLockFileEx.Call(
		uintptr(handle),
		uintptr(flags),
		0,
		uintptr(lowBytes),
		uintptr(highBytes),
		uintptr(unsafe.Pointer(overlapped)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func unlockFileEx(handle syscall.Handle, lowBytes, highBytes uint32, overlapped *syscall.Overlapped) error {
	r1, _, err := procUnlockFileEx.Call(
		uintptr(handle),
		0,
		uintptr(lowBytes),
		uintptr(highBytes),
		uintptr(unsafe.Pointer(overlapped)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

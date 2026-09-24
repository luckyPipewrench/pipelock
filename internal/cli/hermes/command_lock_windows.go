//go:build windows

package hermes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hermesWindowsIdentity() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func secureWindowsLockObject(handle windows.Handle, path string, sid *windows.SID) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("hermes command lock: inspect %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(sid) {
		return fmt.Errorf("hermes command lock: unsafe owner of %s", path)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return fmt.Errorf("hermes command lock: unsafe permissions on %s", path)
	}
	sddl := sd.String()
	if acl.AceCount != 1 || !strings.Contains(sddl, "D:P") || !strings.Contains(sddl, "(A;") || !strings.Contains(sddl, ";;;"+sid.String()+")") || strings.Count(sddl, "(") != 1 {
		return fmt.Errorf("hermes command lock: unsafe permissions on %s", path)
	}

	return nil
}

func ensureHermesLockDir(path string) error {
	sid, err := hermesWindowsIdentity()
	if err != nil {
		return fmt.Errorf("hermes command lock: identify user: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "G:" + sid.String() + "D:P(A;OICI;FA;;;" + sid.String() + ")")
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for _, dir := range []string{filepath.Dir(path), path} {
		name, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(name, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("hermes command lock: create %s: %w", dir, err)
		}
		handle, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return fmt.Errorf("hermes command lock: open directory %s: %w", dir, err)
		}
		info, statErr := os.Lstat(dir)
		safeErr := secureWindowsLockObject(handle, dir, sid)
		_ = windows.CloseHandle(handle)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || safeErr != nil {
			return fmt.Errorf("hermes command lock: unsafe lock directory %s", dir)
		}
	}
	return nil
}

func acquireHermesLock(path string, deadline time.Time) (func(), error) {
	sid, err := hermesWindowsIdentity()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "G:" + sid.String() + "D:P(A;OICI;FA;;;" + sid.String() + ")")
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("hermes command lock: open %s: %w", path, err)
	}
	closeFile := func() { _ = windows.CloseHandle(handle) }
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		closeFile()
		return nil, fmt.Errorf("hermes command lock: unsafe lock file %s", path)
	}
	if err := secureWindowsLockObject(handle, path, sid); err != nil {
		closeFile()
		return nil, err
	}
	for {
		overlap := new(windows.Overlapped)
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlap)
		if err == nil {
			return func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, overlap); closeFile() }, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			closeFile()
			return nil, fmt.Errorf("hermes command lock: lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			closeFile()
			return nil, hermesLockBusy(path)
		}
		time.Sleep(min(10*time.Millisecond, time.Until(deadline)))
	}
}

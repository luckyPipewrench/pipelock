// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package playground

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

type userNamespaceMountProbeOps struct {
	lockOSThread   func()
	unlockOSThread func()
	unshare        func(flags int) error
	writeFile      func(name string, data []byte, perm fs.FileMode) error
	getuid         func() int
	getgid         func() int
	setresgid      func(rgid, egid, sgid int) error
	setresuid      func(ruid, euid, suid int) error
	mkdirTemp      func(dir, pattern string) (string, error)
	removeAll      func(path string) error
	mount          func(source string, target string, fstype string, flags uintptr, data string) error
	unmount        func(target string, flags int) error
}

func realUserNamespaceMountProbeOps() userNamespaceMountProbeOps {
	return userNamespaceMountProbeOps{
		lockOSThread:   runtime.LockOSThread,
		unlockOSThread: runtime.UnlockOSThread,
		unshare:        unix.Unshare,
		writeFile:      os.WriteFile,
		getuid:         os.Getuid,
		getgid:         os.Getgid,
		setresgid:      unix.Setresgid,
		setresuid:      unix.Setresuid,
		mkdirTemp:      os.MkdirTemp,
		removeAll:      os.RemoveAll,
		mount:          unix.Mount,
		unmount:        unix.Unmount,
	}
}

func probeLocalCapability(target, capability string) ProbeResult {
	switch capability {
	case "mknod":
		return probeMknodCapability(target)
	case "mount":
		return probeMountCapability(target)
	case "userns-mount":
		return probeUserNamespaceMountCapability(target)
	default:
		return ProbeResult{
			Target:  target,
			Open:    false,
			Blocked: false,
			Detail:  "unknown local capability target",
		}
	}
}

func probeMknodCapability(target string) ProbeResult {
	const nullDevice = (1 << 8) | 3 // Linux char device major 1, minor 3.

	dir, err := os.MkdirTemp("", "pipelock-local-escape-mknod-*")
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: false, Detail: fmt.Sprintf("probe setup failed: %v", err)}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	nodePath := filepath.Join(dir, "probe-null")
	err = unix.Mknod(nodePath, unix.S_IFCHR|0o600, nullDevice)
	if err != nil {
		return localCapabilityError(target, "mknod", err)
	}
	return ProbeResult{Target: target, Open: true, Blocked: false, Detail: "mknod succeeded"}
}

func probeMountCapability(target string) ProbeResult {
	dir, err := os.MkdirTemp("", "pipelock-local-escape-mount-*")
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: false, Detail: fmt.Sprintf("probe setup failed: %v", err)}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	err = unix.Mount("none", dir, "tmpfs", 0, "")
	if err != nil {
		return localCapabilityError(target, "mount", err)
	}
	_ = unix.Unmount(dir, 0)
	return ProbeResult{Target: target, Open: true, Blocked: false, Detail: "mount succeeded"}
}

func probeUserNamespaceMountCapability(target string) ProbeResult {
	return probeUserNamespaceMountCapabilityWithOps(target, realUserNamespaceMountProbeOps())
}

func probeUserNamespaceMountCapabilityWithOps(target string, ops userNamespaceMountProbeOps) ProbeResult {
	ops.lockOSThread()
	if err := ops.unshare(unix.CLONE_NEWUSER | unix.CLONE_NEWNS); err != nil {
		ops.unlockOSThread()
		return localCapabilityError(target, "unshare", err)
	}
	// Do not unlock this OS thread after a successful unshare. The uid/gid map and
	// Setresuid/Setresgid calls below permanently mutate this thread's namespace
	// and credentials. LocalEscapeTargets keeps this probe last, so the toy-agent
	// process records the result and exits instead of returning the mutated thread
	// to the Go scheduler.

	if err := ops.writeFile("/proc/self/setgroups", []byte("deny\n"), 0o600); err != nil && !os.IsNotExist(err) {
		return ProbeResult{Target: target, Open: true, Blocked: false, Detail: fmt.Sprintf("user namespace created; setgroups map failed afterward: %v", err)}
	}
	if err := ops.writeFile("/proc/self/uid_map", []byte("0 "+strconv.Itoa(ops.getuid())+" 1\n"), 0o600); err != nil {
		return ProbeResult{Target: target, Open: true, Blocked: false, Detail: fmt.Sprintf("user namespace created; uid map failed afterward: %v", err)}
	}
	if err := ops.writeFile("/proc/self/gid_map", []byte("0 "+strconv.Itoa(ops.getgid())+" 1\n"), 0o600); err != nil {
		return ProbeResult{Target: target, Open: true, Blocked: false, Detail: fmt.Sprintf("user namespace created; gid map failed afterward: %v", err)}
	}
	if err := ops.setresgid(0, 0, 0); err != nil {
		return ProbeResult{Target: target, Open: true, Blocked: false, Detail: fmt.Sprintf("user namespace created; setresgid failed afterward: %v", err)}
	}
	if err := ops.setresuid(0, 0, 0); err != nil {
		return ProbeResult{Target: target, Open: true, Blocked: false, Detail: fmt.Sprintf("user namespace created; setresuid failed afterward: %v", err)}
	}

	dir, err := ops.mkdirTemp("", "pipelock-local-escape-userns-mount-*")
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: false, Detail: fmt.Sprintf("probe setup failed: %v", err)}
	}
	defer func() { _ = ops.removeAll(dir) }()

	if err := ops.mount("none", dir, "tmpfs", 0, ""); err != nil {
		return localCapabilityError(target, "mount after userns", err)
	}
	_ = ops.unmount(dir, 0)
	return ProbeResult{Target: target, Open: true, Blocked: false, Detail: "user namespace root mounted tmpfs"}
}

func localCapabilityError(target, operation string, err error) ProbeResult {
	blocked := errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
	absent := errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EOPNOTSUPP) ||
		(operation == "unshare" && errors.Is(err, unix.EINVAL))
	detail := "failed"
	if blocked {
		detail = "denied"
	} else if absent {
		detail = "unsupported"
	}
	return ProbeResult{Target: target, Blocked: blocked, Absent: absent, Detail: fmt.Sprintf("%s: %s: %v", detail, operation, err)}
}

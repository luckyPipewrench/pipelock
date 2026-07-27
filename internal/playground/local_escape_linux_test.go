// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package playground

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProbeLocalCapability_Unknown(t *testing.T) {
	t.Parallel()

	result := probeLocalCapability("cap:unknown", "unknown")
	if result.Open || result.Blocked {
		t.Fatalf("unknown local capability must be Open=false Blocked=false, got: %+v", result)
	}
	if result.Detail != "unknown local capability target" {
		t.Fatalf("detail = %q", result.Detail)
	}
}

func TestProbeMknodCapability_ClassifiesResult(t *testing.T) {
	t.Parallel()

	result := probeLocalCapability("cap:mknod", "mknod")
	if result.Target != "cap:mknod" {
		t.Fatalf("target = %q", result.Target)
	}
	if result.Open == result.Blocked {
		t.Fatalf("mknod probe must classify as exactly one of open/blocked, got: %+v", result)
	}
	if result.Detail == "" {
		t.Fatal("mknod probe detail is empty")
	}
}

func TestProbeMountCapability_ClassifiesResult(t *testing.T) {
	t.Parallel()

	result := probeLocalCapability("cap:mount", "mount")
	if result.Target != "cap:mount" {
		t.Fatalf("target = %q", result.Target)
	}
	if result.Open == result.Blocked {
		t.Fatalf("mount probe must classify as exactly one of open/blocked, got: %+v", result)
	}
	if result.Detail == "" {
		t.Fatal("mount probe detail is empty")
	}
}

func TestProbeUserNamespaceMountCapabilityWithOps(t *testing.T) {
	newOps := func() (*userNamespaceMountProbeOps, *bool, *bool) {
		locked := false
		unlocked := false
		ops := &userNamespaceMountProbeOps{
			lockOSThread: func() { locked = true },
			unlockOSThread: func() {
				unlocked = true
			},
			unshare:   func(int) error { return nil },
			writeFile: func(string, []byte, fs.FileMode) error { return nil },
			getuid:    func() int { return 10001 },
			getgid:    func() int { return 10001 },
			setresgid: func(int, int, int) error { return nil },
			setresuid: func(int, int, int) error { return nil },
			mkdirTemp: func(string, string) (string, error) { return "/tmp/probe-userns", nil },
			removeAll: func(string) error { return nil },
			mount:     func(string, string, string, uintptr, string) error { return nil },
			unmount:   func(string, int) error { return nil },
		}
		return ops, &locked, &unlocked
	}

	t.Run("unshare failure unlocks thread and blocks", func(t *testing.T) {
		ops, locked, unlocked := newOps()
		ops.unshare = func(int) error { return unix.EPERM }

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if !*locked || !*unlocked {
			t.Fatalf("lock=%v unlock=%v, want both true on unshare failure", *locked, *unlocked)
		}
		if result.Open || !result.Blocked || !strings.Contains(result.Detail, "unshare") {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("unsupported user namespaces are absent", func(t *testing.T) {
		ops, _, unlocked := newOps()
		ops.unshare = func(int) error { return unix.EINVAL }

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if !*unlocked || result.Open || result.Blocked || !result.Absent || !strings.Contains(result.Detail, "unsupported") {
			t.Fatalf("unexpected result: %+v unlocked=%v", result, *unlocked)
		}
	})

	t.Run("setgroups missing continues to success", func(t *testing.T) {
		ops, locked, unlocked := newOps()
		ops.writeFile = func(name string, _ []byte, _ fs.FileMode) error {
			if name == "/proc/self/setgroups" {
				return os.ErrNotExist
			}
			return nil
		}

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if !*locked || *unlocked {
			t.Fatalf("lock=%v unlock=%v, want locked and not unlocked after successful unshare", *locked, *unlocked)
		}
		if !result.Open || result.Blocked {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("uid map failure after unshare stays open", func(t *testing.T) {
		ops, _, _ := newOps()
		ops.writeFile = func(name string, _ []byte, _ fs.FileMode) error {
			if name == "/proc/self/uid_map" {
				return errors.New("uid denied")
			}
			return nil
		}

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if !result.Open || result.Blocked || !strings.Contains(result.Detail, "uid map") {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("gid map failure after unshare stays open", func(t *testing.T) {
		ops, _, _ := newOps()
		ops.writeFile = func(name string, _ []byte, _ fs.FileMode) error {
			if name == "/proc/self/gid_map" {
				return errors.New("gid denied")
			}
			return nil
		}

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if !result.Open || result.Blocked || !strings.Contains(result.Detail, "gid map") {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("setresgid failure after unshare stays open", func(t *testing.T) {
		ops, _, _ := newOps()
		ops.setresgid = func(int, int, int) error { return errors.New("setresgid denied") }

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if !result.Open || result.Blocked || !strings.Contains(result.Detail, "setresgid") {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("setresuid failure after unshare stays open", func(t *testing.T) {
		ops, _, _ := newOps()
		ops.setresuid = func(int, int, int) error { return errors.New("setresuid denied") }

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if !result.Open || result.Blocked || !strings.Contains(result.Detail, "setresuid") {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("mount failure blocks", func(t *testing.T) {
		ops, _, _ := newOps()
		ops.mount = func(string, string, string, uintptr, string) error { return unix.EPERM }

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if result.Open || !result.Blocked || !strings.Contains(result.Detail, "mount after userns") {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("mkdir failure is ambiguous setup failure", func(t *testing.T) {
		ops, _, _ := newOps()
		ops.mkdirTemp = func(string, string) (string, error) { return "", errors.New("tmp denied") }

		result := probeUserNamespaceMountCapabilityWithOps("cap:userns-mount", *ops)
		if result.Open || result.Blocked || !strings.Contains(result.Detail, "probe setup failed") {
			t.Fatalf("unexpected result: %+v", result)
		}
	})
}

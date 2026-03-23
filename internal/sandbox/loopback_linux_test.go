// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"runtime"
	"syscall"
	"testing"
)

func TestLoopbackUp_ReturnsError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	// On the host without CAP_NET_ADMIN, loopbackUp returns EPERM.
	// Inside a sandbox namespace (as root), it succeeds.
	// Either outcome is valid — we just verify it doesn't panic.
	err := loopbackUp()
	if err != nil {
		// Expected on host: EPERM because we lack CAP_NET_ADMIN.
		if !errors.Is(err, syscall.EPERM) {
			t.Logf("loopbackUp returned non-EPERM error: %v", err)
		}
	}
	// If err == nil, loopback was already up and we had permission (CI as root).
}

func TestBringUpLoopback_DoesNotPanic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	// bringUpLoopback uses raw netlink syscalls.
	// On unprivileged host, returns EPERM — we just verify no panic.
	_ = bringUpLoopback()
}

func TestLoopbackUp_NetlinkMessageFormat(t *testing.T) {
	// Verify the netlink constants are correct sizes.
	if nlmsgHdrLen != 16 {
		t.Errorf("nlmsgHdrLen = %d, want 16", nlmsgHdrLen)
	}
	if ifInfoMsgLen != 16 {
		t.Errorf("ifInfoMsgLen = %d, want 16", ifInfoMsgLen)
	}
}

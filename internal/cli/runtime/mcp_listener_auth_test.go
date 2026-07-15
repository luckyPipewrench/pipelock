// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadMCPListenerTokenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics")
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("listener-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	token, err := readMCPListenerTokenFile(path)
	if err != nil {
		t.Fatalf("readMCPListenerTokenFile: %v", err)
	}
	if token != "listener-secret" {
		t.Fatalf("token = %q", token)
	}

	worldReadableMode := os.FileMode(0o600 | 0o044)
	if err := os.Chmod(path, worldReadableMode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := readMCPListenerTokenFile(path); err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("permissive token error = %v", err)
	}
}

func TestReadMCPListenerTokenFileRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{name: "empty", data: "\n"},
		{name: "embedded space", data: "bad token"},
		{name: "control", data: "bad\x00token"},
		{name: "oversize", data: strings.Repeat("a", mcpListenerTokenMaxBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := readMCPListenerTokenFile(path); err == nil {
				t.Fatal("expected malformed token error")
			}
		})
	}
}

func TestValidateMCPListenerBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addr  string
		token string
		allow bool
		ok    bool
	}{
		{name: "IPv4 loopback", addr: "127.0.0.1:8889", ok: true},
		{name: "IPv6 loopback", addr: "[::1]:8889", ok: true},
		{name: "wildcard denied", addr: "0.0.0.0:8889"},
		{name: "empty host denied", addr: ":8889"},
		{name: "hostname denied", addr: "localhost:8889"},
		{name: "remote with token", addr: "0.0.0.0:8889", token: "secret", ok: true},
		{name: "remote explicit network boundary", addr: "0.0.0.0:8889", allow: true, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMCPListenerBoundary(tc.addr, tc.token, tc.allow)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected fail-closed boundary error")
			}
		})
	}
}

func TestValidateMCPListenerOrigins(t *testing.T) {
	if err := validateMCPListenerOrigins([]string{"https://console.vendor.example", "http://127.0.0.1:3000"}); err != nil {
		t.Fatalf("valid origins: %v", err)
	}
	for _, origin := range []string{"null", "https://console.vendor.example/path", "https://user@console.vendor.example", "javascript:alert(1)"} {
		if err := validateMCPListenerOrigins([]string{origin}); err == nil {
			t.Fatalf("origin %q accepted", origin)
		}
	}
}

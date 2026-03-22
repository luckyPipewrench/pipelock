// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import (
	"strings"
	"testing"
)

func TestGenerateSBPL_DenyAllBaseline(t *testing.T) {
	p := Policy{Workspace: "/tmp/test-workspace"}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, "(version 1)") {
		t.Error("expected SBPL version header")
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("expected deny-all baseline")
	}
}

func TestGenerateSBPL_AllowReadDirs(t *testing.T) {
	p := Policy{
		Workspace:     "/tmp/test",
		AllowReadDirs: []string{"/usr/", "/lib/"},
	}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, `(allow file-read* (subpath "/usr/"))`) {
		t.Error("expected read allow for /usr/")
	}
	if !strings.Contains(profile, `(allow file-read* (subpath "/lib/"))`) {
		t.Error("expected read allow for /lib/")
	}
}

func TestGenerateSBPL_AllowRWDirs(t *testing.T) {
	p := Policy{
		Workspace:   "/tmp/test",
		AllowRWDirs: []string{"/tmp/test"},
	}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, `(allow file-read* (subpath "/private/tmp/test"))`) {
		t.Error("expected read allow for workspace (macOS path)")
	}
	if !strings.Contains(profile, `(allow file-write* (subpath "/private/tmp/test"))`) {
		t.Error("expected write allow for workspace (macOS path)")
	}
}

func TestGenerateSBPL_DenySecretDirs(t *testing.T) {
	p := Policy{
		Workspace:    "/tmp/test",
		DenyReadDirs: []string{"/home/user/.ssh", "/home/user/.aws"},
	}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, `(deny file-read* (subpath "/home/user/.ssh"))`) {
		t.Error("expected deny for .ssh")
	}
	if !strings.Contains(profile, `(deny file-read* (subpath "/home/user/.aws"))`) {
		t.Error("expected deny for .aws")
	}
}

func TestGenerateSBPL_NetworkLocalhostOnly(t *testing.T) {
	p := Policy{Workspace: "/tmp/test"}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, `(allow network* (remote ip "localhost:*"))`) {
		t.Error("expected localhost network allow")
	}
	if !strings.Contains(profile, `(allow network* (remote ip "127.0.0.1:*"))`) {
		t.Error("expected 127.0.0.1 network allow")
	}
}

func TestGenerateSBPL_ProcessOps(t *testing.T) {
	p := Policy{Workspace: "/tmp/test"}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, "(allow process-exec*)") {
		t.Error("expected process-exec allow")
	}
	if !strings.Contains(profile, "(allow process-fork)") {
		t.Error("expected process-fork allow")
	}
}

func TestGenerateSBPL_AllowReadFiles(t *testing.T) {
	p := Policy{
		Workspace:      "/tmp/test",
		AllowReadFiles: []string{"/etc/resolv.conf", "/etc/hosts"},
	}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, `(allow file-read* (literal "/private/etc/resolv.conf"))`) {
		t.Error("expected literal read for resolv.conf (macOS path)")
	}
}

func TestGenerateSBPL_AllowRWFiles(t *testing.T) {
	p := Policy{
		Workspace:    "/tmp/test",
		AllowRWFiles: []string{"/dev/null"},
	}
	profile := GenerateSBPL(p)

	if !strings.Contains(profile, `(allow file-read* (literal "/dev/null"))`) {
		t.Error("expected read for /dev/null")
	}
	if !strings.Contains(profile, `(allow file-write* (literal "/dev/null"))`) {
		t.Error("expected write for /dev/null")
	}
}

func TestResolveMacOSPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/etc/ssl/certs", "/private/etc/ssl/certs"},
		{"/etc/resolv.conf", "/private/etc/resolv.conf"},
		{"/tmp/workspace", "/private/tmp/workspace"},
		{"/tmp", "/private/tmp"},
		{"/var/log", "/private/var/log"},
		{"/usr/local/bin", "/usr/local/bin"},       // no change
		{"/home/user/.ssh", "/home/user/.ssh"},     // no change
		{"/opt/homebrew/bin", "/opt/homebrew/bin"}, // no change
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := resolveMacOSPath(tc.input)
			if got != tc.expected {
				t.Errorf("resolveMacOSPath(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestDefaultPolicyDarwin(t *testing.T) {
	t.Setenv("HOME", "/Users/testuser")
	p := DefaultPolicyDarwin("/Users/testuser/project")

	if p.Workspace != "/Users/testuser/project" {
		t.Errorf("workspace = %q, want /Users/testuser/project", p.Workspace)
	}

	// Should have macOS-specific read dirs.
	foundSystem := false
	foundLibrary := false
	for _, d := range p.AllowReadDirs {
		if d == "/System/" {
			foundSystem = true
		}
		if d == "/Library/" {
			foundLibrary = true
		}
	}
	if !foundSystem {
		t.Error("expected /System/ in AllowReadDirs")
	}
	if !foundLibrary {
		t.Error("expected /Library/ in AllowReadDirs")
	}

	// Should deny macOS secret dirs.
	foundSSH := false
	foundKeychains := false
	for _, d := range p.DenyReadDirs {
		if d == "/Users/testuser/.ssh" {
			foundSSH = true
		}
		if d == "/Users/testuser/Library/Keychains" {
			foundKeychains = true
		}
	}
	if !foundSSH {
		t.Error("expected .ssh in DenyReadDirs")
	}
	if !foundKeychains {
		t.Error("expected Library/Keychains in DenyReadDirs")
	}
}

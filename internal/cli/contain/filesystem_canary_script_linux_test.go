// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFilesystemCanaryScriptGuards(t *testing.T) {
	base := t.TempDir()
	operator := filepath.Join(base, "operator")
	if err := os.WriteFile(operator, []byte("op\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(operator, &st); err != nil {
		t.Fatal(err)
	}
	inode := strconv.FormatUint(st.Ino, 10)
	workspace := filepath.Join(base, "workspace")
	if err := os.WriteFile(workspace, []byte("ws\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(base, "secret")
	if err := os.WriteFile(secret, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly := filepath.Join(base, "readonly")
	if err := os.Mkdir(readOnly, 0o750); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(base, "writable")
	if err := os.Mkdir(writable, 0o750); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(base, "denied")
	if err := os.Mkdir(denied, 0o500); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(base, "missing")
	available, reason := probeFilesystemReadOnlyMount(t)
	runFilesystemCanaryScriptCases(t, filesystemCanaryScriptCases(operator, missing, inode, readOnly, writable, denied, workspace, secret), available, reason)
}

func TestReadOnlyCanaryCasesSkipWhenBindMountProbeFails(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "unshare")
	body := "#!/bin/sh\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$arg\" = \"/bin/true\" ]; then\n" +
		"    exit 0\n" +
		"  fi\n" +
		"done\n" +
		"printf '%s\\n' \"$*\" | grep -q 'mount --bind' || {\n" +
		"  echo 'unexpected unshare invocation' >&2\n" +
		"  exit 97\n" +
		"}\n" +
		"echo 'bind mount denied' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := exec.CommandContext(t.Context(), "unshare", "--user", "--map-root-user", "--mount", "/bin/true").Run(); err != nil {
		t.Fatalf("/bin/true unshare: %v", err)
	}
	available, reason := probeFilesystemReadOnlyMount(t)
	if available || !strings.Contains(reason, "bind mount denied") {
		t.Fatalf("available=%v reason=%q", available, reason)
	}
	base := t.TempDir()
	operator := filepath.Join(base, "operator")
	if err := os.WriteFile(operator, []byte("op\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(operator, &st); err != nil {
		t.Fatal(err)
	}
	readOnly := filepath.Join(base, "readonly")
	writable := filepath.Join(base, "writable")
	denied := filepath.Join(base, "denied")
	workspace := filepath.Join(base, "workspace")
	secret := filepath.Join(base, "secret")
	for _, dir := range []string{readOnly, writable, denied} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(denied, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspace, []byte("ws\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "missing")
	ran, skipped := runFilesystemCanaryScriptCases(t, filesystemCanaryScriptCases(operator, missing, strconv.FormatUint(st.Ino, 10), readOnly, writable, denied, workspace, secret), available, reason)
	if ran != 3 || skipped != 3 {
		t.Fatalf("ran=%d skipped=%d", ran, skipped)
	}
}

type filesystemCanaryScriptCase struct {
	name     string
	readOnly bool
	op       string
	inode    string
	write    string
	ws       string
	secret   string
	want     int
}

func filesystemCanaryScriptCases(operator, missing, inode, readOnly, writable, denied, workspace, secret string) []filesystemCanaryScriptCase {
	return []filesystemCanaryScriptCase{
		{name: "positive", readOnly: true, op: missing, inode: inode, write: readOnly, ws: workspace, secret: missing, want: 0},
		{name: "operator", op: operator, inode: inode, write: writable, ws: workspace, secret: missing, want: 11},
		{name: "write succeeds", op: missing, inode: inode, write: writable, ws: workspace, secret: missing, want: 12},
		{name: "write denied", op: missing, inode: inode, write: denied, ws: workspace, secret: missing, want: 12},
		{name: "workspace", readOnly: true, op: missing, inode: inode, write: readOnly, ws: missing, secret: missing, want: 13},
		{name: "secret", readOnly: true, op: missing, inode: inode, write: readOnly, ws: workspace, secret: secret, want: 14},
	}
}

// probeFilesystemReadOnlyMount performs the bind and remount the read-only
// cases need, then checks that a write fails. Failure skips those cases.
func probeFilesystemReadOnlyMount(t *testing.T) (bool, string) {
	t.Helper()
	d := t.TempDir()
	script := `mount --bind "$1" "$1" && mount -o remount,bind,ro "$1" && ! touch "$1/x"`
	cmd := exec.CommandContext(t.Context(), "unshare", "--user", "--map-root-user", "--mount", "/bin/bash", "-c", script, "bash", d)
	out, err := cmd.CombinedOutput()
	if err != nil {
		reason := strings.TrimSpace(string(out))
		if reason == "" {
			reason = err.Error()
		}
		return false, reason
	}
	return true, ""
}

func runFilesystemCanaryScriptCases(t *testing.T, cases []filesystemCanaryScriptCase, available bool, reason string) (ran, skipped int) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.readOnly && !available {
				skipped++
				t.Skip(reason)
			}
			ran++
			got := filesystemCanaryScriptExit(t, tc.readOnly, tc.op, tc.inode, tc.write, tc.ws, tc.secret)
			if got != tc.want {
				t.Fatalf("exit = %d, want %d", got, tc.want)
			}
		})
	}
	return ran, skipped
}

func filesystemCanaryScriptExit(t *testing.T, readOnlyWrite bool, op, inode, write, workspace, secret string) int {
	t.Helper()
	var cmd *exec.Cmd
	if readOnlyWrite {
		script := "mount --bind \"$3\" \"$3\" && mount -o remount,bind,ro \"$3\" || exit 99\n" + filesystemCanaryScript
		cmd = exec.CommandContext(t.Context(), "unshare", "--user", "--map-root-user", "--mount", "/bin/bash", "-c", script, "bash", op, inode, write, workspace, secret)
	} else {
		cmd = exec.CommandContext(t.Context(), "/bin/bash", "-c", filesystemCanaryScript, "bash", op, inode, write, workspace, secret)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 99 {
			t.Fatalf("read-only mount setup failed: %s", out)
		}
		return exitErr.ExitCode()
	}
	t.Fatalf("canary script: %v: %s", err, out)
	return -1
}

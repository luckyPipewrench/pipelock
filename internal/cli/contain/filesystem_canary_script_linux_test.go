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
	cases := []struct {
		name     string
		readOnly bool
		op       string
		inode    string
		write    string
		ws       string
		secret   string
		want     int
	}{
		{name: "positive", readOnly: true, op: missing, inode: inode, write: readOnly, ws: workspace, secret: missing, want: 0},
		{name: "operator", op: operator, inode: inode, write: writable, ws: workspace, secret: missing, want: 11},
		{name: "write succeeds", op: missing, inode: inode, write: writable, ws: workspace, secret: missing, want: 12},
		{name: "write denied", op: missing, inode: inode, write: denied, ws: workspace, secret: missing, want: 12},
		{name: "workspace", readOnly: true, op: missing, inode: inode, write: readOnly, ws: missing, secret: missing, want: 13},
		{name: "secret", readOnly: true, op: missing, inode: inode, write: readOnly, ws: workspace, secret: secret, want: 14},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filesystemCanaryScriptExit(t, tc.readOnly, tc.op, tc.inode, tc.write, tc.ws, tc.secret)
			if got != tc.want {
				t.Fatalf("exit = %d, want %d", got, tc.want)
			}
		})
	}
}

func filesystemCanaryScriptExit(t *testing.T, readOnlyWrite bool, op, inode, write, workspace, secret string) int {
	t.Helper()
	var cmd *exec.Cmd
	if readOnlyWrite {
		script := "mount --bind \"$3\" \"$3\" && mount -o remount,bind,ro \"$3\" || exit 99\n" + filesystemCanaryScript
		cmd = exec.Command("unshare", "--user", "--map-root-user", "--mount", "/bin/bash", "-c", script, "bash", op, inode, write, workspace, secret)
	} else {
		cmd = exec.Command("/bin/bash", "-c", filesystemCanaryScript, "bash", op, inode, write, workspace, secret)
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

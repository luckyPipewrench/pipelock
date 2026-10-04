// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// legacyFileOpsProbe exercises file operations through Python's os module,
// whose glibc wrappers issue the legacy path-based syscalls on x86_64
// (access, mkdir, rename, chmod, link, symlink, unlink, rmdir). Each line of
// output is "ok <op>" or "FAIL <op> <errno>". The final operation creates a
// directory outside every granted path and reports its errno, so the test can
// tell a Landlock refusal (EACCES, 13) from a seccomp refusal (EPERM, 1).
const legacyFileOpsProbe = `
import os, sys
ws, outside = sys.argv[1], sys.argv[2]
os.chdir(ws)
def t(name, fn):
    try:
        if fn() is False:
            print("FAIL", name, "false")
        else:
            print("ok", name)
    except OSError as e:
        print("FAIL", name, e.errno)
with open("a", "w") as f:
    f.write("x")
t("access", lambda: os.access("a", os.R_OK))
t("mkdir", lambda: os.mkdir("d"))
t("rename", lambda: os.rename("a", "b"))
t("chmod", lambda: os.chmod("b", 0o600))
t("link", lambda: os.link("b", "c"))
t("symlink", lambda: os.symlink("b", "s"))
t("unlink", lambda: [os.unlink(x) for x in ("b", "c", "s")])
t("rmdir", lambda: os.rmdir("d"))
try:
    os.mkdir(os.path.join(outside, "escape"))
    print("outside created")
except OSError as e:
    print("outside", e.errno)
`

func TestIntegration_SandboxCLI_LegacyFileSyscalls(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	binary := buildTestBinary(t)
	workspace := t.TempDir()
	outside := t.TempDir()
	script := filepath.Join(workspace, "probe.py")
	if err := os.WriteFile(script, []byte(legacyFileOpsProbe), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runSandboxBinary(t, binary,
		"sandbox", "--workspace", workspace, "--", python, script, workspace, outside)
	if err != nil {
		t.Fatalf("sandboxed probe failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Positive control: the probe ran and reported every operation.
	for _, op := range []string{"access", "mkdir", "rename", "chmod", "link", "symlink", "unlink", "rmdir"} {
		if !strings.Contains(stdout, "ok "+op+"\n") {
			t.Errorf("workspace %s did not succeed inside the sandbox\nstdout: %s", op, stdout)
		}
	}

	// The legacy syscall is now permitted by seccomp, so a path outside the
	// workspace must be refused by Landlock (EACCES), not reach the disk.
	if strings.Contains(stdout, "outside created") {
		t.Fatalf("legacy mkdir escaped the Landlock policy\nstdout: %s", stdout)
	}
	if !strings.Contains(stdout, "outside 13\n") {
		t.Errorf("outside mkdir should fail with EACCES from Landlock\nstdout: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); err == nil {
		t.Fatal("legacy mkdir created a directory outside the sandbox")
	}
}

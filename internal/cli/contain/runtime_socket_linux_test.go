// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This creates an unprivileged, throwaway user unit. It never uses the managed
// identities, anchor, proxy, or installed launch scripts.
func TestRuntimeSocketMountIsolation(t *testing.T) {
	runner, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("systemd-run unavailable")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for runtime socket probe")
	}
	ctx, runtimeDir, env := runtimeMountSystemdFixture(t)
	base := []string{"--user", "--wait", "--pipe", "--collect", "--property=PrivateUsers=true", "--property=PrivateNetwork=true"}
	run := func(args []string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, runner, args...) // #nosec G204 -- fixed systemd-run executable resolved by LookPath; fixture properties and command only
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	var sockets []string
	for _, parent := range []string{runtimeDir, "/dev/shm"} {
		dir, err := os.MkdirTemp(parent, "pipelock-runtime-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		path := filepath.Join(dir, "host.sock")
		ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err != nil {
			t.Fatalf("positive control: %v", err)
		}
		_ = conn.Close()
		sockets = append(sockets, path)
	}
	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, []byte("fixture-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{}, base...)
	for _, property := range runtimeSocketProperties() {
		if strings.HasPrefix(property, "BindReadOnlyPaths=") {
			property = "BindReadOnlyPaths=" + identity + ":" + containedNamespaceIdentityPath
		}
		args = append(args, "--property="+property)
	}
	// Reopen only the second endpoint's inode as a synthetic proxy doorway.
	const doorway = "/run/pipelock-test-doorway.sock"
	args = append(args, "--property=BindReadOnlyPaths="+sockets[1]+":"+doorway)
	probe := fmt.Sprintf(`import socket,errno
for path in %q, %q:
 s=socket.socket(socket.AF_UNIX)
 try:
  s.connect(path)
 except OSError as e:
  assert e.errno in (errno.ENOENT,errno.EACCES), e
 else:
  raise AssertionError("host runtime socket visible")
 s.close()
assert open(%q).read() == "fixture-identity"
s=socket.socket(socket.AF_UNIX); s.connect(%q); s.close()
print("runtime-isolated-doorway-reachable")
`, sockets[0], sockets[1], containedNamespaceIdentityPath, doorway)
	args = append(args, "--", python, "-c", probe)
	out, err := run(args)
	if err != nil || !strings.Contains(string(out), "runtime-isolated-doorway-reachable") {
		t.Fatalf("runtime mount isolation: %v: %s", err, out)
	}
}

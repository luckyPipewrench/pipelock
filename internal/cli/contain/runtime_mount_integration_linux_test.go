// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func runtimeMountSystemdFixture(t *testing.T) (context.Context, string, []string) {
	t.Helper()
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run unavailable for private runtime mount integration")
	}
	runtimeDir := filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
	if _, err := os.Stat(filepath.Join(runtimeDir, "bus")); err != nil {
		t.Skipf("user systemd bus unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(45*time.Second))
	t.Cleanup(cancel)
	env := append(os.Environ(), "XDG_RUNTIME_DIR="+runtimeDir, "DBUS_SESSION_BUS_ADDRESS=unix:path="+runtimeDir+"/bus")
	// This independent prerequisite must create a mount namespace too. Some
	// runners permit user/network namespaces but their LSM denies tmpfs mounts.
	// Do not use the product's runtime properties here: broken properties must
	// still fail the actual isolation tests after this minimal mount succeeds.
	cmd := exec.CommandContext(ctx, "systemd-run", "--user", "--wait", "--pipe", "--collect", "--quiet", "--property=PrivateUsers=true", "--property=PrivateNetwork=true", "--property=TemporaryFileSystem=/dev/shm", "/usr/bin/true")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("user systemd cannot create private user/network/mount namespaces: %v: %s", err, out)
	}
	return ctx, runtimeDir, env
}

func TestManagedRuntimeMountIntegration(t *testing.T) {
	const helper = "PIPELOCK_TEST_RUNTIME_MOUNTS"
	if os.Getenv(helper) == "1" {
		if err := assertManagedRuntimeMounts(defaultNetnsAssertEnv()); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, runtimeDir, env := runtimeMountSystemdFixture(t)
	dir, err := os.MkdirTemp(runtimeDir, "pipelock-mount-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	identity := filepath.Join(dir, "identity")
	if err := os.WriteFile(identity, []byte("net:[200]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--user", "--wait", "--pipe", "--collect", "--quiet", "--property=PrivateUsers=true", "--property=PrivateNetwork=true", "--setenv=" + helper + "=1"}
	for _, property := range runtimeSocketProperties() {
		if strings.HasPrefix(property, "BindReadOnlyPaths=") {
			property = "BindReadOnlyPaths=" + identity + ":" + containedNamespaceIdentityPath
		}
		args = append(args, "--property="+property)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "--", binary, "-test.run=^TestManagedRuntimeMountIntegration$", "-test.v")
	cmd := exec.CommandContext(ctx, "systemd-run", args...) // #nosec G204 -- reexec test binary with exact selector and test-owned mounts.
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual managed runtime properties did not satisfy live mount guard: %v: %s", err, out)
	} else {
		t.Logf("live mount guard: %s", out)
	}
}

func TestDoorwayDirectoryObservesSocketReplacement(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for live socket replacement proof")
	}
	ctx, runtimeDir, env := runtimeMountSystemdFixture(t)
	paths := []string{containedDoorwaySocketPath, declaredLoopbackDoorwayPath("127.0.0.1", 3000), declaredLoopbackDoorwayPath("::1", 3000)}
	for i, path := range paths {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			forwarder := renderContainedNamespaceForwarderUnit("/usr/bin/pipelock", "agent", 8888)
			if i > 0 {
				host := "127.0.0.1"
				if i == 2 {
					host = "::1"
				}
				forwarder = renderDeclaredLoopbackNamespaceForwarderUnit("/usr/bin/pipelock", "agent", config.ContainmentLoopbackService{Host: host, Port: 3000})
			}
			property := "BindReadOnlyPaths=" + filepath.Dir(path)
			if filepath.Dir(path) == "/run" || !strings.Contains(forwarder, "\n"+property+"\n") {
				t.Fatal("forwarder must bind its dedicated directory")
			}
			dir, err := os.MkdirTemp(runtimeDir, "pipelock-doorway-recovery-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			source := filepath.Join(dir, filepath.Base(path))
			listen := func() net.Listener {
				ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", source)
				if err != nil {
					t.Fatal(err)
				}
				return ln
			}
			first := listen()
			t.Cleanup(func() { _ = first.Close() })
			unit := fmt.Sprintf("pipelock-doorway-proof-%d-%d.service", os.Getpid(), time.Now().UnixNano())
			t.Cleanup(func() {
				stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), testwait.Deadline(5*time.Second))
				defer cancel()
				cmd := exec.CommandContext(stop, "systemctl", "--user", "stop", unit) // #nosec G204 -- exclusively test-owned transient unit.
				cmd.Env = env
				_ = cmd.Run()
			})
			args := []string{"--user", "--wait", "--pipe", "--collect", "--quiet", "--unit=" + unit, "--property=PrivateUsers=true", "--property=PrivateNetwork=true"}
			for _, mount := range runtimeSocketMountProperties() {
				args = append(args, "--property="+mount)
			}
			args = append(args, "--property=BindReadOnlyPaths="+dir+":"+filepath.Dir(path))
			probe := `import socket,sys
for step in range(2):
 s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.close()
 print("connected",flush=True)
 if step==0: assert sys.stdin.readline()=="replaced\n"
`
			args = append(args, "--", python, "-c", probe, path)
			cmd := exec.CommandContext(ctx, "systemd-run", args...) // #nosec G204 -- fixed producer properties and harmless synthetic socket probe.
			cmd.Env = env
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
			scan := bufio.NewScanner(output)
			if !scan.Scan() || scan.Text() != "connected" {
				t.Fatal("initial doorway connection failed")
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			second := listen()
			defer func() { _ = second.Close() }()
			if _, err := fmt.Fprintln(input, "replaced"); err != nil {
				t.Fatal(err)
			}
			if !scan.Scan() || scan.Text() != "connected" {
				t.Fatal("same running forwarder could not reach replacement doorway")
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("socket replacement command: %v: %s", err, stderr.String())
			}
			t.Log("same mount namespace connected before and after socket inode replacement")
		})
	}
}

func TestDoorwaySocketProducerKeepsDirectory(t *testing.T) {
	ctx, runtimeDir, env := runtimeMountSystemdFixture(t)
	bodies := []string{renderContainedProxySocketUnit("agent")}
	for _, host := range []string{"127.0.0.1", "::1"} {
		bodies = append(bodies, renderDeclaredLoopbackSocketUnit("agent", config.ContainmentLoopbackService{Host: host, Port: 3000}))
	}
	for i, body := range bodies {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			dir, err := os.MkdirTemp(runtimeDir, "pipelock-socket-producer-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			parent := filepath.Join(dir, "doorway")
			path := filepath.Join(parent, "doorway.sock")
			unit := fmt.Sprintf("pipelock-socket-producer-%d-%d", os.Getpid(), time.Now().UnixNano())
			control := func(args ...string) ([]byte, error) {
				cmd := exec.CommandContext(ctx, "systemctl", append([]string{"--user"}, args...)...) // #nosec G204 -- exclusively test-owned units.
				cmd.Env = env
				return cmd.CombinedOutput()
			}
			t.Cleanup(func() { _, _ = control("stop", unit+".socket", unit+".service") })
			args := []string{"--user", "--quiet", "--unit=" + unit, "--socket-property=ListenStream=" + path}
			// Ownership is delegated to the current user manager for this
			// unprivileged proof; lifecycle properties come from the producer.
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "SocketMode=") || strings.HasPrefix(line, "RemoveOnStop=") || strings.HasPrefix(line, "DirectoryMode=") {
					args = append(args, "--socket-property="+line)
				}
			}
			args = append(args, "--", "/usr/bin/true")
			cmd := exec.CommandContext(ctx, "systemd-run", args...) // #nosec G204 -- actual socket producer properties, synthetic path and harmless inactive service.
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("create doorway socket producer: %v: %s", err, out)
			}
			before, err := os.Stat(parent)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := control("stop", unit+".socket"); err != nil {
				t.Fatalf("stop socket producer: %v: %s", err, out)
			}
			after, err := os.Stat(parent)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("socket removal replaced the bound parent directory: %v", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("RemoveOnStop did not remove the socket: %v", err)
			}
			t.Log("actual socket producer removed its socket while preserving the bound directory inode")
		})
	}
}

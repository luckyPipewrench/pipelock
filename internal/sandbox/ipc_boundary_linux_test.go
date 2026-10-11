// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestSandboxRejectsHostUnixSocket(t *testing.T) {
	caps := Detect()
	if caps.LandlockABI == 0 {
		t.Skip("kernel lacks Landlock")
	}
	if !caps.UserNamespaces {
		t.Skip("kernel does not permit user/network namespaces")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the Unix socket integration probe")
	}
	root := shortTempDir(t)
	socket := filepath.Join(root, "host.sock")
	var lc net.ListenConfig
	listener, err := lc.Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// Calibrate the fixture outside the sandbox before checking its denial.
	probe := `import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); print("connected")`
	out, err := exec.CommandContext(t.Context(), python, "-c", probe, socket).CombinedOutput() // #nosec G204 -- fixed Python executable and synthetic socket probe
	if err != nil || strings.TrimSpace(string(out)) != "connected" {
		t.Fatalf("host positive control: %v: %s", err, out)
	}
	if !seccompFilterSupportedByBuild() && caps.LandlockABI < 9 {
		t.Skip("pathname Unix socket mediation needs Landlock ABI 9 on this architecture")
	}
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "strict"}[strict], func(t *testing.T) {
			if strict && !seccompFilterSupportedByBuild() {
				t.Skip("strict sandbox requires the linux/amd64 seccomp implementation")
			}
			if strict {
				requireStrictSandboxPrimitives(t)
			}
			var output bytes.Buffer
			cmd, err := LaunchSandboxed(LaunchConfig{
				Ctx: t.Context(), Workspace: root, Strict: strict,
				Command: []string{python, "-c", probe, socket}, Stdout: &output, Stderr: &output,
			})
			if err != nil {
				t.Fatalf("launch: %v", err)
			}
			defer CleanupSandboxCmd(cmd)
			err = cmd.Wait()
			if strings.Contains(output.String(), "\nconnected\n") {
				t.Fatalf("sandbox reached a host Unix socket in its allowed workspace:\n%s", output.String())
			}
			if err == nil || !strings.Contains(output.String(), "PermissionError") {
				t.Fatalf("expected a socket permission denial, got %v:\n%s", err, output.String())
			}
		})
	}
}

func TestSandboxProxyDoorwayIsolation(t *testing.T) {
	caps := Detect()
	if caps.LandlockABI == 0 {
		t.Skip("kernel lacks Landlock")
	}
	if !caps.UserNamespaces {
		t.Skip("kernel does not permit user/network namespaces")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for proxy doorway integration")
	}
	// A host can permit user namespaces while its LSM denies network setup
	// within them. Skip only that explicit prerequisite failure; failures in
	// rules, bridge startup, or target execution remain test failures.
	var diagnostic bytes.Buffer
	probe, err := LaunchSandboxed(LaunchConfig{
		Ctx: t.Context(), Workspace: t.TempDir(), Command: []string{"/bin/true"},
		BridgeSocketPath: initBridgeSocketFixture(t), Stderr: &diagnostic,
	})
	if err != nil {
		t.Fatalf("bridge prerequisite launch: %v", err)
	}
	err = probe.Wait()
	CleanupSandboxCmd(probe)
	if err != nil {
		if strings.Contains(diagnostic.String(), "[sandbox] loopback:") && strings.Contains(diagnostic.String(), "operation not permitted") {
			t.Skipf("kernel/LSM denies loopback setup in a user namespace: %s", diagnostic.String())
		}
		t.Fatalf("bridge prerequisite: %v: %s", err, diagnostic.String())
	}
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "strict"}[strict], func(t *testing.T) {
			if strict && !seccompFilterSupportedByBuild() {
				t.Skip("strict sandbox requires linux/amd64 seccomp")
			}
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(15*time.Second))
			defer cancel()
			var calls atomic.Int32
			var mismatches atomic.Int32
			err := LaunchStandalone(StandaloneLaunchConfig{
				Ctx: ctx, Workspace: t.TempDir(), Strict: strict,
				Command:      []string{python, "-c", `import urllib.request; assert urllib.request.urlopen("http://api.vendor.example/check",timeout=5).read() == b"doorway"`},
				ProxyHandler: func(conn net.Conn) { serveIPCProxyProbe(conn, &calls, &mismatches) },
			})
			if err != nil {
				t.Fatalf("proxy doorway launch: %v; proxy mismatches: %d", err, mismatches.Load())
			}
			if calls.Load() != 1 {
				t.Fatalf("proxy handled %d requests, want 1", calls.Load())
			}
			if mismatches.Load() != 0 {
				t.Fatalf("proxy received %d malformed or nonmatching requests", mismatches.Load())
			}
		})
	}
}

func serveIPCProxyProbe(conn net.Conn, calls, mismatches *atomic.Int32) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(testwait.Deadline(5 * time.Second)))
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		mismatches.Add(1)
		return
	}
	defer func() { _ = request.Body.Close() }()
	if request.Host == "api.vendor.example" && request.URL.Path == "/check" {
		calls.Add(1)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndoorway")
		return
	}
	mismatches.Add(1)
}

func TestIPCProxyProbeAcceptsFragmentedHeaders(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	if err := client.SetDeadline(time.Now().Add(testwait.Deadline(5 * time.Second))); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var mismatches atomic.Int32
	go serveIPCProxyProbe(server, &calls, &mismatches)
	for _, fragment := range []string{"GET http://api.vendor.", "example/check HTTP/1.1\r\nHost: api.vendor.example\r\n", "\r\n"} {
		if _, err := io.WriteString(client, fragment); err != nil {
			t.Fatalf("writing fragmented request: %v", err)
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "doorway" || calls.Load() != 1 || mismatches.Load() != 0 {
		t.Fatalf("response body %q, calls %d, mismatches %d, error %v", data, calls.Load(), mismatches.Load(), err)
	}
}

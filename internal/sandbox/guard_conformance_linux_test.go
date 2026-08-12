// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const guardConformanceHelperEnv = "PIPELOCK_GUARD_CONFORMANCE_HELPER"

// TestGuardHostileProcessHelper runs as the final process under the real Guard
// CLI. It is intentionally inert in the parent test process.
func TestGuardHostileProcessHelper(t *testing.T) {
	mode := os.Getenv(guardConformanceHelperEnv)
	if mode == "" {
		return
	}

	switch mode {
	case "boundary":
		runGuardBoundaryHelper(t)
	case "broker":
		if _, err := os.Stdin.Write([]byte("delegate")); err != nil {
			t.Fatalf("same-UID broker write: %v", err)
		}
		response := make([]byte, len("broker-ok"))
		_, err := io.ReadFull(os.Stdin, response)
		if err != nil || string(response) != "broker-ok" {
			t.Fatalf("same-UID broker response = %q, %v", response, err)
		}
	case "state":
		state := os.Getenv("PIPELOCK_TEST_STATE")
		run := os.Getenv("PIPELOCK_TEST_RUN")
		if run == "2" {
			if contents, err := os.ReadFile(filepath.Clean(filepath.Join(state, "first"))); err != nil || string(contents) != "one" {
				t.Fatalf("post-success state = %q, %v", contents, err)
			}
		}
		if err := os.WriteFile(filepath.Join(state, map[string]string{"1": "first", "2": "second"}[run]), []byte(map[string]string{"1": "one", "2": "two"}[run]), 0o600); err != nil {
			t.Fatalf("write run %s state: %v", run, err)
		}
	case "revoked-state":
		if _, err := os.ReadFile(filepath.Join(os.Getenv("PIPELOCK_TEST_OLD_STATE"), "first")); err == nil {
			t.Fatal("revoked state remained readable after the policy changed")
		}
		if err := os.WriteFile(filepath.Join(os.Getenv("PIPELOCK_TEST_STATE"), "current"), []byte("new"), 0o600); err != nil {
			t.Fatalf("write replacement state: %v", err)
		}
	default:
		t.Fatalf("unknown Guard conformance helper mode %q", mode)
	}
}

func runGuardBoundaryHelper(t *testing.T) {
	t.Helper()
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil || string(stdin) != "operator stdin\n" {
		t.Fatalf("stdin = %q, %v", stdin, err)
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(key), "__PIPELOCK_") {
			t.Fatalf("Pipelock control variable reached final command: %q", key)
		}
		if isProxyEnvKey(key) && strings.Contains(entry, "attacker.invalid") {
			t.Fatalf("attacker proxy reached final command: %q", entry)
		}
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if value := os.Getenv(key); !strings.HasPrefix(value, "http://127.0.0.1:") {
			t.Fatalf("%s = %q, want Guard loopback bridge", key, value)
		}
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if value := os.Getenv(key); value != "" {
			t.Fatalf("%s = %q, want empty", key, value)
		}
	}

	outside := os.Getenv("PIPELOCK_TEST_OUTSIDE")
	if _, err := os.ReadFile(filepath.Clean(outside)); err == nil {
		t.Fatal("read outside the Guard manifest succeeded")
	}
	if err := os.WriteFile(outside, []byte("overwritten"), 0o600); err == nil {
		t.Fatal("write outside the Guard manifest succeeded")
	}
	link := filepath.Join(os.Getenv("PIPELOCK_TEST_WORKSPACE"), "outside-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("create workspace symlink: %v", err)
	}
	if _, err := os.ReadFile(filepath.Clean(link)); err == nil {
		t.Fatal("workspace symlink escaped the Guard manifest")
	}
	renameSource := filepath.Join(os.Getenv("PIPELOCK_TEST_WORKSPACE"), "rename-source")
	if err := os.WriteFile(renameSource, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write rename source: %v", err)
	}
	if err := os.Rename(renameSource, outside); err == nil {
		t.Fatal("rename escaped the Guard manifest")
	}

	dialer := net.Dialer{Timeout: 300 * time.Millisecond}
	if conn, err := dialer.DialContext(t.Context(), "tcp4", os.Getenv("PIPELOCK_TEST_TCP")); err == nil {
		_ = conn.Close()
		t.Fatal("direct host TCP connection succeeded")
	}
	if conn, err := dialer.DialContext(t.Context(), "tcp6", "[2001:db8::1]:443"); err == nil {
		_ = conn.Close()
		t.Fatal("direct IPv6 connection succeeded")
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", os.Getenv("PIPELOCK_TEST_UDP"))
	if err != nil {
		t.Fatalf("resolve UDP witness: %v", err)
	}
	udp, err := net.DialUDP("udp4", nil, udpAddr)
	if err == nil {
		_, _ = udp.Write([]byte("guard-udp-bypass"))
		_ = udp.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(ctx, "guard-child-dns.invalid."); err == nil {
		t.Fatal("child-side DNS unexpectedly resolved")
	}
}

func TestIntegration_GuardHostileConformance(t *testing.T) {
	binary := buildTestBinary(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test helper: %v", err)
	}

	t.Run("direct egress, filesystem, environment, and stdin", func(t *testing.T) {
		root := t.TempDir()
		workspace := filepath.Join(root, "workspace")
		if err := os.Mkdir(workspace, 0o750); err != nil {
			t.Fatalf("create workspace: %v", err)
		}
		outside := filepath.Join(root, "outside")
		if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
			t.Fatalf("write outside fixture: %v", err)
		}
		tcpWitness, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen TCP witness: %v", err)
		}
		defer func() { _ = tcpWitness.Close() }()
		udpWitness, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen UDP witness: %v", err)
		}
		defer func() { _ = udpWitness.Close() }()

		environment := guardTestEnvironment(map[string]string{
			guardConformanceHelperEnv: "boundary",
			"PIPELOCK_TEST_WORKSPACE": workspace,
			"PIPELOCK_TEST_OUTSIDE":   outside,
			"PIPELOCK_TEST_TCP":       tcpWitness.Addr().String(),
			"PIPELOCK_TEST_UDP":       udpWitness.LocalAddr().String(),
			"HTTP_PROXY":              "http://attacker.invalid:8080",
			"https_proxy":             "http://attacker.invalid:8081",
			"NO_PROXY":                "*",
			"Http_Proxy":              "http://attacker.invalid:8082",
			"__pipelock_attacker":     "must-be-removed",
		})
		_, stderr, err := runGuardBinary(t, binary, environment, strings.NewReader("operator stdin\n"),
			"guard", "--workspace", workspace, "--", helper, "-test.run=^TestGuardHostileProcessHelper$")
		if err != nil {
			t.Fatalf("hostile Guard command: %v\nstderr: %s", err, stderr)
		}
		if contents, err := os.ReadFile(filepath.Clean(outside)); err != nil || string(contents) != "secret" {
			t.Fatalf("outside fixture = %q, %v", contents, err)
		}
		assertNoTCPWitness(t, tcpWitness)
		assertNoUDPWitness(t, udpWitness)
	})

	t.Run("argv transport preserves hostile delimiters", func(t *testing.T) {
		workspace := t.TempDir()
		script := filepath.Join(workspace, "argv-check")
		body := "#!/bin/sh\n" +
			"test \"$1\" = \"left$(printf '\\037')right\" && " +
			"test \"$2\" = \"line one\nline two\" && " +
			"test \"$3\" = \"--config\" && test \"$4\" = \"/proc/self/fd/0\"\n"
		if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
			t.Fatalf("write argv helper: %v", err)
		}
		_, stderr, err := runGuardBinary(t, binary, nil, nil,
			"guard", "--workspace", workspace, "--", "/bin/sh", script,
			"left\x1fright", "line one\nline two", "--config", "/proc/self/fd/0")
		if err != nil {
			t.Fatalf("argv conformance: %v\nstderr: %s", err, stderr)
		}
	})

	t.Run("rerun, post-success state, and policy replacement", func(t *testing.T) {
		root := t.TempDir()
		workspace := filepath.Join(root, "workspace")
		if err := os.Mkdir(workspace, 0o750); err != nil {
			t.Fatalf("create workspace: %v", err)
		}
		oldState := filepath.Join(root, "old-state")
		newState := filepath.Join(root, "new-state")
		oldConfig := writeGuardStateConfig(t, oldState)
		for _, run := range []string{"1", "2"} {
			environment := guardTestEnvironment(map[string]string{
				guardConformanceHelperEnv: "state",
				"PIPELOCK_TEST_STATE":     oldState,
				"PIPELOCK_TEST_RUN":       run,
			})
			_, stderr, err := runGuardBinary(t, binary, environment, nil,
				"guard", "--config", oldConfig, "--profile", "worker", "--workspace", workspace,
				"--", helper, "-test.run=^TestGuardHostileProcessHelper$")
			if err != nil {
				t.Fatalf("Guard state run %s: %v\nstderr: %s", run, err, stderr)
			}
		}
		newConfig := writeGuardStateConfig(t, newState)
		environment := guardTestEnvironment(map[string]string{
			guardConformanceHelperEnv: "revoked-state",
			"PIPELOCK_TEST_OLD_STATE": oldState,
			"PIPELOCK_TEST_STATE":     newState,
		})
		_, stderr, err := runGuardBinary(t, binary, environment, nil,
			"guard", "--config", newConfig, "--profile", "worker", "--workspace", workspace,
			"--", helper, "-test.run=^TestGuardHostileProcessHelper$")
		if err != nil {
			t.Fatalf("Guard replacement policy: %v\nstderr: %s", err, stderr)
		}
	})

	t.Run("same-UID broker limitation remains explicit", func(t *testing.T) {
		workspace := t.TempDir()
		descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("create inherited broker socket: %v", err)
		}
		childBroker := os.NewFile(uintptr(descriptors[0]), "guard-broker-child")
		parentBroker := os.NewFile(uintptr(descriptors[1]), "guard-broker-parent")
		if childBroker == nil || parentBroker == nil {
			t.Fatal("wrap inherited broker descriptors")
		}
		defer func() { _ = childBroker.Close() }()
		defer func() { _ = parentBroker.Close() }()
		served := make(chan error, 1)
		go func() {
			request := make([]byte, len("delegate"))
			if _, readErr := io.ReadFull(parentBroker, request); readErr != nil {
				served <- readErr
				return
			}
			if string(request) != "delegate" {
				served <- fmt.Errorf("broker request = %q", request)
				return
			}
			_, writeErr := parentBroker.Write([]byte("broker-ok"))
			served <- writeErr
		}()
		environment := guardTestEnvironment(map[string]string{
			guardConformanceHelperEnv: "broker",
		})
		stdout, stderr, err := runGuardBinary(t, binary, environment, childBroker,
			"guard", "--workspace", workspace, "--", helper, "-test.run=^TestGuardHostileProcessHelper$")
		if err != nil {
			t.Fatalf("same-UID broker proof: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Fatalf("broker: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("same-UID broker was not reached")
		}
		assertGuardClaimBoundary(t)
	})

	t.Run("malformed control aliases fail before command", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "started")
		for _, testCase := range []struct {
			name string
			env  map[string]string
			want string
		}{
			{name: "guard helper", env: map[string]string{"__PIPELOCK_GUARD_EXEC": "1"}, want: "invalid guard environment descriptor"},
			{name: "standalone init", env: map[string]string{standaloneInitEnv: "1"}, want: "missing workspace, command, or socket path"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				_, stderr, err := runGuardBinary(t, binary, guardTestEnvironment(testCase.env), nil,
					"guard", "--workspace", t.TempDir(), "--", "sh", "-c", "touch "+marker)
				if err == nil || !strings.Contains(stderr, testCase.want) {
					t.Fatalf("malformed control error = %v, stderr=%q", err, stderr)
				}
				if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("operator command ran through malformed controls: %v", statErr)
				}
			})
		}
	})

	t.Run("config stdin aliases fail before command", func(t *testing.T) {
		workspace := t.TempDir()
		marker := filepath.Join(workspace, "started")
		alias := filepath.Join(t.TempDir(), "stdin-config")
		if err := os.Symlink("/proc/self/fd/0", alias); err != nil {
			t.Fatalf("create stdin alias: %v", err)
		}
		for _, configPath := range []string{"/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", alias} {
			_, stderr, err := runGuardBinary(t, binary, nil, strings.NewReader("enforce: true\n"),
				"guard", "--config", configPath, "--workspace", workspace, "--", "sh", "-c", "touch "+marker)
			if err == nil || !strings.Contains(stderr, "stdin") {
				t.Fatalf("config alias %q error = %v, stderr=%q", configPath, err, stderr)
			}
			if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("operator command ran with config alias %q: %v", configPath, statErr)
			}
		}
	})

	t.Run("signaled command status and pre-exec claim", func(t *testing.T) {
		_, stderr, err := runGuardBinary(t, binary, nil, nil,
			"guard", "--workspace", t.TempDir(), "--", "sh", "-c", "kill -TERM $$")
		if err == nil {
			t.Fatal("signaled Guard command unexpectedly succeeded")
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("Guard signal error = %T %v", err, err)
		}
		if got := exitErr.ExitCode(); got != 128+int(syscall.SIGTERM) {
			t.Fatalf("Guard signal exit code = %d, want %d\nstderr: %s", got, 128+int(syscall.SIGTERM), stderr)
		}
		if !strings.Contains(stderr, "[guard] ENFORCED") || strings.Contains(strings.ToLower(stderr), "command started") {
			t.Fatalf("Guard signal output overclaims command start:\n%s", stderr)
		}
		assertGuardClaimBoundary(t)
	})
}

func runGuardBinary(t *testing.T, binary string, environment []string, stdin io.Reader, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- controlled conformance command.
	cmd.Env = environment
	cmd.Stdin = stdin
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("Guard conformance command timed out: %v\nstderr: %s", ctx.Err(), stderr.String())
	}
	return stdout.String(), stderr.String(), err
}

func guardTestEnvironment(overrides map[string]string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for key := range overrides {
		keys[key] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := keys[key]; !replaced {
			environment = append(environment, entry)
		}
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func writeGuardStateConfig(t *testing.T, state string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := fmt.Sprintf("guard:\n  profiles:\n    - name: worker\n      manifests: [state]\n  manifests:\n    - name: state\n      read_write_directories:\n        - %q\n", state)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write Guard state config: %v", err)
	}
	return path
}

func assertNoTCPWitness(t *testing.T, listener net.Listener) {
	t.Helper()
	deadlineListener, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatalf("TCP witness type = %T", listener)
	}
	if err := deadlineListener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set TCP witness deadline: %v", err)
	}
	conn, err := listener.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("guarded process reached the host TCP witness")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("TCP witness accept: %v", err)
	}
}

func assertNoUDPWitness(t *testing.T, listener net.PacketConn) {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set UDP witness deadline: %v", err)
	}
	buffer := make([]byte, 64)
	if n, address, err := listener.ReadFrom(buffer); err == nil {
		t.Fatalf("guarded process reached host UDP witness from %s: %q", address, buffer[:n])
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("UDP witness read: %v", err)
		}
	}
}

func assertGuardClaimBoundary(t *testing.T) {
	t.Helper()
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "cli", "guard.md"))
	if err != nil {
		t.Fatalf("read Guard docs: %v", err)
	}
	text := strings.Join(strings.Fields(string(docs)), " ")
	for _, required := range []string{
		"same-UID host process over an accessible broker or IPC channel",
		"does not claim that the operator command started",
		"direct TCP, UDP, QUIC, and child DNS",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Guard docs lost required claim boundary %q", required)
		}
	}
}

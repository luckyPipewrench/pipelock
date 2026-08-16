// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// processAlive reports whether pid names a live process. A reaped-but-not-yet
// collected zombie is NOT alive: kill(pid, 0) succeeds against a zombie, so a
// liveness check written that way would pass while the tree was still leaking.
func processAlive(pid int) bool {
	statBytes, err := os.ReadFile(filepath.Clean("/proc/" + strconv.Itoa(pid) + "/stat"))
	if err != nil {
		return false
	}
	stat := string(statBytes)
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return false
	}
	fields := strings.Fields(stat[end+1:])
	return len(fields) > 0 && fields[0] != "Z"
}

// aliveReport names the members of a process tree that are still running. It
// formats lazily, so the list reflects the moment a wait actually timed out
// rather than the moment the message was constructed.
type aliveReport map[string]int

func (a aliveReport) String() string {
	parts := make([]string, 0, len(a))
	for label, pid := range a {
		if processAlive(pid) {
			parts = append(parts, fmt.Sprintf("%s (pid %d)", label, pid))
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func waitForGone(t *testing.T, pids map[string]int, deadline time.Duration) {
	t.Helper()
	testwait.For(t, deadline, func() bool {
		for _, pid := range pids {
			if processAlive(pid) {
				return false
			}
		}
		return true
	}, "the process tree to exit after its spawning session was killed; still alive: %s", aliveReport(pids))
}

// TestRunProxy_ResponseTimeoutReapsEscapedPipeHolder verifies the response
// timeout path does not depend on the wrapped server's stdout or stderr pipes
// closing before it can reach the adopted-descendant sweep. The direct shell
// is killed for timing out, while the setsid child keeps both descriptors open.
func TestRunProxy_ResponseTimeoutReapsEscapedPipeHolder(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "escaped.pid")
	script := "setsid sleep 300 &\n" +
		"echo $! > " + pidFile + ".tmp\n" +
		"mv " + pidFile + ".tmp " + pidFile + "\n" +
		"sleep 300\n"

	sc := testScannerWithAction(t, "warn")
	opts := buildTestOpts(sc)
	opts.InputCfg = &InputScanConfig{
		Action:                 config.ActionWarn,
		OnParseError:           config.ActionBlock,
		ResponseTimeoutSeconds: 1,
	}

	var out, logBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- RunProxy(context.Background(),
			strings.NewReader(mcpToolCall(mcpAllowedTool, "")+"\n"),
			&out, &logBuf, []string{"/bin/sh", "-c", script}, opts)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, transport.ErrResponseTimeout) {
			t.Fatalf("RunProxy error = %v, want ErrResponseTimeout", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("RunProxy hung after response timeout with an escaped pipe holder")
	}

	pidBytes, err := os.ReadFile(filepath.Clean(pidFile))
	if err != nil {
		t.Fatalf("reading escaped child PID: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 0 {
		t.Fatalf("escaped child PID = %q, want positive integer", pidBytes)
	}
	t.Cleanup(func() {
		if processAlive(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	waitForGone(t, map[string]int{"escaped pipe holder": pid}, 5*time.Second)
}

// TestSessionExit_RealParentDeathReapsWholeTree drives the actual production
// path with a real three-level process tree and a real kill. Nothing about
// the parent PID is stubbed.
//
//	test  ->  session (sh)  ->  pipelock proxy (RunProxy)  ->  server  ->  grandchild
//
// The test kills the SESSION, which is the process whose death the watcher
// must notice. The wrapped server ignores stdin entirely, so the stdin-EOF
// path that already existed cannot shut it down - reproducing the leak this
// work closes - and the grandchild is detached into its own session via
// setsid so it escapes a plain process-group kill.
func TestSessionExit_RealParentDeathReapsWholeTree(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real process tree and waits out the drain grace window")
	}

	dir := t.TempDir()
	pidFile := filepath.Join(dir, "server.pids")
	proxyPidFile := filepath.Join(dir, "proxy.pid")

	// An MCP server that never reads stdin. Closing its stdin is a no-op,
	// which is precisely why EOF alone is not a shutdown signal.
	serverScript := filepath.Join(dir, "server.sh")
	script := "#!/bin/sh\n" +
		"echo $$ > " + pidFile + ".tmp\n" +
		// Detach a grandchild into its own session so it leaves the
		// server's process group and can only be reached by the
		// adopted-descendant sweep.
		// Keep stdout inherited from the wrapped server. Before the regression
		// fix this makes the scanner's stdout reader block after the direct
		// server dies, proving that the post-Wait adopted-descendant sweep is
		// otherwise unreachable.
		"setsid sleep 300 &\n" +
		"echo $! >> " + pidFile + ".tmp\n" +
		"mv " + pidFile + ".tmp " + pidFile + "\n" +
		"exec sleep 300\n"
	if err := os.WriteFile(serverScript, []byte(script), 0o600); err != nil {
		t.Fatalf("writing server script: %v", err)
	}

	// The session process. It starts the proxy and then sleeps; killing it
	// is what reparents the proxy.
	// Fed to /bin/sh on stdin rather than exec'd as a file, so both the
	// command name and its argument list are constants and the helper
	// binary path travels in the environment instead.
	sess := "\"$PIPELOCK_SESSION_EXIT_BIN\" -test.run=TestSessionExitHelperProcess >" +
		filepath.Join(dir, "helper.log") + " 2>&1 &\n" +
		"echo $! > " + proxyPidFile + "\n" +
		"sleep 300\n"

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	session := exec.CommandContext(ctx, "/bin/sh")
	session.Stdin = strings.NewReader(sess)
	session.Env = append(os.Environ(),
		"PIPELOCK_SESSION_EXIT_HELPER=1",
		"PIPELOCK_SESSION_EXIT_SERVER="+serverScript,
		"PIPELOCK_SESSION_EXIT_BIN="+os.Args[0],
	)
	if err := session.Start(); err != nil {
		t.Fatalf("starting session process: %v", err)
	}
	defer func() {
		_ = session.Process.Kill()
		_, _ = session.Process.Wait()
	}()

	// Wait for the full tree to exist before killing anything.
	var serverPID, grandchildPID, proxyPID int
	testwait.For(t, 30*time.Second, func() bool {
		pidBytes, err1 := os.ReadFile(filepath.Clean(pidFile))
		proxyBytes, err2 := os.ReadFile(filepath.Clean(proxyPidFile))
		if err1 != nil || err2 != nil {
			return false
		}
		fields := strings.Fields(string(pidBytes))
		proxyFields := strings.Fields(string(proxyBytes))
		if len(fields) != 2 || len(proxyFields) != 1 {
			return false
		}
		serverPID, _ = strconv.Atoi(fields[0])
		grandchildPID, _ = strconv.Atoi(fields[1])
		proxyPID, _ = strconv.Atoi(proxyFields[0])
		return serverPID > 0 && grandchildPID > 0 && proxyPID > 0
	}, "the process tree to come up")

	tree := map[string]int{"wrapped server": serverPID, "detached grandchild": grandchildPID, "proxy": proxyPID}
	t.Cleanup(func() {
		for _, pid := range tree {
			if processAlive(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	for label, pid := range tree {
		if !processAlive(pid) {
			t.Fatalf("%s (pid %d) was not alive before the kill; test setup is wrong", label, pid)
		}
	}

	// Kill the session. This is the only action the test takes against the
	// tree - everything below must follow from the watcher noticing.
	if err := syscall.Kill(session.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatalf("killing session process: %v", err)
	}

	// Poll interval + drain grace + teardown, with slack for a loaded CI box.
	waitForGone(t, tree, 45*time.Second)
	if logBytes, readErr := os.ReadFile(filepath.Clean(filepath.Join(dir, "helper.log"))); readErr == nil &&
		strings.Contains(string(logBytes), "input scanner error") {
		t.Errorf("session teardown logged a scanner error instead of its shutdown reason:\n%s", logBytes)
	}

	if t.Failed() {
		if logBytes, readErr := os.ReadFile(filepath.Clean(filepath.Join(dir, "helper.log"))); readErr == nil {
			t.Logf("helper output:\n%s", logBytes)
		}
	}
}

// TestSessionExitHelperProcess is the proxy level of the tree above. It is a
// helper, not a test: it runs only when the parent test sets the env marker.
func TestSessionExitHelperProcess(t *testing.T) {
	if os.Getenv("PIPELOCK_SESSION_EXIT_HELPER") != "1" {
		t.Skip("helper process; driven by TestSessionExit_RealParentDeathReapsWholeTree")
	}

	if os.Getenv("PIPELOCK_SESSION_EXIT_SERVER") == "" {
		t.Fatal("helper started without a server script")
	}

	// Keep stdin open but silent. A closed stdin would make the client
	// reader hit EOF immediately, which is a different (and already
	// handled) path than the one under test.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stdin pipe: %v", err)
	}
	defer func() { _ = stdinW.Close() }()

	// No timeout: if the watcher fails to fire, this call hangs exactly as
	// the leaked proxies on the live host did, and the parent test fails on
	// its own deadline rather than being rescued by a context here.
	err = RunProxy(context.Background(), stdinR, os.Stdout, os.Stderr,
		[]string{"/bin/sh", "-c", "exec /bin/sh \"$PIPELOCK_SESSION_EXIT_SERVER\""}, MCPProxyOpts{},
		"PIPELOCK_SESSION_EXIT_SERVER="+os.Getenv("PIPELOCK_SESSION_EXIT_SERVER"))
	fmt.Fprintf(os.Stderr, "helper: RunProxy returned: %v\n", err)
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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
	script := "umask 077\n" +
		"setsid sleep 300 &\n" +
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

func TestWaitForCommandWithProcessGroupSignalsBeforeReap(t *testing.T) {
	const resolverScript = "umask 077; sleep 300 & child=$!; printf '%s\\n' \"$child\" > \"$MCP_TEST_PID_FILE\"; wait"

	dir := t.TempDir()
	pidFile := filepath.Join(dir, "resolver-child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", resolverScript)
	cmd.Env = append(os.Environ(), "MCP_TEST_PID_FILE="+pidFile)
	setupChildProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting resolver tree: %v", err)
	}
	pgid := captureChildPgid(cmd.Process.Pid)
	reaped := false
	t.Cleanup(func() {
		if !reaped {
			terminateProcessGroup(pgid)
			_ = cmd.Wait()
		}
	})

	var childPID int
	testwait.For(t, 5*time.Second, func() bool {
		pidBytes, err := os.ReadFile(filepath.Clean(pidFile))
		if err != nil {
			return false
		}
		childPID, err = strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		return err == nil && childPID > 0
	}, "the resolver child to write its PID")

	done := make(chan error, 1)
	go func() { done <- waitForCommandWithProcessGroup(ctx, cmd, pgid, &processExitHandoff{}) }()
	cancel()
	select {
	case err := <-done:
		reaped = true
		if err == nil {
			t.Fatal("resolver tree exited cleanly after forced teardown")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resolver tree was not reaped after cancellation")
	}

	waitForGone(t, map[string]int{"resolver child": childPID}, 5*time.Second)
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
		"umask 077\n" +
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
	sess := "umask 077\n" +
		"\"$PIPELOCK_SESSION_EXIT_BIN\" -test.run=TestSessionExitHelperProcess >" +
		filepath.Join(dir, "helper.log") + " 2>&1 &\n" +
		"echo $! > " + proxyPidFile + "\n" +
		"wait\n"

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

// TestSessionExit_SandboxTreeIsReaped drives the sandbox proxy entry point
// through its real child process tree. The watch uses a controllable PPID so
// the test can first prove the sandbox command and its detached descendant
// exist, then trigger the same teardown production runs after reparenting.
func TestSessionExit_SandboxTreeIsReaped(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real sandbox proxy process tree")
	}

	const sandboxScript = "umask 077\necho $$ > \"$MCP_TEST_SANDBOX_FILE\"\nsetsid sleep 300 &\necho $! > \"$MCP_TEST_GRANDCHILD_FILE\"\nsleep 300"

	dir := t.TempDir()
	sandboxFile := filepath.Join(dir, "sandbox.pid")
	grandchildFile := filepath.Join(dir, "grandchild.pid")

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	clientIn := newBlockingReader()
	defer func() { _ = clientIn.Close() }()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", sandboxScript)
	cmd.Env = append(os.Environ(),
		"MCP_TEST_SANDBOX_FILE="+sandboxFile,
		"MCP_TEST_GRANDCHILD_FILE="+grandchildFile,
	)
	sc := testScannerWithAction(t, config.ActionWarn)
	var logBuf syncBuffer
	var parentDied atomic.Bool
	opts := testOpts(sc)
	opts.sessionExitForTest = &sessionExitTestHooks{watch: parentWatchOpts{
		interval:  time.Millisecond,
		startPPID: 4242,
		getppid: func() int {
			if parentDied.Load() {
				return orphanedPPID
			}
			return 4242
		},
	}, grace: 50 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		done <- RunProxyWithSandbox(ctx, cmd, clientIn, io.Discard, &logBuf, opts)
	}()

	var sandboxPID, grandchildPID int
	testwait.For(t, 15*time.Second, func() bool {
		sandboxBytes, sandboxErr := os.ReadFile(filepath.Clean(sandboxFile))
		grandchildBytes, grandchildErr := os.ReadFile(filepath.Clean(grandchildFile))
		if sandboxErr != nil || grandchildErr != nil {
			return false
		}
		var sandboxPIDErr, grandchildPIDErr error
		sandboxPID, sandboxPIDErr = strconv.Atoi(strings.TrimSpace(string(sandboxBytes)))
		grandchildPID, grandchildPIDErr = strconv.Atoi(strings.TrimSpace(string(grandchildBytes)))
		return sandboxPIDErr == nil && grandchildPIDErr == nil && sandboxPID > 0 && grandchildPID > 0
	}, "the sandbox tree to come up")

	tree := map[string]int{
		"sandbox command":        sandboxPID,
		"detached sandbox child": grandchildPID,
	}
	for label, pid := range tree {
		if !processAlive(pid) {
			t.Fatalf("%s (pid %d) was not alive before session exit", label, pid)
		}
	}

	parentDied.Store(true)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("sandbox proxy stayed alive after the spawning session exited")
	}

	waitForGone(t, tree, 10*time.Second)
	if !strings.Contains(logBuf.String(), "spawning session exited") {
		t.Errorf("missing session-exit explanation in operator log, got %q", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "terminating process tree") {
		t.Errorf("missing sandbox process-tree teardown notice, got %q", logBuf.String())
	}
}

func TestSessionExit_SandboxLiveSessionIsNotTornDown(t *testing.T) {
	const liveSessionScript = "umask 077; touch \"$MCP_TEST_READY_FILE\"; sleep 300"

	if testing.Short() {
		t.Skip("spawns a real sandbox proxy process")
	}

	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientIn := newBlockingReader()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", liveSessionScript)
	cmd.Env = append(os.Environ(), "MCP_TEST_READY_FILE="+readyFile)
	sc := testScannerWithAction(t, config.ActionWarn)
	var logBuf syncBuffer
	opts := testOpts(sc)
	opts.sessionExitForTest = liveSessionExitHooks()
	done := make(chan error, 1)
	go func() {
		done <- RunProxyWithSandbox(ctx, cmd, clientIn, io.Discard, &logBuf, opts)
	}()

	testwait.For(t, 10*time.Second, func() bool {
		if _, err := os.Stat(readyFile); err == nil {
			return true
		}
		return false
	}, "the sandbox command to become ready")

	select {
	case err := <-done:
		t.Fatalf("sandbox proxy exited while its session was alive: %v; log: %q", err, logBuf.String())
	case <-time.After(250 * time.Millisecond):
	}
	if strings.Contains(logBuf.String(), "spawning session exited") {
		t.Errorf("session-exit path ran against a live parent, got %q", logBuf.String())
	}

	_ = clientIn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		// Report the operator log and the surviving processes. This assertion
		// has failed on CI while passing on a development host, and a bare
		// timeout says nothing about which stage did not finish.
		t.Fatalf("sandbox proxy did not stop after context cancellation; log: %q; surviving descendants: %s",
			logBuf.String(), describeOwnDescendants())
	}
}

// TestSessionExit_SandboxCancellationWithSurvivingPipeHolder is the CI-shaped
// version of the cancellation case above.
//
// The sibling test runs "sh -c '...; sleep 300'", which on many shells execs
// the final sleep in place, so the direct-child SIGKILL that
// exec.CommandContext sends happens to reach the process holding stdout. That
// makes the test pass without any cancellation teardown at all, and it is why
// it passed on a development host while failing on CI.
//
// Here the shell keeps a detached descendant that holds stdout and does not
// exec in place, so the direct kill cannot reach the pipe holder. Without a
// cancellation teardown the output reader never sees EOF and this call never
// returns.
func TestSessionExit_SandboxCancellationWithSurvivingPipeHolder(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real sandbox proxy process")
	}

	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")
	// setsid moves the descendant into its own session, so it survives both
	// the direct-child kill and a plain process-group signal, while keeping
	// the inherited stdout it was given.
	script := "umask 077; setsid sleep 300 & touch \"$MCP_TEST_READY_FILE\"; wait"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientIn := newBlockingReader()
	defer func() { _ = clientIn.Close() }()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Env = append(os.Environ(), "MCP_TEST_READY_FILE="+readyFile)
	var logBuf syncBuffer
	opts := testOpts(testScannerWithAction(t, config.ActionWarn))
	opts.sessionExitForTest = liveSessionExitHooks()

	done := make(chan error, 1)
	go func() {
		done <- RunProxyWithSandbox(ctx, cmd, clientIn, io.Discard, &logBuf, opts)
	}()

	testwait.For(t, 10*time.Second, func() bool {
		_, err := os.Stat(readyFile)
		return err == nil
	}, "the sandbox command to become ready")

	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("sandbox proxy did not stop after cancellation while a detached descendant held stdout; log: %q; surviving descendants: %s",
			logBuf.String(), describeOwnDescendants())
	}
}

// subreaperDirectionDeadline bounds a hang; it is not part of either assertion.
//
// Both subtests below pass one context to RunProxyWithSandbox AND to
// exec.CommandContext, so the deadline owns the subprocess lifetime as well as
// the test. At 10 seconds that made the deadline a participant in the result: on
// a loaded runner the context expired during startup, exec killed "cat", and the
// best-effort subtest reported "subprocess exited: signal: terminated" as though
// best-effort mode had refused. It failed exactly that way on main at 022ee66f6
// while the same commit passed the full race suite locally, and 15 consecutive
// isolated runs passed in 2.4s.
//
// Neither subtest waits for anything by design: "cat" reads an empty stdin and
// exits on EOF. So the deadline only needs to be large enough that a healthy run
// cannot reach it, with the package -timeout as the real backstop. Each subtest
// also attributes an expiry explicitly, so if this ever does fire the failure
// says it was the clock rather than implying a product verdict.
const subreaperDirectionDeadline = 2 * time.Minute

func TestRunProxyWithSandbox_SubreaperFailureDirections(t *testing.T) {
	failure := errors.New("subreaper unavailable")

	t.Run("best effort continues with warning", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), subreaperDirectionDeadline)
		defer cancel()
		var logBuf syncBuffer
		opts := testOpts(testScannerWithAction(t, config.ActionWarn))
		opts.enableSubreaperForTest = func() error { return failure }
		cmd := exec.CommandContext(ctx, "cat")
		if err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, &logBuf, opts); err != nil {
			if ctx.Err() != nil {
				t.Fatalf("deadline expired before startup finished, so this is a timing failure and not a best-effort refusal: %v (context: %v)", err, ctx.Err())
			}
			t.Fatalf("best-effort sandbox proxy = %v", err)
		}
		if !strings.Contains(logBuf.String(), "session descendant cleanup degraded") {
			t.Errorf("missing subreaper warning, got %q", logBuf.String())
		}
	})

	t.Run("strict fails closed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), subreaperDirectionDeadline)
		defer cancel()
		opts := testOpts(testScannerWithAction(t, config.ActionWarn))
		opts.enableSubreaperForTest = func() error { return failure }
		cmd := exec.CommandContext(ctx, "cat")
		err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, io.Discard, opts, true)
		if !errors.Is(err, failure) {
			if ctx.Err() != nil {
				t.Fatalf("deadline expired before strict mode reported, so this is a timing failure and not a missing refusal: %v (context: %v)", err, ctx.Err())
			}
			t.Fatalf("strict sandbox proxy error = %v, want subreaper failure", err)
		}
	})
}

// TestRunProxyWithSandbox_BestEffortChildSurvivesSiblingReaper is the
// cross-session direction of the subreaper failure case above.
//
// reapAdoptedZombies walks /proc and reaps any zombie parented to this process
// except the direct children sessions have claimed. A session whose subreaper
// setup was refused still owns a direct child, so if it does not claim that
// child, a concurrent session's reaper consumes its exit status and the owning
// cmd.Wait fails with ECHILD, surfacing as "waitid: no child processes".
//
// The sweeper here stands in for that concurrent session's reaper. It is
// deliberately continuous: the theft window is between the child exiting and
// this session reaping it, which is narrow and load-dependent, and is why this
// reproduced on a loaded CI runner rather than on a development host.
func TestRunProxyWithSandbox_BestEffortChildSurvivesSiblingReaper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	opts := testOpts(testScannerWithAction(t, config.ActionWarn))
	opts.enableSubreaperForTest = func() error { return errors.New("subreaper unavailable") }

	// A PID that is never one of ours, so the sweeper protects nothing of the
	// session under test and behaves exactly like a foreign session's reaper.
	const foreignDirectPID = -1
	sweeperDone := make(chan struct{})
	sweeperStopped := make(chan struct{})
	go func() {
		defer close(sweeperStopped)
		for {
			select {
			case <-sweeperDone:
				return
			default:
				reapAdoptedZombies(foreignDirectPID)
			}
		}
	}()
	defer func() {
		close(sweeperDone)
		<-sweeperStopped
	}()

	var logBuf syncBuffer
	cmd := exec.CommandContext(ctx, "cat")
	if err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, &logBuf, opts); err != nil {
		t.Fatalf("best-effort sandbox proxy with a concurrent sibling reaper = %v, want the session to keep its own child", err)
	}
}

func TestRunProxyWithSandbox_OrphanedParentStaysInert(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var logBuf syncBuffer
	opts := testOpts(testScannerWithAction(t, config.ActionWarn))
	opts.sessionExitForTest = &sessionExitTestHooks{watch: parentWatchOpts{startPPID: orphanedPPID}}
	cmd := exec.CommandContext(ctx, "cat")
	if err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, &logBuf, opts); err != nil {
		t.Fatalf("sandbox proxy with an unbound parent = %v", err)
	}
	if strings.Contains(logBuf.String(), "spawning session exited") {
		t.Errorf("unbound parent ran the session-exit path, got %q", logBuf.String())
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

// describeOwnDescendants lists the live processes still parented to this
// process, with their state and command name. It exists for one reason: a
// teardown assertion that times out on CI and passes on a development host
// says nothing about WHAT failed to finish, and a process holding a pipe open
// is the difference between a hung wait and a hung scan.
func describeOwnDescendants() string {
	selfPID := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "unreadable /proc: " + err.Error()
	}
	var found []string
	for _, entry := range entries {
		name := entry.Name()
		pid, convErr := strconv.Atoi(name)
		if convErr != nil || pid == selfPID {
			continue
		}
		statBytes, readErr := os.ReadFile(filepath.Clean("/proc/" + name + "/stat"))
		if readErr != nil {
			continue
		}
		stat := string(statBytes)
		cmdEnd := strings.LastIndex(stat, ")")
		cmdStart := strings.Index(stat, "(")
		if cmdEnd < 0 || cmdStart < 0 || cmdEnd <= cmdStart || cmdEnd+2 > len(stat) {
			continue
		}
		rest := strings.Fields(stat[cmdEnd+1:])
		if len(rest) < 2 {
			continue
		}
		if rest[1] != strconv.Itoa(selfPID) {
			continue
		}
		found = append(found, fmt.Sprintf("pid=%d state=%s comm=%s", pid, rest[0], stat[cmdStart+1:cmdEnd]))
	}
	if len(found) == 0 {
		return "none"
	}
	sort.Strings(found)
	return strings.Join(found, "; ")
}

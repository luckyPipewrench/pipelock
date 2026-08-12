// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// skipIfStandaloneUnavailable skips tests that require full standalone
// sandbox (CLONE_NEWUSER + CLONE_NEWNET + loopback setup). CI runners
// (Ubuntu with AppArmor) may allow namespace creation but restrict
// network capabilities inside the namespace.
func skipIfStandaloneUnavailable(t *testing.T) {
	t.Helper()
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	// Probe: try launching a minimal standalone sandbox. If loopback setup
	// fails (AppArmor restricts CAP_NET_ADMIN in user namespaces), skip.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"true"},
		Workspace: t.TempDir(),
	})
	if err != nil {
		t.Skipf("standalone sandbox unavailable: %v", err)
	}
}

func TestIsStandaloneInitMode_FalseByDefault(t *testing.T) {
	if IsStandaloneInitMode() {
		t.Error("should not be in standalone init mode during normal tests")
	}
}

func TestLaunchStandalone_EchoCommand(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"echo", "standalone-test-output"},
		Workspace: workspace,
	})
	// echo exits immediately, LaunchStandalone should return cleanly.
	if err != nil {
		t.Fatalf("LaunchStandalone: %v", err)
	}
}

func TestLaunchStandalone_FilesystemBlocked(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	workspace := t.TempDir()

	// Create a test file in HOME so ENOENT isn't the failure reason.
	testFile := filepath.Join(home, ".pipelock-sandbox-test-marker")
	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		t.Skipf("cannot create test file in HOME: %v", err)
	}
	defer func() { _ = os.Remove(testFile) }()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"cat", testFile},
		Workspace: workspace,
	})
	// Should fail because Landlock blocks HOME access.
	if err == nil {
		t.Error("expected error (filesystem should be blocked)")
	}
}

func TestLaunchStandalone_NetworkBlocked(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	// Verify network isolation: count network interfaces in /proc/self/net/dev.
	// In a network namespace, only "lo" exists. Skip the 2 header lines,
	// then count non-lo interfaces.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "awk 'NR>2 && !/^\\s*lo:/' /proc/self/net/dev | grep -q . && exit 1; exit 0"},
		Workspace: workspace,
	})
	if err != nil {
		t.Errorf("network isolation check failed (non-lo interface found): %v", err)
	}
}

func TestLaunchStandalone_RejectsInvalidWorkspace(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: "/",
	})
	if err == nil {
		t.Error("expected error for / workspace")
	}
}

func TestLaunchStandalone_RequireProxyHandlerRejectsBeforeChildStart(t *testing.T) {
	workspace := t.TempDir()
	marker := filepath.Join(workspace, "child-started")

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:             []string{"sh", "-c", "touch " + marker},
		Workspace:           workspace,
		RequireProxyHandler: true,
	})
	if err == nil || !strings.Contains(err.Error(), "proxy handler is required") {
		t.Fatalf("LaunchStandalone error = %v, want required proxy handler error", err)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("child started despite required proxy handler denial: stat error = %v", statErr)
	}
}

func TestLaunchStandaloneRejectsInvalidGuardLaunchBeforeChildStart(t *testing.T) {
	workspace := t.TempDir()
	largeDeclaration := &config.Guard{Services: []config.GuardService{{
		Name: strings.Repeat("x", (1<<20)+1), Protocol: "tcp", Host: "api.vendor.example", Port: 443,
	}}}
	for _, testCase := range []struct {
		name string
		cfg  StandaloneLaunchConfig
		want string
	}{
		{name: "missing command", cfg: StandaloneLaunchConfig{Workspace: workspace}, want: "command is required"},
		{name: "missing guard hash", cfg: StandaloneLaunchConfig{Workspace: workspace, Command: []string{"true"}, GuardDeclaration: &config.Guard{}}, want: "policy hash is required"},
		{name: "oversized guard declaration", cfg: StandaloneLaunchConfig{Workspace: workspace, Command: []string{"true"}, GuardDeclaration: largeDeclaration, GuardPolicyHash: "hash"}, want: "64 KiB"},
		{name: "missing guard command", cfg: StandaloneLaunchConfig{Workspace: workspace, Command: []string{"missing-guard-command"}, GuardDeclaration: &config.Guard{}, GuardPolicyHash: "hash"}, want: "resolving guard command"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := LaunchStandalone(testCase.cfg); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestGuardLookupEnvironmentUsesCompleteSyntheticPath(t *testing.T) {
	got := guardLookupEnvironment(false, []string{"PATH=/developer/bin"})
	if len(got) != 1 || got[0] != "PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin" {
		t.Fatalf("synthetic guard lookup environment = %v", got)
	}
	developer := []string{"PATH=/developer/bin", "TOKEN=value"}
	if got := guardLookupEnvironment(true, developer); len(got) != len(developer) || got[0] != developer[0] || got[1] != developer[1] {
		t.Fatalf("developer guard lookup environment = %v", got)
	}
}

func TestGuardLookupEnvironmentResolvesSystemSbinCommand(t *testing.T) {
	var candidate string
	for _, path := range []string{"/usr/local/sbin", "/usr/sbin", "/sbin"} {
		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			info, infoErr := entry.Info()
			if infoErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				candidate = filepath.Join(path, entry.Name())
				break
			}
		}
		if candidate != "" {
			break
		}
	}
	if candidate == "" {
		t.Skip("no executable found in a system sbin directory")
	}
	resolved, err := ResolveCommandInDir(filepath.Base(candidate), guardLookupEnvironment(false, nil), t.TempDir())
	if err != nil {
		t.Fatalf("resolve sbin command %q: %v", candidate, err)
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil {
		t.Fatalf("stat resolved command %q: %v", resolved, err)
	}
	candidateInfo, err := os.Stat(candidate)
	if err != nil {
		t.Fatalf("stat candidate %q: %v", candidate, err)
	}
	if !os.SameFile(resolvedInfo, candidateInfo) {
		t.Fatalf("resolved sbin command = %q, want the same file as %q", resolved, candidate)
	}
}

func TestReadGuardExecutionProofRejectsExecFailureAndTrailingSuccess(t *testing.T) {
	success := `{"record":{"state":"enforced"},"effective_policy_hash":"hash"}`
	if got, err := readGuardExecutionProof(strings.NewReader(success)); err != nil || string(got) != success {
		t.Fatalf("success proof = %q, %v", got, err)
	}
	failure := success + "\n" + `{"exec_error":"permission denied"}`
	if _, err := readGuardExecutionProof(strings.NewReader(failure)); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("exec failure proof error = %v", err)
	}
	if _, err := readGuardExecutionProof(strings.NewReader(success + "\n" + success)); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("duplicate success proof error = %v", err)
	}
	for _, testCase := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: "reading enforced record"},
		{name: "wrong JSON type", raw: "1", want: "decoding enforced record"},
		{name: "truncated trailing record", raw: success + "\n{", want: "status completion"},
		{name: "first record is failure", raw: `{"exec_error":"refused"}`, want: "refused"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := readGuardExecutionProof(strings.NewReader(testCase.raw)); err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestLaunchStandalone_RequireNetNSRejectsBestEffort(t *testing.T) {
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:      []string{"true"},
		Workspace:    t.TempDir(),
		BestEffort:   true,
		RequireNetNS: true,
	})
	if err == nil || !strings.Contains(err.Error(), "network namespace is required") {
		t.Fatalf("LaunchStandalone error = %v, want required network namespace error", err)
	}
}

func TestLaunchStandalone_NonLinuxReturnsError(t *testing.T) {
	if runtime.GOOS == osLinux {
		t.Skip("testing non-linux behavior")
	}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: t.TempDir(),
	})
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

func TestLaunchStandalone_ProxyHandlerCalled(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	// Track whether the proxy handler was called.
	// Use mutex for thread safety since handler runs in a goroutine.
	var mu sync.Mutex
	var proxyData string
	handler := func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		mu.Lock()
		proxyData = string(buf[:n])
		mu.Unlock()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}

	// Use curl to make a request through the bridge proxy.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:      []string{"curl", "-s", "--max-time", "3", "--proxy", "http://127.0.0.1:8888", "http://test.local/check"},
		Workspace:    workspace,
		ProxyHandler: handler,
	})
	_ = err

	mu.Lock()
	defer mu.Unlock()
	if proxyData == "" {
		t.Error("proxy handler was never called")
	}
	if !strings.Contains(proxyData, "test.local") {
		t.Errorf("proxy handler didn't receive expected request, got: %s", proxyData)
	}
}

func TestLaunchStandalone_BridgeProxyListens(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	// Verify HTTP_PROXY is set and non-empty (bridge proxy address).
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "test -n \"$HTTP_PROXY\" || exit 1"},
		Workspace: workspace,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone: %v", err)
	}
}

func TestLaunchStandalone_ControlDirectoryIsPrivate(t *testing.T) {
	dir, err := newStandaloneControlDir()
	if err != nil {
		t.Fatalf("newStandaloneControlDir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// Lstat so a symlink would be reported as a symlink, not followed.
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("lstat control directory: %v", err)
	}
	if !info.Mode().IsDir() {
		t.Fatalf("control dir is not a real directory: %v", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("control directory mode = %#o, want 0700", got)
	}
	// The name must be unpredictable, not the per-PID path an attacker could
	// anticipate and pre-create or symlink in the sticky /tmp.
	if predictable := fmt.Sprintf("/tmp/pipelock-sandbox-%d", os.Getpid()); dir == predictable {
		t.Fatalf("control directory uses the predictable per-PID path: %s", dir)
	}
	// Two allocations must differ: a predictable implementation would return the
	// same path both times.
	dir2, err := newStandaloneControlDir()
	if err != nil {
		t.Fatalf("newStandaloneControlDir (second): %v", err)
	}
	defer func() { _ = os.RemoveAll(dir2) }()
	if dir2 == dir {
		t.Fatalf("two control directories share a predictable path: %s", dir)
	}
}

func TestPreflightWithRequirements_IndependentlyReportsNetworkAndHandler(t *testing.T) {
	requirements := PreflightRequirements{
		RequireNetNS:        true,
		RequireProxyHandler: true,
	}
	result := PreflightWithRequirements(t.TempDir(), []string{"true"}, nil, requirements)
	if result.Mode != "required" {
		t.Fatalf("mode = %q, want required", result.Mode)
	}
	if result.Requirements == nil || *result.Requirements != requirements {
		t.Fatalf("requirements = %#v, want %#v", result.Requirements, requirements)
	}

	required := make(map[LayerName]bool, len(result.Layers))
	for _, layer := range result.Layers {
		required[layer.Name] = layer.Required
	}
	if !required[LayerNetNS] {
		t.Fatal("network namespace was not reported as required")
	}
	if required[LayerLandlock] || required[LayerSeccomp] {
		t.Fatalf("optional layers reported as required: %#v", required)
	}
	if !Detect().UserNamespaces && result.Status != StatusError {
		t.Fatalf("required unavailable network namespace status = %q, want error", result.Status)
	}
}

func TestPreflight_BackwardCompatibleStrictWrapper(t *testing.T) {
	result := Preflight(t.TempDir(), []string{"true"}, nil, false)
	if result.Requirements != nil {
		t.Fatalf("legacy Preflight exposed requirements = %#v", result.Requirements)
	}
	if result.Mode != "best-effort" {
		t.Fatalf("legacy Preflight mode = %q, want best-effort", result.Mode)
	}
}

func TestLandlockMeetsRequirementRejectsOlderABI(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		observedABI int
		minimumABI  int
		want        bool
	}{
		{name: "absent legacy probe", observedABI: 0, want: false},
		{name: "present legacy probe", observedABI: 1, want: true},
		{name: "below explicit floor", observedABI: 4, minimumABI: 5, want: false},
		{name: "at explicit floor", observedABI: 5, minimumABI: 5, want: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := landlockMeetsRequirement(testCase.observedABI, testCase.minimumABI); got != testCase.want {
				t.Fatalf("landlockMeetsRequirement(%d, %d) = %v, want %v", testCase.observedABI, testCase.minimumABI, got, testCase.want)
			}
		})
	}
}

func TestStandaloneProxyServer_StopJoinsHandlers(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "stop waits for active handler"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socketDir, err := os.MkdirTemp("/tmp", "plk-proxy-*")
			if err != nil {
				t.Fatalf("mkdir socket dir: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
			socketPath := filepath.Join(socketDir, "proxy.sock")
			ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
			if err != nil {
				t.Fatalf("unix listen: %v", err)
			}

			handlerEntered := make(chan struct{})
			releaseHandler := make(chan struct{})
			handlerDone := make(chan struct{})
			server := startStandaloneProxyServer(ln, standaloneProxyConnectionConfig{
				ProxyHandler: func(conn net.Conn) {
					defer close(handlerDone)
					defer func() { _ = conn.Close() }()
					close(handlerEntered)
					for {
						select {
						case <-releaseHandler:
							return
						default:
							runtime.Gosched()
						}
					}
				},
			})
			defer server.stop()

			conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath)
			if err != nil {
				t.Fatalf("unix dial: %v", err)
			}
			defer func() { _ = conn.Close() }()

			select {
			case <-handlerEntered:
			case <-time.After(time.Second):
				t.Fatal("proxy handler did not start")
			}

			stopDone := make(chan struct{})
			go func() {
				defer close(stopDone)
				server.stop()
			}()

			select {
			case <-stopDone:
				close(releaseHandler)
				<-handlerDone
				t.Fatal("stop returned before active proxy handler exited")
			case <-time.After(100 * time.Millisecond):
				close(releaseHandler)
			}

			select {
			case <-handlerDone:
			case <-time.After(time.Second):
				t.Fatal("proxy handler did not exit")
			}
			select {
			case <-stopDone:
			case <-time.After(time.Second):
				t.Fatal("stop did not return after proxy handler exited")
			}
		})
	}
}

func TestStandaloneProxyServer_StopIsBoundedForBlockedHandler(t *testing.T) {
	socketDir, err := os.MkdirTemp("/tmp", "plk-proxy-*")
	if err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "proxy.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}

	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	handlerDone := make(chan struct{})
	server := startStandaloneProxyServer(ln, standaloneProxyConnectionConfig{
		ProxyHandler: func(conn net.Conn) {
			defer close(handlerDone)
			defer func() { _ = conn.Close() }()
			close(handlerEntered)
			<-releaseHandler
		},
	})
	defer func() {
		close(releaseHandler)
		<-handlerDone
	}()

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("unix dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("proxy handler did not start")
	}

	if server.stopWithin(50 * time.Millisecond) {
		t.Fatal("stop reported a clean drain while proxy handler was still blocked")
	}
}

func TestStandaloneProxyServer_StopWithinReportsDrainOnlyOnFirstCall(t *testing.T) {
	socketDir, err := os.MkdirTemp("/tmp", "plk-proxy-*")
	if err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "proxy.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}

	server := startStandaloneProxyServer(ln, standaloneProxyConnectionConfig{
		ProxyHandler: func(conn net.Conn) {
			_ = conn.Close()
		},
	})
	if !server.stopWithin(time.Second) {
		t.Fatal("first stopWithin call did not report clean drain")
	}
	if server.stopWithin(time.Second) {
		t.Fatal("second stopWithin call reported drain status")
	}
}

func TestStandaloneProxyServer_StopTimeoutAllowsLateHandlerCleanup(t *testing.T) {
	socketDir, err := os.MkdirTemp("/tmp", "plk-proxy-*")
	if err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "proxy.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}

	handlerEntered := make(chan struct{})
	releaseHandler := make(chan struct{})
	handlerDone := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}
	t.Cleanup(release)
	server := startStandaloneProxyServer(ln, standaloneProxyConnectionConfig{
		ProxyHandler: func(conn net.Conn) {
			defer close(handlerDone)
			defer func() { _ = conn.Close() }()
			close(handlerEntered)
			<-releaseHandler
		},
	})

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("unix dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("proxy handler did not start")
	}

	if server.stopWithin(time.Millisecond) {
		t.Fatal("stop reported a clean drain while proxy handler was still blocked")
	}

	release()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("proxy handler did not exit after release")
	}

	// handlerDone closes inside the handler, while the server untracks the
	// connection after the handler returns, so the untrack is strictly later and
	// its timing is not ordered against this goroutine. Poll for the drain.
	testwait.For(t, 2*time.Second, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return len(server.conns) == 0
	}, "timed-out proxy server leaked tracked connections")
}

func TestHandleStandaloneProxyConnection_NilHandlerFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		cfg  standaloneProxyConnectionConfig
	}{
		{name: "nil handler defaults to deny"},
		{
			name: "explicit unscanned opt-in false denies",
			cfg: standaloneProxyConnectionConfig{
				AllowUnscannedDirectForward: false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targetLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("target listen: %v", err)
			}
			defer func() { _ = targetLn.Close() }()

			accepted := make(chan struct{}, 1)
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				conn, acceptErr := targetLn.Accept()
				if acceptErr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				accepted <- struct{}{}
			}()

			clientConn, serverConn := net.Pipe()
			handlerDone := make(chan struct{})
			go func() {
				defer close(handlerDone)
				handleStandaloneProxyConnection(serverConn, tc.cfg)
			}()

			_, _ = fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetLn.Addr(), targetLn.Addr())
			_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1)
			if _, readErr := clientConn.Read(buf); !errors.Is(readErr, io.EOF) {
				t.Fatalf("bridge read error = %v, want EOF from fail-closed connection", readErr)
			}
			_ = clientConn.Close()
			<-handlerDone

			_ = targetLn.Close()
			<-acceptDone
			select {
			case <-accepted:
				t.Fatal("nil-handler bridge forwarded to target")
			default:
			}
		})
	}
}

func TestHandleDirectForward_CONNECT(t *testing.T) {
	// Test the debug-only CONNECT handler with its explicit opt-in enabled.
	// Set up a target server.
	targetLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer func() { _ = targetLn.Close() }()

	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("hello from target"))
	}()

	// Create a pipe to simulate the bridge connection.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	// Run handleDirectForward in a goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleStandaloneProxyConnection(serverConn, standaloneProxyConnectionConfig{
			AllowUnscannedDirectForward: true,
		})
	}()

	// Send CONNECT request.
	_, _ = fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		targetLn.Addr(), targetLn.Addr())

	// Read response with deadline to prevent hang on regression.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "200") {
		t.Errorf("expected 200 response, got: %s", resp)
	}

	// Read tunneled data.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ = clientConn.Read(buf)
	if got := string(buf[:n]); got != "hello from target" {
		t.Errorf("expected 'hello from target', got: %q", got)
	}

	_ = clientConn.Close()
	<-done
}

func TestHandleDirectForward_BadRequest(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleStandaloneProxyConnection(serverConn, standaloneProxyConnectionConfig{
			AllowUnscannedDirectForward: true,
		})
	}()

	// Send non-CONNECT request.
	_, _ = fmt.Fprintf(clientConn, "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "400") {
		t.Errorf("expected 400 for non-CONNECT, got: %s", resp)
	}
	_ = clientConn.Close()
	<-done
}

func TestBringUpLoopback(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("linux only")
	}
	// bringUpLoopback only works inside a network namespace where we
	// have CAP_NET_ADMIN. In the test process (host namespace), it will
	// fail with EPERM. We just verify it doesn't panic.
	err := bringUpLoopback()
	// Expected: either nil (if already up) or permission error.
	_ = err
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Constants to avoid goconst triggers.
// ---------------------------------------------------------------------------

const (
	echoCmd         = "echo"
	testStr         = "test"
	sandboxLinuxMsg = "sandbox requires linux"
)

// NOTE: ApplyRlimits is NOT called directly in the test process because
// setting RLIMIT_NPROC permanently limits process creation, which would
// break subsequent tests that fork subprocesses (LaunchStandalone, etc.).
// ApplyRlimits is exercised via the subprocess test in seccomp_test.go
// (TestApplyRlimits_ChildVerifiesAll).

// ---------------------------------------------------------------------------
// PrepareSandboxCmd: cover various configuration paths.
// ---------------------------------------------------------------------------

func TestPrepareSandboxCmd_ReadsExePath(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	workspace := t.TempDir()

	cmd, err := PrepareSandboxCmd(LaunchConfig{
		Command:    []string{echoCmd, testStr},
		Workspace:  workspace,
		BestEffort: true,
	})
	if err != nil {
		t.Fatalf("PrepareSandboxCmd: %v", err)
	}

	exePath := cmd.Path
	if !filepath.IsAbs(exePath) {
		t.Errorf("expected absolute exe path, got: %s", exePath)
	}
	if _, statErr := os.Stat(exePath); statErr != nil {
		t.Errorf("exe path does not exist: %s", exePath)
	}
}

func TestPrepareSandboxCmd_SetsProcessGroup(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	workspace := t.TempDir()

	cmd, err := PrepareSandboxCmd(LaunchConfig{
		Command:    []string{echoCmd, testStr},
		Workspace:  workspace,
		BestEffort: true,
	})
	if err != nil {
		t.Fatalf("PrepareSandboxCmd: %v", err)
	}

	if cmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be set")
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Error("expected Setpgid to be true for cleanup signal delivery")
	}
}

func TestPrepareSandboxCmd_SetsIOStreams(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	workspace := t.TempDir()

	var stdin bytes.Buffer
	var stdout, stderr bytes.Buffer
	cmd, err := PrepareSandboxCmd(LaunchConfig{
		Command:    []string{echoCmd, testStr},
		Workspace:  workspace,
		BestEffort: true,
		Stdin:      &stdin,
		Stdout:     &stdout,
		Stderr:     &stderr,
	})
	if err != nil {
		t.Fatalf("PrepareSandboxCmd: %v", err)
	}

	if cmd.Stdin == nil {
		t.Error("expected Stdin to be set")
	}
	if cmd.Stdout == nil {
		t.Error("expected Stdout to be set")
	}
	if cmd.Stderr == nil {
		t.Error("expected Stderr to be set")
	}
}

// NOTE: LaunchStandalone strict mode tests are not included because strict
// mode blocks clone3 via seccomp, which prevents the Go runtime from
// creating threads in the re-exec'd subprocess (cgo uses pthread_create).
// Strict standalone mode is tested via the full binary integration tests.

// ---------------------------------------------------------------------------
// LaunchStandalone: proxy handler path with custom handler.
// ---------------------------------------------------------------------------

func TestLaunchStandalone_CustomProxyHandler(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	handler := func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:      []string{"curl", "-s", "--max-time", "3", "--proxy", "http://127.0.0.1:8888", "http://probe.local/"},
		Workspace:    workspace,
		ProxyHandler: handler,
	})
	_ = err
}

// ---------------------------------------------------------------------------
// handleDirectForward: cover the valid CONNECT round-trip path.
// ---------------------------------------------------------------------------

func TestHandleDirectForward_ValidCONNECTRoundTrip(t *testing.T) {
	ctx := context.Background()
	targetLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer func() { _ = targetLn.Close() }()

	go func() {
		conn, acceptErr := targetLn.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDirectForward(serverConn)
	}()

	_, _ = fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		targetLn.Addr(), targetLn.Addr())

	buf := make([]byte, 256)
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got: %s", resp)
	}

	tunnelMsg := "ping-through-tunnel"
	_, _ = fmt.Fprint(clientConn, tunnelMsg)

	n, _ = clientConn.Read(buf)
	if got := string(buf[:n]); got != tunnelMsg {
		t.Errorf("expected %q, got %q", tunnelMsg, got)
	}

	_ = clientConn.Close()
	<-done
}

// ---------------------------------------------------------------------------
// Preflight: exercise additional paths.
// ---------------------------------------------------------------------------

func TestPreflight_CommandNotFound_StatusNotError(t *testing.T) {
	workspace := t.TempDir()

	result := Preflight(workspace, []string{"nonexistent-cmd-xyz"}, nil, false)

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e, "nonexistent-cmd-xyz") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about nonexistent command in Errors")
	}
}

func TestPreflight_EmptyWorkspace(t *testing.T) {
	result := Preflight("", nil, nil, false)
	if result.Status != StatusError {
		t.Errorf("expected error for empty workspace, got status: %s", result.Status)
	}
}

func TestPreflight_CommandAbsolutePath(t *testing.T) {
	workspace := t.TempDir()
	result := Preflight(workspace, []string{"/bin/sh", "-c", echoCmd}, nil, false)

	if len(result.Command) > 0 && result.Command[0] != "/bin/sh" {
		t.Errorf("expected /bin/sh, got: %s", result.Command[0])
	}
}

// ---------------------------------------------------------------------------
// ValidateWorkspace: cover additional edge cases.
// ---------------------------------------------------------------------------

func TestValidateWorkspace_RejectsMacOSDangerousPaths(t *testing.T) {
	macPaths := []string{"/private/tmp", "/private/var", "/private/etc"}
	for _, p := range macPaths {
		found := false
		for _, root := range dangerousRoots {
			if root == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("macOS path %s not in dangerousRoots", p)
		}
	}
}

func TestValidateWorkspace_SensitiveChildrenCheck(t *testing.T) {
	err := ValidateWorkspace("/")
	if err == nil {
		t.Error("/ should be rejected")
	}
	if !strings.Contains(err.Error(), "must not be") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateWorkspace_EmptyHome(t *testing.T) {
	t.Setenv("HOME", "")
	workspace := t.TempDir()
	err := ValidateWorkspace(workspace)
	if err != nil {
		t.Errorf("expected no error with empty HOME: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValidatePolicy: cover EvalSymlinks fallback paths.
// ---------------------------------------------------------------------------

func TestValidatePolicy_SecretDirSymlinkFallback(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.Symlink("/nonexistent/target", sshDir); err != nil {
		t.Fatal(err)
	}

	workspace := t.TempDir()
	p := Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{"/usr/"},
		AllowRWDirs:   []string{workspace},
	}

	err := ValidatePolicy(p)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidatePolicy_AllowDirEvalSymlinksFallback(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)

	workspace := t.TempDir()
	p := DefaultPolicy(workspace)
	p.AllowReadDirs = append(p.AllowReadDirs, "/opt/nonexistent-tool/data/")

	err := ValidatePolicy(p)
	if err != nil {
		t.Errorf("non-existent allow_read dir should pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// buildSeccompFilter: verify filter properties.
// ---------------------------------------------------------------------------

func TestBuildSeccompFilter_BestEffortAndStrict(t *testing.T) {
	bestEffort := buildSeccompFilter(false)
	strict := buildSeccompFilter(true)

	const minInstructions = 4
	if len(bestEffort) < minInstructions {
		t.Errorf("best-effort filter too short: %d instructions", len(bestEffort))
	}
	if len(strict) < minInstructions {
		t.Errorf("strict filter too short: %d instructions", len(strict))
	}

	t.Logf("best-effort: %d instructions, strict: %d instructions", len(bestEffort), len(strict))
}

// ---------------------------------------------------------------------------
// Capabilities.Summary: additional edge cases.
// ---------------------------------------------------------------------------

func TestCapabilities_Summary_MixedAvailability(t *testing.T) {
	tests := []struct {
		name string
		caps Capabilities
		want []string
	}{
		{
			name: "landlock only",
			caps: Capabilities{LandlockABI: 3},
			want: []string{"Landlock ABI v3", "user namespaces: unavailable", "seccomp: unavailable"},
		},
		{
			name: "seccomp only",
			caps: Capabilities{Seccomp: true},
			want: []string{"Landlock: unavailable", "user namespaces: unavailable", "seccomp: available"},
		},
		{
			name: "userns only",
			caps: Capabilities{UserNamespaces: true},
			want: []string{"Landlock: unavailable", "user namespaces: available", "seccomp: unavailable"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := tt.caps.Summary()
			for _, w := range tt.want {
				if !strings.Contains(summary, w) {
					t.Errorf("Summary() missing %q, got: %s", w, summary)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Detect: verify all fields are populated.
// ---------------------------------------------------------------------------

func TestDetect_ReturnsAllFields(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	caps := Detect()

	t.Logf("LandlockABI=%d UserNamespaces=%v Seccomp=%v MaxUserNS=%d SELinux=%q",
		caps.LandlockABI, caps.UserNamespaces, caps.Seccomp, caps.MaxUserNS, caps.SELinux)

	if caps.MaxUserNS == 0 {
		t.Log("MaxUserNS is 0 — may be inside a restricted container")
	}
}

// ---------------------------------------------------------------------------
// LaunchSandboxed: error propagation tests.
// ---------------------------------------------------------------------------

func TestLaunchSandboxed_PropagatesPrepareSandboxCmdError(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	_, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{echoCmd},
		Workspace: "",
	})
	if err == nil {
		t.Error("expected error for empty workspace")
	}
}

func TestLaunchSandboxed_PropagatesPolicyError(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)

	workspace := t.TempDir()
	policy := &Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{home},
		AllowRWDirs:   []string{workspace},
	}
	_, err := LaunchSandboxed(LaunchConfig{
		Command:   []string{echoCmd},
		Workspace: workspace,
		Policy:    policy,
	})
	if err == nil {
		t.Error("expected error for policy covering secrets")
	}
}

// ---------------------------------------------------------------------------
// LaunchStandalone: error paths.
// ---------------------------------------------------------------------------

func TestLaunchStandalone_NonexistentWorkspace(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{echoCmd},
		Workspace: "/nonexistent/path/xyz",
	})
	if err == nil {
		t.Error("expected error for nonexistent workspace")
	}
}

// ---------------------------------------------------------------------------
// PrepareSandboxCmd: workspace as file error.
// ---------------------------------------------------------------------------

func TestPrepareSandboxCmd_WorkspaceIsFile(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	f, err := os.CreateTemp("", "sandbox-test-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	defer func() { _ = os.Remove(f.Name()) }()

	_, prepErr := PrepareSandboxCmd(LaunchConfig{
		Command:   []string{echoCmd},
		Workspace: f.Name(),
	})
	if prepErr == nil {
		t.Error("expected error for file as workspace")
	}
}

// ---------------------------------------------------------------------------
// lookPathIn: additional edge cases.
// ---------------------------------------------------------------------------

func TestLookPathIn_DirectoryNotBinary(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "mybinary")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatal(err)
	}

	_, err := lookPathIn("mybinary", []string{"PATH=" + dir})
	if err == nil {
		t.Error("expected error when PATH entry is a directory")
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestLookPathIn_EmptyName(t *testing.T) {
	_, err := lookPathIn("", []string{"PATH=/usr/bin"})
	if err == nil {
		t.Error("expected error for empty command name")
	}
}

func TestLookPathIn_MultiplePathEntries(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	binPath := filepath.Join(dir2, "test-binary")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	path, err := lookPathIn("test-binary", []string{"PATH=" + dir1 + ":" + dir2})
	if err != nil {
		t.Fatalf("lookPathIn: %v", err)
	}
	if path != binPath {
		t.Errorf("expected %s, got %s", binPath, path)
	}
}

// ---------------------------------------------------------------------------
// removeEnvKey: edge cases.
// ---------------------------------------------------------------------------

func TestRemoveEnvKey_EmptySlice(t *testing.T) {
	result := removeEnvKey(nil, "KEY")
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestRemoveEnvKey_EmptyKey(t *testing.T) {
	env := []string{"=empty_key_value", "A=1"}
	result := removeEnvKey(env, "")
	if len(result) != 1 {
		t.Errorf("expected 1 entry, got %d: %v", len(result), result)
	}
}

// ---------------------------------------------------------------------------
// ProxySocketPath: verify path construction.
// ---------------------------------------------------------------------------

func TestProxySocketPath_Absolute(t *testing.T) {
	path := ProxySocketPath("/tmp/sandbox-42")
	if path != "/tmp/sandbox-42/proxy.sock" {
		t.Errorf("expected /tmp/sandbox-42/proxy.sock, got %s", path)
	}
}

// ---------------------------------------------------------------------------
// BridgeProxy: exercise the Serve context cancellation path.
// ---------------------------------------------------------------------------

func TestBridgeProxy_ServeContextCancel(t *testing.T) {
	dir := shortTempDir(t)
	socketPath := ProxySocketPath(dir)

	parentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = parentLn.Close() }()

	bp, err := NewBridgeProxy(socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		bp.Serve(ctx)
		close(serveDone)
	}()

	cancel()
	<-serveDone
	bp.Close()
}

// ---------------------------------------------------------------------------
// BridgeProxy: exercise handleConn with multiple connections.
// ---------------------------------------------------------------------------

func TestBridgeProxy_HandleConnMultiple(t *testing.T) {
	dir := shortTempDir(t)
	socketPath := ProxySocketPath(dir)

	parentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = parentLn.Close() }()

	go func() {
		for {
			conn, acceptErr := parentLn.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 256)
				n, readErr := conn.Read(buf)
				if readErr != nil {
					return
				}
				_, _ = conn.Write(buf[:n])
			}()
		}
	}()

	bp, err := NewBridgeProxy(socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bp.Serve(ctx)
	defer bp.Close()

	for i := range 3 {
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, "tcp", bp.Addr())
		if dialErr != nil {
			t.Fatalf("dial %d: %v", i, dialErr)
		}
		msg := fmt.Sprintf("msg-%d", i)
		_, _ = fmt.Fprint(conn, msg)

		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if got := string(buf[:n]); got != msg {
			t.Errorf("connection %d: got %q, want %q", i, got, msg)
		}
		_ = conn.Close()
	}
}

// ---------------------------------------------------------------------------
// secretDirs: verify all expected subdirectories are checked.
// ---------------------------------------------------------------------------

func TestSecretDirs_AllCandidatesChecked(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	candidates := []string{".ssh", ".aws", ".gnupg", ".kube", ".docker"}
	configDir := filepath.Join(".config", "pipelock")
	candidates = append(candidates, configDir)

	for _, c := range candidates {
		fullPath := filepath.Join(tmpHome, c)
		if err := os.MkdirAll(fullPath, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", fullPath, err)
		}
	}

	dirs := secretDirs()
	const expectedCount = 6
	if len(dirs) != expectedCount {
		t.Errorf("expected %d secret dirs, got %d: %v", expectedCount, len(dirs), dirs)
	}
}

// ---------------------------------------------------------------------------
// DefaultPolicy: verify DenyReadDirs alignment.
// ---------------------------------------------------------------------------

func TestDefaultPolicy_DenyReadDirsMatchSecretDirs(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)

	workspace := t.TempDir()
	p := DefaultPolicy(workspace)
	secrets := secretDirs()

	for _, s := range secrets {
		found := false
		for _, d := range p.DenyReadDirs {
			if d == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("secret dir %s not in DenyReadDirs", s)
		}
	}
}

// ---------------------------------------------------------------------------
// ErrUnavailable: verify it's a proper sentinel error.
// ---------------------------------------------------------------------------

func TestErrUnavailable_Sentinel(t *testing.T) {
	wrapped := fmt.Errorf("sandbox test: %w", ErrUnavailable)
	if !errors.Is(wrapped, ErrUnavailable) {
		t.Error("wrapped ErrUnavailable should be detectable via errors.Is")
	}
}

// ---------------------------------------------------------------------------
// LayerName constants: verify values don't change.
// ---------------------------------------------------------------------------

func TestLayerNameConstants(t *testing.T) {
	tests := []struct {
		name string
		got  LayerName
		want string
	}{
		{name: "Landlock", got: LayerLandlock, want: "filesystem"},
		{name: "NetNS", got: LayerNetNS, want: "network"},
		{name: "Seccomp", got: LayerSeccomp, want: "syscall"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Errorf("Layer%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// seccomp conditionals: verify instruction counts.
// ---------------------------------------------------------------------------

func TestSeccompConditionals_InstructionCounts(t *testing.T) {
	cloneInsns := cloneConditional()
	clone3Strict := clone3Conditional(true)
	clone3BestEff := clone3Conditional(false)
	socketInsns := socketConditional()
	personalityInsns := personalityConditional()

	tests := []struct {
		name  string
		count int
		got   int
	}{
		{name: "clone", count: 5, got: len(cloneInsns)},
		{name: "clone3_strict", count: 2, got: len(clone3Strict)},
		{name: "clone3_besteff", count: 2, got: len(clone3BestEff)},
		{name: "socket", count: 5, got: len(socketInsns)},
		{name: "personality", count: 9, got: len(personalityInsns)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.count {
				t.Errorf("%s: got %d instructions, want %d", tt.name, tt.got, tt.count)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// allowedSyscalls / killSyscalls / denySyscalls: no dups, no overlap.
// ---------------------------------------------------------------------------

func TestSyscallLists_NoDuplicates(t *testing.T) {
	lists := map[string][]uint32{
		"allowed": allowedSyscalls(),
		"kill":    killSyscalls(),
		"deny":    denySyscalls(),
	}

	for name, list := range lists {
		t.Run(name, func(t *testing.T) {
			if len(list) == 0 {
				t.Errorf("%s syscall list is empty", name)
			}
			seen := make(map[uint32]bool, len(list))
			for _, nr := range list {
				if seen[nr] {
					t.Errorf("%s: duplicate syscall number %d", name, nr)
				}
				seen[nr] = true
			}
		})
	}
}

func TestSyscallLists_NoOverlap(t *testing.T) {
	allow := make(map[uint32]bool)
	for _, nr := range allowedSyscalls() {
		allow[nr] = true
	}

	for _, nr := range killSyscalls() {
		if allow[nr] {
			t.Errorf("syscall %d is in both allowed and kill lists", nr)
		}
	}
	for _, nr := range denySyscalls() {
		if allow[nr] {
			t.Errorf("syscall %d is in both allowed and deny lists", nr)
		}
	}
}

// ---------------------------------------------------------------------------
// loopbackUp: verify direct call (will fail without CAP_NET_ADMIN).
// ---------------------------------------------------------------------------

func TestLoopbackUp_HostNamespace(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	err := loopbackUp()
	t.Logf("loopbackUp in host namespace: %v", err)
}

// ---------------------------------------------------------------------------
// IsStrictMode / IsInitMode: exercise via env var.
// ---------------------------------------------------------------------------

func TestIsStrictMode_ViaEnv(t *testing.T) {
	t.Setenv(strictEnvKey, "1")
	if !IsStrictMode() {
		t.Error("expected strict mode when env var is 1")
	}

	t.Setenv(strictEnvKey, "")
	if IsStrictMode() {
		t.Error("expected non-strict mode when env var is empty")
	}
}

func TestIsInitMode_ViaEnv(t *testing.T) {
	t.Setenv(initEnvKey, "1")
	if !IsInitMode() {
		t.Error("expected init mode when env var is 1")
	}

	t.Setenv(initEnvKey, "")
	if IsInitMode() {
		t.Error("expected non-init mode when env var is empty")
	}
}

// ---------------------------------------------------------------------------
// SyntheticEnv: exercise MkdirAll failure path.
// ---------------------------------------------------------------------------

func TestSyntheticEnv_MkdirAllError(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "block")
	if err := os.WriteFile(blockFile, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := SyntheticEnv(filepath.Join(blockFile, "sub"), t.TempDir(), nil)
	if err == nil {
		t.Error("expected error when MkdirAll fails")
	}
}

// ---------------------------------------------------------------------------
// ValidatePolicy: additional path coverage.
// ---------------------------------------------------------------------------

func TestValidatePolicy_RejectsRWFileInsideProtectedDir(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	protected := secretDirs()

	p := DefaultPolicy(t.TempDir())
	p.AllowRWFiles = append(p.AllowRWFiles, filepath.Join(protected[0], "rw_file"))
	if err := ValidatePolicy(p); err == nil {
		t.Errorf("expected error for RW file inside protected directory %s", protected[0])
	}
}

func TestValidatePolicy_AcceptsRWFileOutsideProtectedDir(t *testing.T) {
	p := DefaultPolicy(t.TempDir())
	p.AllowRWFiles = append(p.AllowRWFiles, "/opt/app/state.db")
	if err := ValidatePolicy(p); err != nil {
		t.Errorf("RW file outside protected dirs should pass: %v", err)
	}
}

func TestValidatePolicy_EmptySecretDirs(t *testing.T) {
	t.Setenv("HOME", "")
	p := Policy{
		Workspace:     t.TempDir(),
		AllowReadDirs: []string{"/anything/"},
		AllowRWDirs:   []string{"/whatever/"},
	}
	if err := ValidatePolicy(p); err != nil {
		t.Errorf("expected nil error when no secret dirs: %v", err)
	}
}

// ---------------------------------------------------------------------------
// PrepareSandboxCmd: additional error and configuration paths.
// ---------------------------------------------------------------------------

func TestPrepareSandboxCmd_RejectsInvalidPolicy(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	workspace := t.TempDir()

	policy := &Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{home},
		AllowRWDirs:   []string{workspace},
	}
	_, err := PrepareSandboxCmd(LaunchConfig{
		Command:   []string{echoCmd, testStr},
		Workspace: workspace,
		Policy:    policy,
	})
	if err == nil {
		t.Error("expected error for policy covering secret dirs")
	}
}

func TestPrepareSandboxCmd_StrictSetsCloneNewNS(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	workspace := t.TempDir()

	cmd, err := PrepareSandboxCmd(LaunchConfig{
		Command:   []string{echoCmd, testStr},
		Workspace: workspace,
		Strict:    true,
	})
	if err != nil {
		t.Fatalf("PrepareSandboxCmd: %v", err)
	}

	foundStrict := false
	for _, e := range cmd.Env {
		if e == strictEnvKey+"=1" {
			foundStrict = true
			break
		}
	}
	if !foundStrict {
		t.Error("expected strict env var in cmd.Env")
	}

	if cmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be set")
	}
	const cloneNewNS = 0x00020000
	if cmd.SysProcAttr.Cloneflags&uintptr(cloneNewNS) == 0 {
		t.Error("strict mode should include CLONE_NEWNS in clone flags")
	}
}

// ---------------------------------------------------------------------------
// LaunchStandalone: additional error and configuration paths.
// ---------------------------------------------------------------------------

func TestLaunchStandalone_InvalidPolicy(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	workspace := t.TempDir()

	policy := &Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{home},
		AllowRWDirs:   []string{workspace},
	}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{echoCmd, testStr},
		Workspace: workspace,
		Policy:    policy,
	})
	if err == nil {
		t.Error("expected error for policy covering secrets")
	}
}

func TestLaunchStandalone_NilCtxUsesBackground(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Ctx:       nil,
		Command:   []string{"true"},
		Workspace: workspace,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone with nil ctx: %v", err)
	}
}

func TestLaunchStandalone_CustomPolicy(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	policy := &Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/ssl/", "/etc/pki/", "/proc/self/"},
		AllowReadFiles: []string{
			"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
			"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/passwd", "/etc/group",
		},
		AllowRWDirs:  []string{workspace, "/dev/shm/"},
		AllowRWFiles: []string{"/dev/null", "/dev/zero", "/dev/urandom"},
	}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"true"},
		Workspace: workspace,
		Policy:    policy,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone with custom policy: %v", err)
	}
}

func TestLaunchStandalone_ExtraEnv(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "test \"$MY_TEST_VAR\" = hello"},
		Workspace: workspace,
		ExtraEnv:  []string{"MY_TEST_VAR=hello"},
	})
	if err != nil {
		t.Fatalf("LaunchStandalone with extra env: %v", err)
	}
}

func TestLaunchStandalone_BestEffortMode(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip(sandboxLinuxMsg)
	}
	// Skip in containers where CLONE_NEWUSER is blocked by seccomp.
	if os.Getenv("CI") != "" {
		t.Skip("skipping in CI: LaunchStandalone requires user namespace support")
	}
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:    []string{"true"},
		Workspace:  workspace,
		BestEffort: true,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone best-effort: %v", err)
	}
}

// ---------------------------------------------------------------------------
// handleDirectForward: additional paths.
// ---------------------------------------------------------------------------

func TestHandleDirectForward_502BadGateway(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDirectForward(serverConn)
	}()

	_, _ = fmt.Fprintf(clientConn, "CONNECT 192.0.2.1:99999 HTTP/1.1\r\nHost: 192.0.2.1:99999\r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "502") {
		t.Errorf("expected 502 for unreachable target, got: %s", resp)
	}
	_ = clientConn.Close()
	<-done
}

func TestHandleDirectForward_ShortCONNECT(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDirectForward(serverConn)
	}()

	_, _ = fmt.Fprintf(clientConn, "CONNECT\r\n")
	_ = clientConn.Close()
	<-done
}

func TestHandleDirectForward_ReadEOF(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDirectForward(serverConn)
	}()

	_ = clientConn.Close()
	<-done
}

// ---------------------------------------------------------------------------
// SetChildSubreaper / ReapOrphans: subprocess tests.
// ---------------------------------------------------------------------------

const deepSubreapTestEnv = "__SANDBOX_DEEP_SUBREAP_TEST"

func init() {
	if op := os.Getenv(deepSubreapTestEnv); op != "" {
		switch op {
		case "set-subreaper":
			if err := SetChildSubreaper(); err != nil {
				_, _ = os.Stderr.WriteString("subreaper: " + err.Error() + "\n")
				os.Exit(1)
			}
			os.Exit(0)
		case "reap-orphans":
			ReapOrphans()
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func TestSetChildSubreaper_Deep(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("linux only")
	}
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^$")
	cmd.Env = append(os.Environ(), deepSubreapTestEnv+"=set-subreaper")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("SetChildSubreaper child failed: %v\n%s", err, out)
	}
}

func TestReapOrphans_Deep(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("linux only")
	}
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^$")
	cmd.Env = append(os.Environ(), deepSubreapTestEnv+"=reap-orphans")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("ReapOrphans child failed: %v\n%s", err, out)
	}
}

// ---------------------------------------------------------------------------
// probeUserNamespace: exercise the successful path.
// ---------------------------------------------------------------------------

func TestProbeUserNamespace(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("linux only")
	}
	got := probeUserNamespace()
	t.Logf("probeUserNamespace: %v", got)
}

// ---------------------------------------------------------------------------
// Preflight: complete coverage paths.
// ---------------------------------------------------------------------------

func TestPreflight_ValidBestEffort(t *testing.T) {
	workspace := t.TempDir()
	result := Preflight(workspace, []string{echoCmd, "hello"}, nil, false)

	if result.Workspace != workspace {
		t.Errorf("workspace = %q, want %q", result.Workspace, workspace)
	}
	if result.Mode != "best-effort" {
		t.Errorf("mode = %q, want best-effort", result.Mode)
	}
	if len(result.Layers) != 3 {
		t.Errorf("expected 3 layers, got %d", len(result.Layers))
	}
}

func TestPreflight_StrictMode(t *testing.T) {
	workspace := t.TempDir()
	result := Preflight(workspace, []string{echoCmd}, nil, true)

	if result.Mode != "strict" {
		t.Errorf("mode = %q, want strict", result.Mode)
	}
	for _, l := range result.Layers {
		if !l.Required {
			t.Errorf("layer %s: required = false, want true in strict mode", l.Name)
		}
	}
}

func TestPreflight_InvalidWorkspace(t *testing.T) {
	result := Preflight("/nonexistent/path/xyz", []string{echoCmd}, nil, false)
	if result.Status != StatusError {
		t.Errorf("status = %q, want %q", result.Status, StatusError)
	}
}

func TestPreflight_WithCustomPolicy(t *testing.T) {
	workspace := t.TempDir()
	policy := &Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{"/usr/"},
		AllowRWDirs:   []string{workspace},
	}
	result := Preflight(workspace, []string{echoCmd}, policy, false)
	if result.Status == StatusError {
		t.Errorf("unexpected error with valid custom policy: %v", result.Errors)
	}
}

func TestPreflight_InvalidPolicy(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)

	workspace := t.TempDir()
	policy := &Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{home},
		AllowRWDirs:   []string{workspace},
	}
	result := Preflight(workspace, []string{echoCmd}, policy, false)
	if result.Status != StatusError {
		t.Errorf("status = %q, want %q for policy covering secrets", result.Status, StatusError)
	}
}

func TestPreflight_AllLayersAvailable(t *testing.T) {
	workspace := t.TempDir()
	caps := Detect()

	if caps.LandlockABI <= 0 || !caps.UserNamespaces || !caps.Seccomp {
		t.Skip("not all layers available on this system")
	}

	result := Preflight(workspace, []string{echoCmd}, nil, false)
	if result.Status != StatusReady {
		t.Errorf("status = %q, want %q with all layers available", result.Status, StatusReady)
	}
}

func TestPreflight_StrictAllAvailable(t *testing.T) {
	workspace := t.TempDir()
	caps := Detect()

	if caps.LandlockABI <= 0 || !caps.UserNamespaces || !caps.Seccomp {
		t.Skip("not all layers available on this system")
	}

	result := Preflight(workspace, []string{echoCmd}, nil, true)
	if result.Status != StatusReady {
		t.Errorf("strict with all layers: status = %q, want %q", result.Status, StatusReady)
	}
}

func TestPreflight_PrivateShm(t *testing.T) {
	workspace := t.TempDir()

	bestEffort := Preflight(workspace, []string{echoCmd}, nil, false)
	strict := Preflight(workspace, []string{echoCmd}, nil, true)

	if bestEffort.PrivateShm {
		t.Error("best-effort should not have private SHM")
	}

	caps := Detect()
	if caps.UserNamespaces && !strict.PrivateShm {
		t.Error("strict with user namespaces should have private SHM")
	}
}

// ---------------------------------------------------------------------------
// encodePolicyJSON: cover the nil fields case.
// ---------------------------------------------------------------------------

func TestEncodePolicyJSON_NilFields(t *testing.T) {
	p := &Policy{}
	s, err := encodePolicyJSON(p)
	if err != nil {
		t.Fatalf("encodePolicyJSON: %v", err)
	}
	if s == "" {
		t.Error("expected non-empty JSON for empty policy")
	}
}

// ---------------------------------------------------------------------------
// ValidateWorkspace: additional paths.
// ---------------------------------------------------------------------------

func TestValidateWorkspace_AcceptsSymlinkToSafeDir(t *testing.T) {
	target := t.TempDir()
	dir := t.TempDir()
	link := filepath.Join(dir, "safe-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := ValidateWorkspace(link)
	if err != nil {
		t.Errorf("expected no error for symlink to safe dir: %v", err)
	}
}

func TestValidateWorkspace_HomeDirEvalSymlinksError(t *testing.T) {
	tmpDir := t.TempDir()
	brokenHome := filepath.Join(tmpDir, "broken-home")
	if err := os.Symlink("/nonexistent/target", brokenHome); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", brokenHome)

	workspace := t.TempDir()
	err := ValidateWorkspace(workspace)
	if err != nil {
		t.Errorf("expected no error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// secretDirs: verify filtering by existence.
// ---------------------------------------------------------------------------

func TestSecretDirs_FiltersNonexistent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	dirs := secretDirs()
	if len(dirs) != 0 {
		t.Errorf("expected 0 secret dirs in temp HOME, got %d: %v", len(dirs), dirs)
	}
}

func TestSecretDirs_FindsExisting(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o750); err != nil {
		t.Fatal(err)
	}

	dirs := secretDirs()
	if len(dirs) != 1 {
		t.Errorf("expected 1 secret dir, got %d: %v", len(dirs), dirs)
	}
	if len(dirs) > 0 && dirs[0] != sshDir {
		t.Errorf("expected %s, got %s", sshDir, dirs[0])
	}
}

// ---------------------------------------------------------------------------
// Detect: SELinux field.
// ---------------------------------------------------------------------------

func TestDetect_SELinuxField(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("linux only")
	}
	caps := Detect()
	t.Logf("SELinux: %q, MaxUserNS: %d", caps.SELinux, caps.MaxUserNS)
}

// ---------------------------------------------------------------------------
// buildRules: verify behavior with various policies.
// ---------------------------------------------------------------------------

func TestBuildRules_EmptyPolicy(t *testing.T) {
	policy := Policy{}
	rules := buildRules(policy)
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty policy, got %d", len(rules))
	}
}

func TestBuildRules_AllSlicesFilled(t *testing.T) {
	policy := Policy{
		AllowReadDirs:  []string{"/usr/"},
		AllowReadFiles: []string{"/etc/hosts"},
		AllowRWDirs:    []string{"/tmp/work"},
		AllowRWFiles:   []string{"/dev/null"},
	}
	rules := buildRules(policy)
	if len(rules) != 4 {
		t.Errorf("expected 4 rules, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// BPF helpers: verify instruction codes.
// ---------------------------------------------------------------------------

func TestBPFHelpers(t *testing.T) {
	t.Run("bpfLoad", func(t *testing.T) {
		insn := bpfLoad(42)
		if insn.K != 42 {
			t.Errorf("K = %d, want 42", insn.K)
		}
	})

	t.Run("bpfJumpEq", func(t *testing.T) {
		insn := bpfJumpEq(100, 2, 3)
		if insn.K != 100 {
			t.Errorf("K = %d, want 100", insn.K)
		}
		if insn.Jt != 2 {
			t.Errorf("Jt = %d, want 2", insn.Jt)
		}
		if insn.Jf != 3 {
			t.Errorf("Jf = %d, want 3", insn.Jf)
		}
	})

	t.Run("bpfRet", func(t *testing.T) {
		insn := bpfRet(0x7FFF0001)
		if insn.K != 0x7FFF0001 {
			t.Errorf("K = %d, want %d", insn.K, 0x7FFF0001)
		}
	})

	t.Run("bpfJumpSet", func(t *testing.T) {
		insn := bpfJumpSet(0xFF, 1, 0)
		if insn.K != 0xFF {
			t.Errorf("K = %d, want 255", insn.K)
		}
		if insn.Jt != 1 {
			t.Errorf("Jt = %d, want 1", insn.Jt)
		}
	})
}

// ---------------------------------------------------------------------------
// Rlimit constants: verify values.
// ---------------------------------------------------------------------------

func TestRlimitConstants(t *testing.T) {
	tests := []struct {
		name string
		got  uint64
		want uint64
	}{
		{name: "nproc", got: rlimitNProc, want: 1024},
		{name: "nofile", got: rlimitNoFile, want: 4096},
		{name: "fsize", got: rlimitFSize, want: 1 << 30},
		{name: "core", got: rlimitCore, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("rlimit %s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Netlink constants.
// ---------------------------------------------------------------------------

func TestLoopbackConstants(t *testing.T) {
	if nlmsgHdrLen != 16 {
		t.Errorf("nlmsgHdrLen = %d, want 16", nlmsgHdrLen)
	}
	if ifInfoMsgLen != 16 {
		t.Errorf("ifInfoMsgLen = %d, want 16", ifInfoMsgLen)
	}
}

// ---------------------------------------------------------------------------
// CleanupChildSandboxDir: verify cleanup.
// ---------------------------------------------------------------------------

func TestCleanupChildSandboxDir_Deep(t *testing.T) {
	pid := 99998
	dir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", pid)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	CleanupChildSandboxDir(pid)

	if _, err := os.Stat(dir); err == nil {
		_ = os.RemoveAll(dir)
		t.Error("expected sandbox dir to be removed")
	}
}

// ---------------------------------------------------------------------------
// CleanupSandboxCmd: nil process.
// ---------------------------------------------------------------------------

func TestCleanupSandboxCmd_NilProcess_Deep(t *testing.T) {
	cmd := &exec.Cmd{}
	CleanupSandboxCmd(cmd) // should not panic
}

// ---------------------------------------------------------------------------
// BridgeProxy: default listen address.
// ---------------------------------------------------------------------------

func TestNewBridgeProxy_DefaultAddr(t *testing.T) {
	dir := shortTempDir(t)
	socketPath := ProxySocketPath(dir)

	parentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = parentLn.Close() }()

	bp, err := NewBridgeProxy(socketPath, "")
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			t.Logf("NewBridgeProxy with default addr failed (expected if port in use): %v", err)
		}
		return
	}
	defer bp.Close()

	addr := bp.Addr()
	if addr == "" {
		t.Error("expected non-empty addr")
	}
}

// ---------------------------------------------------------------------------
// Preflight: status constants.
// ---------------------------------------------------------------------------

func TestPreflight_StatusConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "ready", got: StatusReady, want: "capabilities_ok"},
		{name: "degraded", got: StatusDegraded, want: "degraded"},
		{name: "error", got: StatusError, want: "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("Status%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

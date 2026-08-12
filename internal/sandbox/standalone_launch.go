// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// standaloneProxyConnectionConfig controls how one accepted bridge connection
// is dispatched. Unscanned forwarding is an internal debug-only opt-in whose
// zero value is fail closed.
type standaloneProxyConnectionConfig struct {
	ProxyHandler                func(net.Conn)
	AllowUnscannedDirectForward bool
}

// LaunchStandalone runs a command in a full sandbox with network traffic
// routed through pipelock's scanner via a Unix domain socket bridge.
//
// Architecture:
//  1. Parent creates Unix socket proxy at /tmp/pipelock-sandbox-<pid>/proxy.sock
//  2. Parent forks child in new user+net namespace
//  3. Child applies Landlock + seccomp + rlimits
//  4. Child starts bridge proxy on loopback (127.0.0.1:8888)
//  5. Child runs agent command with HTTP_PROXY pointing to bridge
//  6. Agent traffic: loopback → bridge → Unix socket → parent proxy → scanner → internet
//
// When BestEffort is true and namespaces are unavailable, step 2 skips
// namespace creation. Network scanning still works via HTTP_PROXY routing
// but is not kernel-enforced (cooperative, not mandatory).
//
// Returns when the agent command exits.
func LaunchStandalone(cfg StandaloneLaunchConfig) error {
	if runtime.GOOS != osLinux {
		return fmt.Errorf("%w: sandbox requires Linux", ErrUnavailable)
	}
	if len(cfg.Command) == 0 || cfg.Command[0] == "" {
		return errors.New("sandbox: command is required")
	}
	if cfg.RequireProxyHandler && cfg.ProxyHandler == nil {
		return errors.New("sandbox: proxy handler is required")
	}
	if cfg.RequireNetNS && cfg.BestEffort {
		return errors.New("sandbox: network namespace is required; best_effort is not permitted")
	}
	if cfg.UseDeveloperEnvironment && cfg.DeveloperEnvironment == nil {
		return errors.New("sandbox: developer environment is required when enabled")
	}
	if cfg.UseDeveloperEnvironment && cfg.BestEffort {
		// Developer-environment mode forwards the caller's real credentials to
		// the final command. That is only safe when egress is kernel-mediated
		// through the network namespace: best_effort explicitly runs without a
		// namespace and relies on cooperative HTTP_PROXY variables, which an
		// agent can clear or bypass with raw sockets, turning the preserved
		// secrets into a direct exfiltration path around the bridge. Requiring a
		// namespace here (best_effort false) also makes the launch fail closed
		// when namespaces are unavailable, via the probe check below.
		return errors.New("sandbox: developer environment requires network namespace isolation; best_effort is not permitted")
	}
	if cfg.UseDeveloperEnvironment && len(cfg.ExtraEnv) > 0 {
		return errors.New("sandbox: developer environment cannot be combined with extra environment")
	}
	if cfg.GuardDeclaration != nil && cfg.GuardPolicyHash == "" {
		return errors.New("sandbox: guard policy hash is required")
	}
	var guardDeclarationJSON []byte
	if cfg.GuardDeclaration != nil {
		declaration, err := json.Marshal(cfg.GuardDeclaration)
		if err != nil {
			return fmt.Errorf("sandbox: encoding guard declaration: %w", err)
		}
		if len(declaration) > 64<<10 {
			return errors.New("sandbox: guard declaration exceeds the 64 KiB environment transport limit")
		}
		guardDeclarationJSON = declaration
	}

	if err := ValidateWorkspace(cfg.Workspace); err != nil {
		return fmt.Errorf("workspace validation: %w", err)
	}

	// Validate policy doesn't re-authorize secret directories.
	policy := DefaultPolicy(cfg.Workspace)
	if cfg.Policy != nil {
		policy = *cfg.Policy
	}
	// The standalone child re-execs this exact binary after applying the outer
	// Landlock policy. Installed binaries are normally covered by /usr or /bin,
	// but development and CI binaries commonly live in a private /tmp tree.
	// Grant only the resolved executable file, never its containing directory.
	selfExe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("reading /proc/self/exe: %w", err)
	}
	policy.AllowReadFiles = append(policy.AllowReadFiles, selfExe)
	if cfg.GuardDeclaration != nil {
		lookupEnvironment := guardLookupEnvironment(cfg.UseDeveloperEnvironment, cfg.DeveloperEnvironment)
		guardExecutable, lookupErr := ResolveCommandInDir(cfg.Command[0], lookupEnvironment, cfg.Workspace)
		if lookupErr != nil {
			return fmt.Errorf("resolving guard command %q: %w", cfg.Command[0], lookupErr)
		}
		// The outer domain must admit the same exact executable that the final
		// Guard domain admits. Otherwise the final helper correctly detects an
		// ancestor policy narrowing and refuses developer tools outside /usr or
		// the workspace. Grant the file only, never its bin directory.
		policy.AllowReadFiles = append(policy.AllowReadFiles, guardExecutable)
	}
	policy, coverageEnv := prepareSubprocessCoverage(policy, nil)
	policy, err = ResolvePolicyPaths(policy)
	if err != nil {
		return fmt.Errorf("resolve policy paths: %w", err)
	}
	if err := ValidatePolicy(policy); err != nil {
		return err
	}

	// Strict and BestEffort are mutually exclusive - catch misuse by callers.
	if cfg.Strict && cfg.BestEffort {
		return fmt.Errorf("sandbox: strict and best_effort are mutually exclusive")
	}

	// Probe namespace support before forking.
	// Only CLONE_NEWUSER is probed because CLONE_NEWNET requires CLONE_NEWUSER
	// on unprivileged processes - if user namespaces work, network namespaces
	// will too (created inside the user namespace with CAP_SYS_ADMIN).
	hasNamespaces := probeUserNamespace()
	if !hasNamespaces && (cfg.RequireNetNS || !cfg.BestEffort) {
		return fmt.Errorf("%w: user namespaces unavailable (blocked by seccomp or sysctl? use --best-effort for degraded mode)", ErrUnavailable)
	}

	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Create a private per-invocation 0o700 control directory for the Unix socket.
	sandboxDir, err := newStandaloneControlDir()
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(sandboxDir) }()

	socketPath := ProxySocketPath(sandboxDir)

	// Start Unix socket proxy listener.
	_ = os.Remove(socketPath) // clean up stale socket
	unixLn, err := (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("unix proxy listen: %w", err)
	}
	defer func() { _ = unixLn.Close() }()

	// Chmod the socket so the sandboxed child can connect.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Accept connections from the bridge proxy in the child.
	proxyServer := startStandaloneProxyServer(unixLn, standaloneProxyConnectionConfig{
		ProxyHandler: cfg.ProxyHandler,
	})
	defer proxyServer.stop()

	// Fork child in sandbox with standalone init mode.
	cmd := exec.CommandContext(ctx, selfExe) //nolint:gosec // G204: re-exec of self
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	policyJSON, jsonErr := encodePolicyJSON(&policy)
	if jsonErr != nil {
		return fmt.Errorf("encoding sandbox policy: %w", jsonErr)
	}
	var guardStatusReader, guardStatusWriter *os.File
	if cfg.GuardDeclaration != nil {
		guardStatusReader, guardStatusWriter, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("creating guard status pipe: %w", err)
		}
		defer func() {
			_ = guardStatusReader.Close()
			_ = guardStatusWriter.Close()
		}()
	}

	var developerPipe *developerEnvironmentPipe
	if cfg.UseDeveloperEnvironment {
		developerPipe, err = newDeveloperEnvironmentPipe(cfg.DeveloperEnvironment)
		if err != nil {
			return fmt.Errorf("encoding developer environment: %w", err)
		}
		defer developerPipe.close()
		cmd.ExtraFiles = []*os.File{developerPipe.reader}
	}
	if guardStatusWriter != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, guardStatusWriter)
	}
	guardStatusFD := 0
	if guardStatusWriter != nil {
		guardStatusFD = 2 + len(cmd.ExtraFiles)
	}
	cmd.Env = standaloneInitControlEnv(cfg, socketPath, coverageEnv, policyJSON, hasNamespaces, guardDeclarationJSON, guardStatusFD)

	if hasNamespaces {
		cloneFlags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET)
		if cfg.Strict {
			cloneFlags |= syscall.CLONE_NEWNS // mount namespace for private /dev/shm
		}
		uid := os.Getuid()
		gid := os.Getgid()
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: cloneFlags,
			UidMappings: []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: uid, Size: 1},
			},
			GidMappings: []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: gid, Size: 1},
			},
			Pdeathsig: syscall.SIGTERM,
			Setpgid:   true,
		}
	} else {
		// Best-effort: no namespace isolation. Tell child to skip loopback setup.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGTERM,
			Setpgid:   true,
		}
	}

	// Strict mode: become subreaper so orphaned grandchildren are
	// adopted by us instead of PID 1. This lets us reap them after
	// the main child exits, even if they called setsid().
	if cfg.Strict {
		if err := SetChildSubreaper(); err != nil {
			return fmt.Errorf("enable subreaper: %w", err)
		}
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting sandbox child: %w", err)
	}
	if guardStatusWriter != nil {
		if err := guardStatusWriter.Close(); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("closing guard status write pipe: %w", err)
		}
	}
	if developerPipe != nil {
		// ExtraFiles duplicates reader into the re-exec child. Drop the parent's
		// copy before writing so every failure path closes both local pipe ends.
		if err := developerPipe.reader.Close(); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("closing developer environment read pipe: %w", err)
		}
		if err := developerPipe.writeAndClose(); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("transporting developer environment: %w", err)
		}
	}
	if guardStatusReader != nil {
		proof, proofErr := readGuardExecutionProof(guardStatusReader)
		if proofErr == nil && cfg.GuardAppliedPreExec != nil {
			proofErr = cfg.GuardAppliedPreExec(proof)
		}
		if proofErr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("guard execution proof: %w", proofErr)
		}
	}

	// Wait for child to exit.
	waitErr := cmd.Wait()

	// Kill process group - terminate descendants that may still hold bridge
	// proxy connections open.
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	// Strict mode: reap orphaned descendants adopted by subreaper.
	// Best-effort relies on process-group termination plus proxy server stop.
	if cfg.Strict {
		ReapOrphans()
	}

	// Stop accepting, close active bridge connections, and join the accept
	// loop plus all proxy handlers before sandbox directory cleanup.
	proxyServer.stop()

	// Clean up child's sandbox temp dir.
	if cmd.Process != nil {
		CleanupChildSandboxDir(cmd.Process.Pid)
	}

	return waitErr
}

func guardLookupEnvironment(useDeveloperEnvironment bool, developerEnvironment []string) []string {
	if useDeveloperEnvironment {
		return developerEnvironment
	}
	return []string{"PATH=" + syntheticPath}
}

func readGuardExecutionProof(r io.Reader) ([]byte, error) {
	// EOF proves only that the close-on-exec writer is gone. That can follow a
	// successful exec or abrupt helper termination, so the returned record is
	// strictly proof of ruleset application before the exec attempt.
	decoder := json.NewDecoder(io.LimitReader(r, 1<<20))
	var proof json.RawMessage
	if err := decoder.Decode(&proof); err != nil {
		return nil, fmt.Errorf("reading enforced record: %w", err)
	}
	var status struct {
		ExecError string `json:"exec_error"`
	}
	if err := json.Unmarshal(proof, &status); err != nil {
		return nil, fmt.Errorf("decoding enforced record: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err == nil {
		var failure struct {
			ExecError string `json:"exec_error"`
		}
		_ = json.Unmarshal(trailing, &failure)
		if failure.ExecError != "" {
			return nil, fmt.Errorf("operator command exec failed: %s", failure.ExecError)
		}
		return nil, errors.New("guard status pipe contained multiple success records")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading guard status completion: %w", err)
	}
	if status.ExecError != "" {
		return nil, fmt.Errorf("operator command exec failed: %s", status.ExecError)
	}
	return proof, nil
}

// standaloneInitControlEnv is the complete re-exec environment. In
// developer-environment mode it carries only a fixed descriptor number, never
// a developer-supplied value.
func standaloneInitControlEnv(cfg StandaloneLaunchConfig, socketPath string, coverageEnv []string, policyJSON string, hasNamespaces bool, guardDeclarationJSON []byte, guardStatusFD int) []string {
	commandJSON, _ := json.Marshal(cfg.Command)
	env := []string{
		standaloneInitEnv + "=1",
		"__PIPELOCK_SANDBOX_WORKSPACE=" + cfg.Workspace,
		standaloneCommandJSONEnv + "=" + string(commandJSON),
		sandboxSocketEnv + "=" + socketPath,
	}
	env = append(env, subprocessCoverageControlEnv(coverageEnv)...)
	if cfg.Strict {
		env = append(env, strictEnvKey+"=1")
	}
	if len(cfg.ExtraEnv) > 0 {
		env = append(env, "__PIPELOCK_SANDBOX_EXTRA_ENV="+strings.Join(cfg.ExtraEnv, "\x1f"))
	}
	if cfg.UseDeveloperEnvironment {
		env = append(env, developerEnvironmentControlEnv+"="+strconv.Itoa(developerEnvironmentFD))
	}
	env = append(env, "__PIPELOCK_SANDBOX_POLICY="+policyJSON)
	if !hasNamespaces {
		env = append(env, noNetNSEnvKey+"=1")
	}
	if cfg.GuardDeclaration != nil {
		env = append(env,
			standaloneGuardDeclarationEnv+"="+string(guardDeclarationJSON),
			standaloneGuardProfileEnv+"="+cfg.GuardProfile,
			standaloneGuardPolicyHashEnv+"="+cfg.GuardPolicyHash,
			guardStatusControlEnv+"="+strconv.Itoa(guardStatusFD),
		)
	}
	return env
}

// newStandaloneControlDir creates the per-invocation control directory that
// carries the Unix proxy socket. It uses os.MkdirTemp so the name is
// unpredictable and the directory is created atomically at 0o700: a predictable
// /tmp/pipelock-sandbox-<pid> path could be pre-created, symlinked, or squatted
// in the sticky /tmp before this invocation, letting a same-permission attacker
// interpose on the control socket. The caller passes the resolved socket path
// to the child, so the directory name does not need to be predictable.
//
// As defense in depth against a TOCTOU swap, it re-validates with Lstat (not
// Stat, so a symlink is detected rather than followed): the result must be a
// real directory owned by this process. Any deviation fails closed.
func newStandaloneControlDir() (retDir string, retErr error) {
	sandboxDir, err := os.MkdirTemp("", "pipelock-sandbox-")
	if err != nil {
		return "", fmt.Errorf("creating sandbox dir: %w", err)
	}
	// On any validation failure below, remove the directory we just created:
	// the caller's cleanup defer is only installed once this returns a path, so
	// without this a rejected directory would leak. os.Remove (not RemoveAll) so
	// a swapped or unexpectedly non-empty path is never recursively deleted.
	defer func() {
		if retErr != nil {
			_ = os.Remove(sandboxDir)
		}
	}()
	info, err := os.Lstat(sandboxDir)
	if err != nil {
		return "", fmt.Errorf("stat sandbox dir: %w", err)
	}
	if !info.Mode().IsDir() {
		return "", fmt.Errorf("sandbox control dir %s is not a directory", sandboxDir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		return "", fmt.Errorf("sandbox control dir %s has mode %04o, want 0700", sandboxDir, perm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("sandbox control dir %s ownership is unavailable", sandboxDir)
	}
	if int(stat.Uid) != os.Geteuid() {
		return "", fmt.Errorf("sandbox control dir %s is owned by uid %d, not this process (uid %d)", sandboxDir, stat.Uid, os.Geteuid())
	}
	return sandboxDir, nil
}

type standaloneProxyServer struct {
	ln   net.Listener
	cfg  standaloneProxyConnectionConfig
	once sync.Once

	mu       sync.Mutex
	stopping bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

const standaloneProxyDrainTimeout = 5 * time.Second

func startStandaloneProxyServer(ln net.Listener, cfg standaloneProxyConnectionConfig) *standaloneProxyServer {
	s := &standaloneProxyServer{
		ln:    ln,
		cfg:   cfg,
		conns: make(map[net.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *standaloneProxyServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !s.trackConn(conn) {
			_ = conn.Close()
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *standaloneProxyServer) trackConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return false
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *standaloneProxyServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer s.untrackConn(conn)
	handleStandaloneProxyConnection(conn, s.cfg)
}

func (s *standaloneProxyServer) untrackConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

func (s *standaloneProxyServer) stop() {
	_ = s.stopWithin(standaloneProxyDrainTimeout)
}

// stopWithin performs shutdown once and reports whether that first shutdown
// drained active handlers before timeout. Subsequent calls are no-ops and return
// false regardless of the first shutdown's drain outcome.
func (s *standaloneProxyServer) stopWithin(timeout time.Duration) bool {
	stopped := false
	s.once.Do(func() {
		s.mu.Lock()
		s.stopping = true
		_ = s.ln.Close()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()

		done := make(chan struct{})
		go func() {
			defer close(done)
			s.wg.Wait()
		}()
		if timeout <= 0 {
			<-done
			stopped = true
			return
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-done:
			stopped = true
		case <-timer.C:
		}
	})
	return stopped
}

// handleStandaloneProxyConnection dispatches a bridge connection to the
// scanning handler. A missing handler fails closed unless an internal caller
// explicitly opts into the unscanned debug-only forwarding path.
func handleStandaloneProxyConnection(conn net.Conn, cfg standaloneProxyConnectionConfig) {
	if cfg.ProxyHandler != nil {
		cfg.ProxyHandler(conn)
		return
	}
	handleDirectForward(conn, cfg.AllowUnscannedDirectForward)
}

// handleDirectForward bridges a Unix socket connection to a direct TCP
// connection only when allowUnscannedDirectForward is explicitly true.
// This is DEBUG ONLY: it performs no scanning or SSRF protection.
func handleDirectForward(conn net.Conn, allowUnscannedDirectForward bool) {
	defer func() { _ = conn.Close() }()
	if !allowUnscannedDirectForward {
		return
	}

	// Read the first line to get the CONNECT target.
	// For now, just close - the real handler is provided by the CLI.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Parse CONNECT host:port from the HTTP request.
	line := string(buf[:n])
	if !strings.HasPrefix(line, "CONNECT ") {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT supported\r\n")
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	target := parts[1]

	// Direct connect (no scanning).
	upstream, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", target)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n%v\r\n", err)
		return
	}
	defer func() { _ = upstream.Close() }()

	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Bridge.
	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd // two copy directions
	go func() { defer wg.Done(); _, _ = io.Copy(upstream, conn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(conn, upstream) }()
	wg.Wait()
}

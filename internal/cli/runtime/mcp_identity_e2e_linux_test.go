// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/identity"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	e2eHelperEnv = "PIPELOCK_IDE2E_HELPER"
	e2eHoldEnv   = "PIPELOCK_IDE2E_HOLD"
	e2ePortEnv   = "PIPELOCK_IDE2E_PORT"
	e2eAuthEnv   = "PIPELOCK_IDE2E_AUTH"
	e2ePortLine  = "PORT "
)

// e2eHeldFile keeps the pinned module open for the life of the helper process.
var e2eHeldFile *os.File

// TestIdentityE2EHelperProcess is the stand-in local MCP service. The tests
// re-execute the test binary with the helper environment set, so the service
// is a real process with its own socket, executable and open files. Without the
// environment it is a no-op.
func TestIdentityE2EHelperProcess(t *testing.T) {
	if os.Getenv(e2eHelperEnv) != "1" {
		return
	}
	if hold := os.Getenv(e2eHoldEnv); hold != "" {
		f, err := os.Open(filepath.Clean(hold))
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "open held file:", err)
			os.Exit(2)
		}
		e2eHeldFile = f
	}
	port := os.Getenv(e2ePortEnv)
	if port == "" {
		port = "0"
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort(e2eLoopbackHost, port))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(2)
	}
	srv := &http.Server{Handler: identityE2EHandler(os.Getenv(e2eAuthEnv)), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	_, _ = fmt.Fprintf(os.Stdout, "%s%d\n", e2ePortLine, ln.Addr().(*net.TCPAddr).Port)
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func identityE2EHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != e2eIdentityPath {
			http.NotFound(w, r)
			return
		}
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			serveIdentityE2EWebSocket(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		reply, ok := identityE2EReply(body)
		if !ok {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(reply)
	})
}

func serveIdentityE2EWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	for {
		msg, _, err := wsutil.ReadClientData(conn)
		if err != nil {
			return
		}
		if reply, ok := identityE2EReply(msg); ok {
			if err := wsutil.WriteServerMessage(conn, ws.OpText, reply); err != nil {
				return
			}
		}
	}
}

// identityE2EReply answers one JSON-RPC message; ok is false for a notification.
func identityE2EReply(raw []byte) ([]byte, bool) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || len(req.ID) == 0 {
		return nil, false
	}
	switch req.Method {
	case "initialize":
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}`, req.ID)), true
	case "tools/list":
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[%s]}}`, req.ID, ackListenerTool)), true
	default:
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, req.ID)), true
	}
}

type identityE2EServer struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	cancel context.CancelFunc
	stderr *syncBuffer
	once   sync.Once
	Port   int
}

type identityE2EServerOpts struct {
	Hold  string
	Token string
	Port  int
}

// startIdentityE2EServer starts the stand-in service. A server given Hold keeps
// that file open, which is how a real service holds its native module; one
// without it is the same executable under the same uid that does not hold it.
func startIdentityE2EServer(t *testing.T, o identityE2EServerOpts) *identityE2EServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIdentityE2EHelperProcess$") //nolint:gosec // G204: re-exec of the test binary
	env := append(os.Environ(), e2eHelperEnv+"=1")
	if o.Hold != "" {
		env = append(env, e2eHoldEnv+"="+o.Hold)
	}
	if o.Token != "" {
		env = append(env, e2eAuthEnv+"="+o.Token)
	}
	if o.Port != 0 {
		env = append(env, e2ePortEnv+"="+strconv.Itoa(o.Port))
	}
	cmd.Env = env
	s := &identityE2EServer{cmd: cmd, cancel: cancel, stderr: &syncBuffer{}}
	cmd.Stderr = s.stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	s.stdin = stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(s.stop)

	portCh := make(chan int, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if rest, ok := strings.CutPrefix(sc.Text(), e2ePortLine); ok {
				if n, convErr := strconv.Atoi(rest); convErr == nil {
					portCh <- n
					return
				}
			}
		}
		portCh <- 0
	}()
	select {
	case s.Port = <-portCh:
	case <-time.After(testwait.Deadline(30 * time.Second)):
	}
	if s.Port == 0 {
		t.Fatalf("stand-in service did not report a port (stderr: %s)", s.stderr.String())
	}
	return s
}

func (s *identityE2EServer) stop() {
	s.once.Do(func() {
		s.cancel()
		_ = s.stdin.Close()
		_ = s.cmd.Wait()
	})
}

func (s *identityE2EServer) url(scheme string) string {
	return fmt.Sprintf("%s://%s:%d%s", scheme, e2eLoopbackHost, s.Port, e2eIdentityPath)
}

// newE2ERegistration pins the stand-in service: this test binary's executable
// digest, this uid, and a module file the genuine service holds open.
func newE2ERegistration(t *testing.T, scheme string, sessionHeader bool) e2eRegistration {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exeBytes, err := os.ReadFile(filepath.Clean(exe))
	if err != nil {
		t.Fatal(err)
	}
	exeSum := sha256.Sum256(exeBytes)
	module := filepath.Join(t.TempDir(), "vendor-module.bin")
	content := []byte("vendor module fixture contents")
	if err := os.WriteFile(module, content, 0o600); err != nil {
		t.Fatal(err)
	}
	moduleSum := sha256.Sum256(content)
	uid, err := strconv.ParseUint(strconv.Itoa(os.Getuid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return e2eRegistration{
		Scheme:        scheme,
		UID:           uint32(uid),
		ExecSHA:       hex.EncodeToString(exeSum[:]),
		MappedPath:    module,
		MappedSHA:     hex.EncodeToString(moduleSum[:]),
		SessionHeader: sessionHeader,
	}
}

// e2eSessionAckConfig writes a configuration whose acknowledgment names the
// registered service in verified-local-session mode. The binding is computed
// through the resolver exactly as a launch computes it; the upstream's port and
// the session token are not part of it.
func e2eSessionAckConfig(t *testing.T, reg e2eRegistration, tr identity.Transport) string {
	t.Helper()
	probe, err := config.Load(writeE2EConfig(t, "", reg.yaml()))
	if err != nil {
		t.Fatal(err)
	}
	res, err := identity.Resolve(probe, "", tr)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	binding, err := identity.SessionBinding(res, tr)
	if err != nil {
		t.Fatalf("session binding: %v", err)
	}
	return writeE2EConfig(t, e2eAckBlock(t, res.Name, binding, config.MCPAckBindingModeVerifiedLocalSession), reg.yaml())
}

func e2eHTTPTransport(upstream, token string) identity.Transport {
	return identity.Transport{
		Kind:        identity.KindHTTP,
		UpstreamURL: upstream,
		Headers: []identity.Header{{
			Name: "Authorization", Value: "Bearer " + token,
			Source: identity.HeaderSourceCarrier, Carrier: e2eSessionCarrier,
		}},
	}
}

func e2eProxyArgs(cfgPath, upstream string, carrier bool) []string {
	args := []string{"proxy", "--config", cfgPath, "--upstream", upstream}
	if carrier {
		args = append(args, "--header-carrier", "Authorization="+e2eSessionCarrier)
	}
	return args
}

const (
	e2eRefusedPrefix  = "verified local service " + e2eIdentityName
	e2eNotHeldMessage = "is not open or mapped by the owner"
)

// The acknowledgment covers every session of the registered service: a second
// session has a new process, a new port and a new bearer value, and the same
// acknowledgment still applies. Each session's ownership is proven at dial.
func TestMCPProxyVerifiedLocalSessionAckCoversNewSessions(t *testing.T) {
	reg := newE2ERegistration(t, config.MCPIdentitySchemeHTTP, true)
	const tokenOne, tokenTwo = "session-token-one", "session-token-two"
	first := startIdentityE2EServer(t, identityE2EServerOpts{Hold: reg.MappedPath, Token: tokenOne})
	second := startIdentityE2EServer(t, identityE2EServerOpts{Hold: reg.MappedPath, Token: tokenTwo})
	if first.Port == second.Port {
		t.Fatalf("sessions share port %d", first.Port)
	}
	cfgPath := e2eSessionAckConfig(t, reg, e2eHTTPTransport(first.url(config.MCPIdentitySchemeHTTP), tokenOne))

	for i, session := range []struct {
		srv   *identityE2EServer
		token string
	}{{first, tokenOne}, {second, tokenTwo}} {
		t.Run(fmt.Sprintf("session %d", i+1), func(t *testing.T) {
			t.Setenv(e2eSessionCarrier, "Bearer "+session.token)
			p := startE2EProxy(t, e2eProxyArgs(cfgPath, session.srv.url(config.MCPIdentitySchemeHTTP), true))
			got := p.call()
			stderr, err := p.finish()
			if err != nil {
				t.Fatalf("proxy exit: %v (stderr: %s)", err, stderr)
			}
			if !strings.Contains(got, e2eStoreSecret) {
				t.Fatalf("acknowledged tool not forwarded under verified-local-session: %s (stderr: %s)", got, stderr)
			}
			for _, want := range []string{"server=" + e2eIdentityName, "source=verified-local-service", "binding=verified-local-session"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("startup line missing %q: %s", want, stderr)
				}
			}
		})
	}
}

// A process that is the right executable under the right uid but does not hold
// the pinned module is refused at dial. Nothing reaches it, the tool list
// fails closed, and the error names the registration field that failed.
func TestMCPProxyVerifiedLocalServiceRefusesImpostor(t *testing.T) {
	reg := newE2ERegistration(t, config.MCPIdentitySchemeHTTP, true)
	const token = "session-token-impostor"
	genuine := startIdentityE2EServer(t, identityE2EServerOpts{Hold: reg.MappedPath, Token: token})
	impostor := startIdentityE2EServer(t, identityE2EServerOpts{Token: token})
	cfgPath := e2eSessionAckConfig(t, reg, e2eHTTPTransport(genuine.url(config.MCPIdentitySchemeHTTP), token))

	t.Setenv(e2eSessionCarrier, "Bearer "+token)
	p := startE2EProxy(t, e2eProxyArgs(cfgPath, impostor.url(config.MCPIdentitySchemeHTTP), true))
	got, answered := p.tryCall(e2eToolsListLine)
	stderr, _ := p.finish()
	if strings.Contains(got, e2eStoreSecret) {
		t.Fatalf("tool list reached the client through an unverified service: %s", got)
	}
	if answered && !strings.Contains(got, `"error"`) {
		t.Fatalf("unverified service answered without a JSON-RPC error: %s", got)
	}
	for _, want := range []string{e2eRefusedPrefix, "mapped_files[0]", e2eNotHeldMessage} {
		if !strings.Contains(stderr, want) && !strings.Contains(got, want) {
			t.Errorf("refusal does not name %q (response %q, stderr %q)", want, got, stderr)
		}
	}
}

// Ownership is verified on every new connection, not once per session: after a
// verified exchange, replacing the service on the same port with an impostor
// is refused on the next connection the proxy dials.
func TestMCPProxyVerifiedLocalServiceReverifiesReconnect(t *testing.T) {
	reg := newE2ERegistration(t, config.MCPIdentitySchemeHTTP, true)
	const token = "session-token-reconnect"
	genuine := startIdentityE2EServer(t, identityE2EServerOpts{Hold: reg.MappedPath, Token: token})
	cfgPath := e2eSessionAckConfig(t, reg, e2eHTTPTransport(genuine.url(config.MCPIdentitySchemeHTTP), token))

	t.Setenv(e2eSessionCarrier, "Bearer "+token)
	p := startE2EProxy(t, e2eProxyArgs(cfgPath, genuine.url(config.MCPIdentitySchemeHTTP), true))
	if got := p.call(); !strings.Contains(got, e2eStoreSecret) {
		t.Fatalf("verified session not served: %s (stderr: %s)", got, p.stderr.String())
	}

	port := genuine.Port
	genuine.stop()
	startIdentityE2EServer(t, identityE2EServerOpts{Token: token, Port: port})

	// The first request after the swap can fail on the dead pooled connection;
	// a request that must dial is verified and refused.
	for i := 0; i < 2; i++ {
		got, _ := p.tryCall(e2eToolsListLine)
		if strings.Contains(got, e2eStoreSecret) {
			t.Fatalf("impostor on the same port served a tool list: %s", got)
		}
	}
	stderr, _ := p.finish()
	if !strings.Contains(stderr, e2eRefusedPrefix) || !strings.Contains(stderr, e2eNotHeldMessage) {
		t.Fatalf("reconnect was not verified and refused: %s", stderr)
	}
}

// A WebSocket upstream matched by a registration without a session header is
// verified at dial too: the genuine service is served and an impostor refused.
func TestMCPProxyVerifiedLocalServiceWebSocket(t *testing.T) {
	reg := newE2ERegistration(t, config.MCPIdentitySchemeWS, false)
	genuine := startIdentityE2EServer(t, identityE2EServerOpts{Hold: reg.MappedPath})
	impostor := startIdentityE2EServer(t, identityE2EServerOpts{})
	genuineURL := genuine.url(config.MCPIdentitySchemeWS)
	cfgPath := e2eSessionAckConfig(t, reg, identity.Transport{Kind: identity.KindWS, UpstreamURL: genuineURL})

	t.Run("genuine service is served", func(t *testing.T) {
		p := startE2EProxy(t, e2eProxyArgs(cfgPath, genuineURL, false))
		got := p.call()
		stderr, err := p.finish()
		if err != nil {
			t.Fatalf("proxy exit: %v (stderr: %s)", err, stderr)
		}
		if !strings.Contains(got, e2eStoreSecret) {
			t.Fatalf("acknowledged tool not forwarded over the verified WebSocket: %s (stderr: %s)", got, stderr)
		}
	})
	t.Run("impostor is refused", func(t *testing.T) {
		p := startE2EProxy(t, e2eProxyArgs(cfgPath, impostor.url(config.MCPIdentitySchemeWS), false))
		got, _ := p.tryCall(e2eToolsListLine)
		stderr, _ := p.finish()
		if strings.Contains(got, e2eStoreSecret) {
			t.Fatalf("tool list reached the client through an unverified WebSocket service: %s", got)
		}
		if !strings.Contains(stderr, e2eRefusedPrefix) || !strings.Contains(stderr, e2eNotHeldMessage) {
			t.Fatalf("WebSocket dial was not verified and refused: %s", stderr)
		}
	})
}

// The pipelock run MCP listener serves a registered service that declares no
// session header. The resolution is pinned at startup: a reload that changes
// the registration refuses every later request, while an unrelated reload does
// not.
func TestServerRunListenerVerifiedLocalServiceFollowsRegistration(t *testing.T) {
	reg := newE2ERegistration(t, config.MCPIdentitySchemeHTTP, false)
	genuine := startIdentityE2EServer(t, identityE2EServerOpts{Hold: reg.MappedPath})
	upstream := genuine.url(config.MCPIdentitySchemeHTTP)
	cfgPath := e2eSessionAckConfig(t, reg, listenerTransport(upstream))

	testport.WithRetry(t, 2, func(addrs []string) error {
		fetchAddr, mcpAddr := addrs[0], addrs[1]
		text, err := os.ReadFile(filepath.Clean(cfgPath))
		if err != nil {
			t.Fatal(err)
		}
		listenerCfg := writeServerTestConfig(t, string(text)+fmt.Sprintf("\nfetch_proxy:\n  listen: %q\n  timeout_seconds: 5\nlogging:\n  format: json\n  output: stdout\n", fetchAddr))
		s, buf := newTestServer(t, func(o *ServerOpts) {
			o.ConfigFile = listenerCfg
			o.Listen = fetchAddr
			o.ListenChanged = true
			o.MCPListen = mcpAddr
			o.MCPUpstream = upstream
		})
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- s.Start(ctx) }()
		defer func() {
			cancel()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), testwait.Deadline(5*time.Second))
			defer shutdownCancel()
			_ = s.Shutdown(shutdownCtx)
			select {
			case <-errCh:
			case <-shutdownCtx.Done():
				t.Error("listener did not stop after cancellation")
			}
		}()
		if err := waitForPortOrCommandExitResult(mcpAddr, errCh, buf); err != nil {
			return err
		}

		id := 0
		toolsList := func() string {
			id++
			return postReloadSnapshotToolsList(t, mcpAddr, id)
		}
		reloadFromDisk := func(mutate func(*config.Config)) {
			next, err := config.Load(listenerCfg)
			if err != nil {
				t.Fatal(err)
			}
			if mutate != nil {
				mutate(next)
			}
			if err := s.Reload(next); err != nil {
				t.Fatalf("reload: %v", err)
			}
		}

		if got := toolsList(); !strings.Contains(got, e2eStoreSecret) {
			t.Fatalf("registered service not served through the run listener: %s (log: %s)", got, buf.String())
		}
		reloadFromDisk(nil)
		if got := toolsList(); !strings.Contains(got, e2eStoreSecret) {
			t.Fatalf("an unrelated reload refused the registered service: %s", got)
		}
		reloadFromDisk(func(next *config.Config) {
			next.MCPIdentities[0].VerifiedLocalService.MappedFiles[0].SHA256 = e2eFakeModuleHash
		})
		got := toolsList()
		if strings.Contains(got, e2eStoreSecret) || !strings.Contains(got, "-32003") {
			t.Fatalf("a reload that changed the registration did not refuse requests: %s", got)
		}
		if !strings.Contains(buf.String(), "registration changed; restart pipelock run") {
			t.Errorf("refusal did not log the restart instruction: %s", buf.String())
		}
		reloadFromDisk(nil)
		if got := toolsList(); !strings.Contains(got, e2eStoreSecret) {
			t.Fatalf("restoring the registered pin did not restore service: %s", got)
		}
		return nil
	})
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build liveproof

// This file is behind the `liveproof` build tag so it never runs in the normal
// `go test ./...` lane. Run it with:
//
//	make test-liveproof
//
// or directly:
//
//	go test -tags liveproof -run TestLiveProof -count=1 -v ./internal/liveproof/...
//
// These tests build the shipped `pipelock` binary, write real YAML configs,
// start real proxy processes on ephemeral ports, and observe customer-visible
// HTTP/CLI results. They intentionally skip proofs that cannot be driven with
// shipped operator surfaces; a missing customer-driving surface is a product
// gap, not a test seam to invent here.

package liveproof_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	liveproofAPIToken = "liveproof-admin-token"
	baselineAgent     = "liveproof-baseline"
	taintAgent        = "liveproof-taint"

	// heldSettleTimeout is how long a held MCP request is observed to stay
	// unanswered before the test concludes it is genuinely held.
	heldSettleTimeout = 250 * time.Millisecond
	// rpcReadTimeout bounds waiting for a single JSON-RPC response line.
	rpcReadTimeout = 5 * time.Second
)

var (
	buildOnce        sync.Once
	buildBin         string
	buildBinDir      string
	buildOutput      []byte
	errBuildPipelock error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if buildBinDir != "" {
		_ = os.RemoveAll(buildBinDir)
	}
	os.Exit(code)
}

// TestLiveProofBehavioralBaselineEnforcement proves the profile-then-lock
// behavioral baseline path as a customer runs it: real proxy learns a profile
// from mediated fetch traffic, the shipped `pipelock baseline ratify` CLI locks
// it through the admin API, a matching session is allowed, and a deviating
// session is denied with a real 403 response.
func TestLiveProofBehavioralBaselineEnforcement(t *testing.T) {
	bin := buildPipelock(t)
	upstream := startLiveHTTPServer(t, liveHTTPHandler(t, nil))
	proxyAddr := freeTCPAddr(t)
	apiAddr := freeTCPAddr(t)
	work := t.TempDir()
	profileDir := filepath.Join(work, "profiles")
	cfgPath := filepath.Join(work, "pipelock.yaml")
	writeFile(t, cfgPath, baselineConfig(proxyAddr, apiAddr, profileDir, filepath.Join(work, "audit.log")))

	proxy := startPipelock(t, bin, cfgPath, proxyAddr)
	defer proxy.stop(t)

	steadyURL := liveURL("steady.liveproof.test", upstream.port, "/steady")
	deviantURL := liveURL("deviant.liveproof.test", upstream.port, "/deviant")

	status, body := fetchViaPipelock(t, proxyAddr, baselineAgent, steadyURL)
	requireStatus(t, "baseline learning fetch", status, http.StatusOK, body)
	status, body = fetchViaPipelock(t, proxyAddr, "liveproof-evictor", steadyURL)
	requireStatus(t, "baseline eviction fetch", status, http.StatusOK, body)

	ratifyBaseline(t, bin, cfgPath, apiAddr, baselineAgent)

	status, body = fetchViaPipelock(t, proxyAddr, baselineAgent, steadyURL)
	requireStatus(t, "locked baseline matching fetch", status, http.StatusOK, body)
	status, body = fetchViaPipelock(t, proxyAddr, baselineAgent, deviantURL)
	requireStatus(t, "locked baseline deviation fetch", status, http.StatusForbidden, body)
	requireContains(t, "baseline block body", body, "baseline deviation")
}

// TestLiveProofTaintCrossRequestEnforcement proves cross-request taint through
// the shipped proxy: a clean publish through the forward proxy is allowed, the
// same bound session reads an untrusted external-looking source through fetch,
// and a later external publish is denied before the upstream receives it.
func TestLiveProofTaintCrossRequestEnforcement(t *testing.T) {
	bin := buildPipelock(t)
	var publishHits atomic.Int64
	upstream := startLiveHTTPServer(t, liveHTTPHandler(t, &publishHits))
	proxyAddr := freeTCPAddr(t)
	apiAddr := freeTCPAddr(t)
	work := t.TempDir()
	cfgPath := filepath.Join(work, "pipelock.yaml")
	writeFile(t, cfgPath, taintConfig(proxyAddr, apiAddr, filepath.Join(work, "audit.log")))

	proxy := startPipelock(t, bin, cfgPath, proxyAddr)
	defer proxy.stop(t)

	publishURL := liveURL("publish.liveproof.test", upstream.port, "/auth/update")
	sourceURL := liveURL("source.liveproof.test", upstream.port, "/article")

	status, body := postThroughForwardProxy(t, proxyAddr, publishURL, "before-taint")
	requireStatus(t, "clean publish before taint", status, http.StatusOK, body)
	if got := publishHits.Load(); got != 1 {
		t.Fatalf("publish upstream hits before taint = %d, want 1", got)
	}

	status, body = fetchViaPipelock(t, proxyAddr, "", sourceURL)
	requireStatus(t, "untrusted source fetch", status, http.StatusOK, body)

	status, body = postThroughForwardProxy(t, proxyAddr, publishURL, "after-taint")
	requireStatus(t, "publish after untrusted source", status, http.StatusForbidden, body)
	requireContains(t, "taint block body", body, "external_publish_after_untrusted_external_exposure")
	if got := publishHits.Load(); got != 1 {
		t.Fatalf("publish upstream hits after blocked taint publish = %d, want 1", got)
	}
}

func TestLiveProofDeferredCascade(t *testing.T) {
	bin := buildPipelock(t)
	upstream := startLiveMCPHTTPServer(t)
	apiAddr := freeTCPAddr(t)
	work := t.TempDir()
	evidenceDir := filepath.Join(work, "evidence")
	keyPath := writeLiveProofSigningKey(t, filepath.Join(work, "flight-recorder.key"))
	cfgPath := filepath.Join(work, "pipelock.yaml")
	writeFile(t, cfgPath, deferredMCPConfig(apiAddr, evidenceDir, keyPath))

	proxy := startMCPProxy(t, bin, cfgPath, apiAddr, upstream.url)
	defer proxy.stop(t)
	requireMCPHandshake(t, proxy)

	t.Run("operator deny resolves held parent closed", func(t *testing.T) {
		const rawArgsMarker = "LIVEPROOF_RAW_ARGS_SHOULD_NOT_LEAK"
		proxy.send(t, `{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"live_defer","arguments":{"payload":"`+rawArgsMarker+`"}}}`)
		proxy.requireNoResponse(t, "held parent before operator deny")

		list, raw := waitDeferredList(t, bin, apiAddr, 1)
		if strings.Contains(raw, rawArgsMarker) || strings.Contains(raw, "arguments") || strings.Contains(raw, "arg_digest") {
			t.Fatalf("deferred list leaked raw held payload/args/digest:\n%s", raw)
		}
		parent := findHeldByDepth(t, list, 1)

		out := runDeferredCLI(t, bin, apiAddr, "deny", parent.DeferID)
		requireContains(t, "operator deny output", out, "deny "+parent.DeferID+" -> block")

		resp := proxy.readRPCResponse(t, "denied parent response")
		requireRPCError(t, resp, "100", "pipelock: deferred action denied")
		if got := upstream.toolCallCount(); got != 0 {
			t.Fatalf("denied parent reached upstream tool handler %d time(s), want 0", got)
		}
	})

	t.Run("parent deny cascades to held child", func(t *testing.T) {
		proxy.send(t, `{"jsonrpc":"2.0","id":200,"method":"tools/call","params":{"name":"live_defer","arguments":{"label":"cascade-parent"}}}`)
		proxy.requireNoResponse(t, "held cascade parent")
		proxy.send(t, `{"jsonrpc":"2.0","id":201,"method":"tools/call","params":{"name":"live_defer","arguments":{"label":"cascade-child"}}}`)
		proxy.requireNoResponse(t, "held cascade child")

		list, _ := waitDeferredList(t, bin, apiAddr, 2)
		parent := findHeldByDepth(t, list, 1)
		child := findHeldByDepth(t, list, 2)
		if child.ParentDeferID != parent.DeferID {
			t.Fatalf("child parent_defer_id=%q, want %q", child.ParentDeferID, parent.DeferID)
		}

		out := runDeferredCLI(t, bin, apiAddr, "deny", parent.DeferID)
		requireContains(t, "operator cascade deny output", out, "deny "+parent.DeferID+" -> block")

		responses := []liveRPCResponse{
			proxy.readRPCResponse(t, "cascade response 1"),
			proxy.readRPCResponse(t, "cascade response 2"),
		}
		requireRPCErrorIDs(t, responses, map[string]string{
			"200": "pipelock: deferred action denied",
			"201": "pipelock: deferred action denied",
		})
		waitDeferredJournalSource(t, filepath.Join(evidenceDir, "deferred-actions.jsonl"), child.DeferID, "cascade")
		if got := upstream.toolCallCount(); got != 0 {
			t.Fatalf("cascade-denied calls reached upstream tool handler %d time(s), want 0", got)
		}
	})

	t.Run("cascade depth cap denies over-depth action closed", func(t *testing.T) {
		proxy.send(t, `{"jsonrpc":"2.0","id":300,"method":"tools/call","params":{"name":"live_defer","arguments":{"label":"depth-root"}}}`)
		proxy.requireNoResponse(t, "held depth root")
		proxy.send(t, `{"jsonrpc":"2.0","id":301,"method":"tools/call","params":{"name":"live_defer","arguments":{"label":"depth-child"}}}`)
		proxy.requireNoResponse(t, "held depth child")

		list, _ := waitDeferredList(t, bin, apiAddr, 2)
		root := findHeldByDepth(t, list, 1)
		depthChild := findHeldByDepth(t, list, 2)
		if depthChild.ParentDeferID != root.DeferID {
			t.Fatalf("depth child parent_defer_id=%q, want %q", depthChild.ParentDeferID, root.DeferID)
		}

		proxy.send(t, `{"jsonrpc":"2.0","id":302,"method":"tools/call","params":{"name":"live_defer","arguments":{"label":"over-depth"}}}`)
		overDepth := proxy.readRPCResponse(t, "over-depth response")
		requireRPCError(t, overDepth, "302", "pipelock: defer cascade depth exceeded")
		waitFlightRecorderResolutionSource(t, evidenceDir, "cascade_limit")

		out := runDeferredCLI(t, bin, apiAddr, "deny", root.DeferID)
		requireContains(t, "operator depth cleanup output", out, "deny "+root.DeferID+" -> block")
		responses := []liveRPCResponse{
			proxy.readRPCResponse(t, "depth cleanup response 1"),
			proxy.readRPCResponse(t, "depth cleanup response 2"),
		}
		requireRPCErrorIDs(t, responses, map[string]string{
			"300": "pipelock: deferred action denied",
			"301": "pipelock: deferred action denied",
		})
	})
}

// TestLiveProofRestartRecoveryDurability proves persisted behavioral-baseline
// state survives a process restart: the first real proxy learns and ratifies a
// locked profile, the process is killed, a second real proxy starts with the
// same YAML/profile directory, matching traffic is allowed, and a later
// deviation is still denied instead of silently resetting to observe.
func TestLiveProofRestartRecoveryDurability(t *testing.T) {
	bin := buildPipelock(t)
	upstream := startLiveHTTPServer(t, liveHTTPHandler(t, nil))
	proxyAddr := freeTCPAddr(t)
	apiAddr := freeTCPAddr(t)
	work := t.TempDir()
	profileDir := filepath.Join(work, "profiles")
	cfgPath := filepath.Join(work, "pipelock.yaml")
	writeFile(t, cfgPath, baselineConfig(proxyAddr, apiAddr, profileDir, filepath.Join(work, "audit.log")))

	steadyURL := liveURL("steady.liveproof.test", upstream.port, "/steady")
	deviantURL := liveURL("deviant.liveproof.test", upstream.port, "/deviant")

	first := startPipelock(t, bin, cfgPath, proxyAddr)
	status, body := fetchViaPipelock(t, proxyAddr, baselineAgent, steadyURL)
	requireStatus(t, "restart learning fetch", status, http.StatusOK, body)
	status, body = fetchViaPipelock(t, proxyAddr, "liveproof-evictor", steadyURL)
	requireStatus(t, "restart eviction fetch", status, http.StatusOK, body)
	ratifyBaseline(t, bin, cfgPath, apiAddr, baselineAgent)
	first.stop(t)

	second := startPipelock(t, bin, cfgPath, proxyAddr)
	defer second.stop(t)
	status, body = fetchViaPipelock(t, proxyAddr, baselineAgent, steadyURL)
	requireStatus(t, "post-restart matching fetch", status, http.StatusOK, body)
	status, body = fetchViaPipelock(t, proxyAddr, baselineAgent, deviantURL)
	requireStatus(t, "post-restart deviation fetch", status, http.StatusForbidden, body)
	requireContains(t, "post-restart baseline block body", body, "baseline deviation")
}

type liveServer struct {
	url  string
	port string
}

type liveProxy struct {
	cancel   context.CancelFunc
	errCh    <-chan error
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	stopOnce sync.Once
}

func buildPipelock(t *testing.T) string {
	t.Helper()

	buildOnce.Do(func() {
		buildBinDir, errBuildPipelock = os.MkdirTemp("", "pipelock-liveproof-bin-*")
		if errBuildPipelock != nil {
			return
		}
		buildBin = filepath.Join(buildBinDir, "pipelock")

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", buildBin, "./cmd/pipelock")
		cmd.Dir = repoRoot(t)
		cmd.Env = goCommandEnv()
		buildOutput, errBuildPipelock = cmd.CombinedOutput()
	})
	if errBuildPipelock != nil {
		t.Fatalf("building shipped pipelock binary: %v\n%s", errBuildPipelock, buildOutput)
	}
	return buildBin
}

type liveMCPUpstream struct {
	liveServer
	mu        sync.Mutex
	toolCalls []string
}

func startLiveMCPHTTPServer(t *testing.T) *liveMCPUpstream {
	t.Helper()

	upstream := &liveMCPUpstream{}
	upstream.liveServer = startLiveHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "stream not used in liveproof", http.StatusMethodNotAllowed)
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
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json-rpc", http.StatusBadRequest)
			return
		}
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Mcp-Session-Id", "liveproof-session")
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"liveproof","version":"1.0.0"}}}`, req.ID)
		case "tools/list":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"live_defer","description":"held liveproof tool","inputSchema":{"type":"object"}}]}}`, req.ID)
		case "tools/call":
			upstream.mu.Lock()
			upstream.toolCalls = append(upstream.toolCalls, string(body))
			upstream.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"called %s"}]}}`, req.ID, req.Params.Name)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, req.ID)
		}
	}))
	return upstream
}

func (u *liveMCPUpstream) toolCallCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.toolCalls)
}

type liveMCPProxy struct {
	cancel   context.CancelFunc
	errCh    <-chan error
	stdin    io.WriteCloser
	stdout   <-chan string
	stderr   *lockedStringBuffer
	stopOnce sync.Once
}

type lockedStringBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedStringBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedStringBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startMCPProxy(t *testing.T, bin, cfgPath, apiAddr, upstreamURL string) *liveMCPProxy {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	stderr := &lockedStringBuffer{}
	cmd := exec.CommandContext(ctx, bin, "mcp", "proxy", "--config", cfgPath, "--upstream", upstreamURL)
	cmd.Env = append(os.Environ(), "PIPELOCK_HOME="+filepath.Join(t.TempDir(), "home"))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatalf("open mcp proxy stdin: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("open mcp proxy stdout: %v", err)
	}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("starting mcp proxy: %v\nstderr:\n%s", err, stderr.String())
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Wait()
		close(errCh)
	}()
	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	proxy := &liveMCPProxy{cancel: cancel, errCh: errCh, stdin: stdin, stdout: lines, stderr: stderr}
	t.Cleanup(func() {
		proxy.stop(t)
	})
	waitForDeferredAPI(t, apiAddr, errCh, stderr)
	return proxy
}

func (p *liveMCPProxy) stop(t *testing.T) {
	t.Helper()
	p.stopOnce.Do(func() {
		_ = p.stdin.Close()
		p.cancel()
		select {
		case <-p.errCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("mcp proxy process did not exit after cancellation\nstderr:\n%s", p.stderr.String())
		}
	})
}

func (p *liveMCPProxy) send(t *testing.T, msg string) {
	t.Helper()
	if _, err := io.WriteString(p.stdin, msg+"\n"); err != nil {
		t.Fatalf("write MCP stdin: %v\nstderr:\n%s", err, p.stderr.String())
	}
}

func (p *liveMCPProxy) requireNoResponse(t *testing.T, label string) {
	t.Helper()
	select {
	case line := <-p.stdout:
		t.Fatalf("%s produced unexpected stdout response while held: %s\nstderr:\n%s", label, line, p.stderr.String())
	case err := <-p.errCh:
		t.Fatalf("%s: mcp proxy exited while waiting for held request: %v\nstderr:\n%s", label, err, p.stderr.String())
	case <-time.After(heldSettleTimeout):
	}
}

func (p *liveMCPProxy) readRPCResponse(t *testing.T, label string) liveRPCResponse {
	t.Helper()
	timer := time.NewTimer(rpcReadTimeout)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-p.stdout:
			if !ok {
				t.Fatalf("%s: stdout closed\nstderr:\n%s", label, p.stderr.String())
			}
			var resp liveRPCResponse
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				t.Fatalf("%s: decode stdout line %q: %v\nstderr:\n%s", label, line, err, p.stderr.String())
			}
			return resp
		case err := <-p.errCh:
			t.Fatalf("%s: mcp proxy exited: %v\nstderr:\n%s", label, err, p.stderr.String())
		case <-timer.C:
			t.Fatalf("%s timed out waiting for stdout\nstderr:\n%s", label, p.stderr.String())
		}
	}
}

type liveRPCResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func requireMCPHandshake(t *testing.T, proxy *liveMCPProxy) {
	t.Helper()
	proxy.send(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"liveproof","version":"1.0.0"}}}`)
	initResp := proxy.readRPCResponse(t, "initialize response")
	if string(initResp.ID) != "1" || initResp.Error != nil || len(initResp.Result) == 0 {
		t.Fatalf("initialize response = %+v, want result id 1", initResp)
	}
	proxy.send(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	proxy.send(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	listResp := proxy.readRPCResponse(t, "tools/list response")
	if string(listResp.ID) != "2" || listResp.Error != nil || !bytes.Contains(listResp.Result, []byte("live_defer")) {
		t.Fatalf("tools/list response = %+v, want live_defer result", listResp)
	}
}

func requireRPCError(t *testing.T, resp liveRPCResponse, wantID, wantMessage string) {
	t.Helper()
	if string(resp.ID) != wantID {
		t.Fatalf("response id = %s, want %s", resp.ID, wantID)
	}
	if resp.Error == nil {
		t.Fatalf("response id %s had no error: %+v", wantID, resp)
	}
	if resp.Error.Message != wantMessage {
		t.Fatalf("response id %s error message = %q, want %q", wantID, resp.Error.Message, wantMessage)
	}
}

func requireRPCErrorIDs(t *testing.T, responses []liveRPCResponse, want map[string]string) {
	t.Helper()
	seen := make(map[string]bool, len(responses))
	for _, resp := range responses {
		wantMessage, ok := want[string(resp.ID)]
		if !ok {
			t.Fatalf("unexpected response id %s in %+v", resp.ID, responses)
		}
		requireRPCError(t, resp, string(resp.ID), wantMessage)
		seen[string(resp.ID)] = true
	}
	for id := range want {
		if !seen[id] {
			t.Fatalf("missing response id %s in %+v", id, responses)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve liveproof source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func startPipelock(t *testing.T, bin, cfgPath, proxyAddr string) *liveProxy {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	proxy := &liveProxy{cancel: cancel, stdout: stdout, stderr: stderr}
	t.Cleanup(func() {
		proxy.stop(t)
	})

	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("mkdir pipelock home: %v", err)
	}

	cmd := exec.CommandContext(ctx, bin, "run", "--config", cfgPath)
	cmd.Env = append(os.Environ(), "PIPELOCK_HOME="+home)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting pipelock: %v\nstderr:\n%s", err, stderr.String())
	}
	errCh := make(chan error, 1)
	proxy.errCh = errCh
	go func() {
		errCh <- cmd.Wait()
		close(errCh)
	}()

	waitForHTTP(t, "proxy health", "http://"+proxyAddr+"/health", errCh, stderr)
	return proxy
}

func (p *liveProxy) stop(t *testing.T) {
	t.Helper()
	p.stopOnce.Do(func() {
		p.cancel()
		if p.errCh == nil {
			return
		}
		select {
		case <-p.errCh:
		case <-time.After(5 * time.Second):
			t.Fatal("pipelock process did not exit after cancellation")
		}
	})
}

func startLiveHTTPServer(t *testing.T, handler http.Handler) liveServer {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind liveproof upstream listener: %v", err)
	}
	addr := ln.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("split upstream addr %q: %v", addr, err)
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("liveproof upstream server exited: %v", err)
		}
	})

	return liveServer{url: "http://" + addr, port: port}
}

func liveHTTPHandler(t *testing.T, publishHits *atomic.Int64) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/steady", "/deviant", "/article":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintf(w, "liveproof response for %s", r.URL.Path)
		case "/auth/update":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if publishHits != nil {
				publishHits.Add(1)
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "published")
		default:
			http.NotFound(w, r)
		}
	})
}

func waitForHTTP(t *testing.T, label, target string, errCh <-chan error, stderr *bytes.Buffer) {
	t.Helper()

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			t.Fatalf("%s: pipelock exited before ready: %v\nstderr:\n%s", label, err, stderr.String())
		case <-deadline.C:
			t.Fatalf("%s did not become ready\nstderr:\n%s", label, stderr.String())
		case <-ticker.C:
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
			if err != nil {
				t.Fatalf("%s: build readiness request: %v", label, err)
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
}

func ratifyBaseline(t *testing.T, bin, cfgPath, apiAddr, agent string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := runPipelock(ctx, bin,
		"baseline",
		"--config", cfgPath,
		"--api-url", "http://"+apiAddr,
		"--api-token", liveproofAPIToken,
		"ratify", agent,
	)
	if err != nil {
		t.Fatalf("ratifying baseline through shipped CLI: %v\n%s", err, out)
	}
	requireContains(t, "ratify CLI output", out, "ratified baseline "+agent)
}

func runPipelock(ctx context.Context, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runDeferredCLI(t *testing.T, bin, apiAddr string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fullArgs := append([]string{
		"session",
		"--api-url", "http://" + apiAddr,
		"--api-token", liveproofAPIToken,
		"deferred",
	}, args...)
	out, err := runPipelock(ctx, bin, fullArgs...)
	if err != nil {
		t.Fatalf("pipelock %s: %v\n%s", strings.Join(fullArgs, " "), err, out)
	}
	return out
}

type liveDeferredList struct {
	Held  []liveDeferredHeld `json:"held"`
	Count int                `json:"count"`
}

type liveDeferredHeld struct {
	DeferID       string `json:"defer_id"`
	Method        string `json:"method"`
	Target        string `json:"target"`
	ParentDeferID string `json:"parent_defer_id"`
	CascadeDepth  int    `json:"cascade_depth"`
}

func waitDeferredList(t *testing.T, bin, apiAddr string, wantCount int) (liveDeferredList, string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastRaw string
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := runPipelock(ctx, bin,
			"session",
			"--api-url", "http://"+apiAddr,
			"--api-token", liveproofAPIToken,
			"deferred",
			"list",
			"--json",
		)
		cancel()
		lastRaw = out
		lastErr = err
		if err == nil {
			var list liveDeferredList
			if decErr := json.Unmarshal([]byte(out), &list); decErr != nil {
				t.Fatalf("decode deferred list JSON %q: %v", out, decErr)
			}
			if list.Count == wantCount && len(list.Held) == wantCount {
				return list, out
			}
		}
		<-ticker.C
	}
	t.Fatalf("deferred list count did not reach %d; lastErr=%v raw=%s", wantCount, lastErr, lastRaw)
	return liveDeferredList{}, ""
}

func findHeldByDepth(t *testing.T, list liveDeferredList, depth int) liveDeferredHeld {
	t.Helper()
	var matches []liveDeferredHeld
	for _, held := range list.Held {
		if held.CascadeDepth == depth {
			matches = append(matches, held)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("held actions at depth %d = %+v, want exactly one in %+v", depth, matches, list.Held)
	}
	if matches[0].Target != "live_defer" || matches[0].Method != "tools/call" {
		t.Fatalf("held action at depth %d = %+v, want live_defer tools/call", depth, matches[0])
	}
	return matches[0]
}

func fetchViaPipelock(t *testing.T, proxyAddr, agent, target string) (int, string) {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	reqURL := "http://" + proxyAddr + "/fetch?url=" + url.QueryEscape(target)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, nil)
	if err != nil {
		t.Fatalf("build fetch request: %v", err)
	}
	if agent != "" {
		req.Header.Set("X-Pipelock-Agent", agent)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch through pipelock: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read fetch response body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func postThroughForwardProxy(t *testing.T, proxyAddr, target, body string) (int, string) {
	t.Helper()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build forward proxy POST: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST through forward proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read forward proxy response body: %v", err)
	}
	return resp.StatusCode, string(respBody)
}

func liveURL(host, port, path string) string {
	return "http://" + net.JoinHostPort(host, port) + path
}

func baselineConfig(proxyAddr, apiAddr, profileDir, logPath string) string {
	return fmt.Sprintf(`version: 1
mode: balanced
enforce: true
fetch_proxy:
  listen: %s
  timeout_seconds: 5
  max_response_mb: 1
forward_proxy:
  enabled: true
logging:
  format: json
  output: file
  file: %s
session_profiling:
  enabled: true
  anomaly_action: warn
  domain_burst: 100
  window_minutes: 5
  max_sessions: 1
  session_ttl_minutes: 30
  cleanup_interval_seconds: 60
behavioral_baseline:
  enabled: true
  profile_dir: %s
  learning_window: 1
  deviation_action: block
  sensitivity_sigma: 0
  lock_dimensions:
    - domains
    - requests
  poison_resistance: false
%s
dns:
  host_overrides:
    steady.liveproof.test:
      - "127.0.0.1"
    deviant.liveproof.test:
      - "127.0.0.1"
`, yq(proxyAddr), yq(logPath), yq(profileDir), commonSecurityYAML(apiAddr))
}

func taintConfig(proxyAddr, apiAddr, logPath string) string {
	return fmt.Sprintf(`version: 1
mode: balanced
enforce: true
default_agent_identity: %s
bind_default_agent_identity: true
fetch_proxy:
  listen: %s
  timeout_seconds: 5
  max_response_mb: 1
forward_proxy:
  enabled: true
request_body_scanning:
  enabled: true
  action: block
  scan_headers: true
logging:
  format: json
  output: file
  file: %s
session_profiling:
  enabled: true
  max_sessions: 10
%s
dns:
  host_overrides:
    source.liveproof.test:
      - "127.0.0.1"
    publish.liveproof.test:
      - "127.0.0.1"
taint:
  enabled: true
  policy: strict
`, yq(taintAgent), yq(proxyAddr), yq(logPath), commonSecurityYAML(apiAddr))
}

func commonSecurityYAML(apiAddr string) string {
	return fmt.Sprintf(`kill_switch:
  api_token: %s
  api_listen: %s
ssrf:
  ip_allowlist:
    - "127.0.0.0/8"
    - "::1/128"
trusted_domains:
  - "*.liveproof.test"
response_scanning:
  enabled: false
`, yq(liveproofAPIToken), yq(apiAddr))
}

func deferredMCPConfig(apiAddr, evidenceDir, signingKeyPath string) string {
	return fmt.Sprintf(`version: 1
mode: balanced
enforce: true
kill_switch:
  api_token: %s
  api_listen: %s
ssrf:
  ip_allowlist:
    - "127.0.0.0/8"
    - "::1/128"
response_scanning:
  enabled: false
mcp_input_scanning:
  enabled: false
  action: block
mcp_tool_scanning:
  enabled: false
  action: warn
mcp_tool_policy:
  enabled: true
  action: warn
  defer_resolver_profiles:
    slow_operator:
      exec: ["/bin/sh", "-c", "sleep 30; printf block"]
      reason: "operator CLI liveproof owns resolution"
  rules:
    - name: hold-live-defer
      tool_pattern: "^live_defer$"
      action: defer
      resolution_policy:
        resolver_profile: slow_operator
        allow_on:
          approval: true
defer:
  enabled: true
  timeout_seconds: 60
  max_pending: 16
  max_pending_per_session: 16
  max_pending_bytes: 1048576
  max_cascade_depth: 2
flight_recorder:
  enabled: true
  dir: %s
  signing_key_path: %s
  redact: true
`, yq(liveproofAPIToken), yq(apiAddr), yq(evidenceDir), yq(signingKeyPath))
}

func writeLiveProofSigningKey(t *testing.T, path string) string {
	t.Helper()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate liveproof signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("write liveproof signing key: %v", err)
	}
	return path
}

func waitForDeferredAPI(t *testing.T, apiAddr string, errCh <-chan error, stderr fmt.Stringer) {
	t.Helper()

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			t.Fatalf("deferred operator API: pipelock exited before ready: %v\nstderr:\n%s", err, stderr.String())
		case <-deadline.C:
			t.Fatalf("deferred operator API did not become ready\nstderr:\n%s", stderr.String())
		case <-ticker.C:
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+apiAddr+"/api/v1/deferred", nil)
			if err != nil {
				t.Fatalf("build deferred API readiness request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+liveproofAPIToken)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
}

type liveDeferredJournalEntry struct {
	DeferID string `json:"defer_id"`
	State   string `json:"state"`
	Source  string `json:"source"`
}

func waitDeferredJournalSource(t *testing.T, path, deferID, source string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last []liveDeferredJournalEntry
	for time.Now().Before(deadline) {
		entries := readDeferredJournal(t, path)
		last = entries
		for _, entry := range entries {
			if entry.DeferID == deferID && entry.Source == source {
				return
			}
		}
		<-ticker.C
	}
	t.Fatalf("deferred journal missing defer_id=%s source=%s; entries=%+v", deferID, source, last)
}

func readDeferredJournal(t *testing.T, path string) []liveDeferredJournalEntry {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatalf("open deferred journal: %v", err)
	}
	defer func() { _ = f.Close() }()
	var entries []liveDeferredJournalEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var entry liveDeferredJournalEntry
		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			t.Fatalf("decode deferred journal line %q: %v", sc.Text(), err)
		}
		entries = append(entries, entry)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan deferred journal: %v", err)
	}
	return entries
}

func waitFlightRecorderResolutionSource(t *testing.T, dir, source string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last []string
	for time.Now().Before(deadline) {
		sources := readFlightRecorderResolutionSources(t, dir)
		last = sources
		for _, got := range sources {
			if got == source {
				return
			}
		}
		<-ticker.C
	}
	t.Fatalf("flight recorder missing resolution_source=%s; sources=%v", source, last)
}

func readFlightRecorderResolutionSources(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatalf("read flight recorder dir: %v", err)
	}
	var sources []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") || entry.Name() == "deferred-actions.jsonl" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		f, err := os.Open(filepath.Clean(path))
		if err != nil {
			t.Fatalf("open flight recorder %s: %v", path, err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var row struct {
				Type   string `json:"type"`
				Detail struct {
					ActionRecord struct {
						ResolutionSource string `json:"resolution_source"`
					} `json:"action_record"`
				} `json:"detail"`
			}
			if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
				_ = f.Close()
				t.Fatalf("decode flight recorder line %q: %v", sc.Text(), err)
			}
			if row.Type == "action_receipt" && row.Detail.ActionRecord.ResolutionSource != "" {
				sources = append(sources, row.Detail.ActionRecord.ResolutionSource)
			}
		}
		if err := sc.Err(); err != nil {
			_ = f.Close()
			t.Fatalf("scan flight recorder %s: %v", path, err)
		}
		_ = f.Close()
	}
	return sources
}

func yq(s string) string {
	return strconv.Quote(filepath.ToSlash(s))
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot reserve ephemeral TCP address: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close ephemeral listener: %v", err)
	}
	return addr
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func goCommandEnv() []string {
	return append(os.Environ(),
		"TMPDIR="+filepath.Join(os.Getenv("HOME"), ".cache", "pipelock-tmp"),
		"GOTMPDIR="+filepath.Join(os.Getenv("HOME"), ".cache", "pipelock-tmp"),
		"GOCACHE="+filepath.Join(os.Getenv("HOME"), ".cache", "go-build"),
	)
}

func requireStatus(t *testing.T, label string, got, want int, body string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s status = %d, want %d\nbody:\n%s", label, got, want, body)
	}
}

func requireContains(t *testing.T, label, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("%s = %q, want substring %q", label, got, want)
	}
}

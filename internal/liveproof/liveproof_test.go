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
	"bytes"
	"context"
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
)

const (
	liveproofAPIToken = "liveproof-admin-token"
	baselineAgent     = "liveproof-baseline"
	taintAgent        = "liveproof-taint"
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

// TestLiveProofDeferredCascade documents the current shipped-surface gap for
// deferred-action cascade proofing. A customer can configure resolver profiles
// for supported MCP defer transports, but there is no shipped operator CLI/API
// to enumerate a pending defer tree and deny a parent while observing child
// cascade resolution and depth-cap behavior from outside the process.
func TestLiveProofDeferredCascade(t *testing.T) {
	t.Skip("shipped-surface gap: no `pipelock session`/admin API surface exists to enumerate and explicitly deny pending deferred actions, so parent-denial cascade and depth-cap behavior cannot be live-proven the customer way without an internal seam")
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
		buildOutput, errBuildPipelock = cmd.CombinedOutput()
	})
	if errBuildPipelock != nil {
		t.Fatalf("building shipped pipelock binary: %v\n%s", errBuildPipelock, buildOutput)
	}
	return buildBin
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

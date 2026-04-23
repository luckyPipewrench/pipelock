// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	mcptools "github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

const serverTestUpstreamURL = "http://127.0.0.1:1"

// newServerTestFreePort returns a free 127.0.0.1 TCP port by binding and
// releasing it, same pattern used in run_test.go:freePort.
func newServerTestFreePort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// newTestServer builds a Server with an in-memory stderr sink and no
// listener bindings yet. Defaults() provides a populated api_allowlist so
// strict-mode overrides stay valid through cfg.Validate. The returned
// buffer captures every stderr write performed during construction and
// any subsequent Reload call.
func newTestServer(t *testing.T, mutate func(*ServerOpts)) (*Server, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	opts := ServerOpts{
		Stdout: buf,
		Stderr: buf,
	}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })
	return s, buf
}

func waitForServerCancel(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.cancelMu.Lock()
		ready := s.internalCancel != nil
		s.cancelMu.Unlock()
		if ready {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not publish internal cancel")
}

// TestNewServer_AppliesCLIOverrides verifies that ModeChanged / ListenChanged
// drive Mode and FetchProxy.Listen overrides on the loaded config. This is
// the behavior RunCmd used to implement via cobra.Flag.Changed().
func TestNewServer_AppliesCLIOverrides(t *testing.T) {
	listenAddr := newServerTestFreePort(t)
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.Mode = config.ModeAudit
		o.ModeChanged = true
		o.Listen = listenAddr
		o.ListenChanged = true
	})
	if s.cfg.Mode != config.ModeAudit {
		t.Errorf("Mode override: want %q, got %q", config.ModeAudit, s.cfg.Mode)
	}
	if s.cfg.FetchProxy.Listen != listenAddr {
		t.Errorf("Listen override: want %q, got %q", listenAddr, s.cfg.FetchProxy.Listen)
	}

	// Without ModeChanged / ListenChanged the opts values must be ignored.
	s2, _ := newTestServer(t, func(o *ServerOpts) {
		o.Mode = config.ModeStrict // intentionally different
		o.Listen = "127.0.0.1:1"   // intentionally different
	})
	if s2.cfg.Mode != config.ModeBalanced {
		t.Errorf("Mode without ModeChanged: want default %q, got %q", config.ModeBalanced, s2.cfg.Mode)
	}
	if s2.cfg.FetchProxy.Listen == "127.0.0.1:1" {
		t.Errorf("Listen override fired without ListenChanged: got %q", s2.cfg.FetchProxy.Listen)
	}
}

// TestNewServer_ResolveRuntimeRuns verifies the ResolveRuntime pipeline
// wired through NewServer. With --mcp-listen the runtime mode is
// RuntimeForwardWithMCPListener which WrapsMCP, so MCP input / tool /
// policy scanning auto-enable and the emitResolveInfoLogs helper writes
// "listener mode" notices to stderr.
func TestNewServer_ResolveRuntimeRuns(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.MCPListen = newServerTestFreePort(t)
		o.MCPUpstream = serverTestUpstreamURL
	})
	if s.runtimeMode != config.RuntimeForwardWithMCPListener {
		t.Errorf("runtimeMode: want RuntimeForwardWithMCPListener, got %v", s.runtimeMode)
	}
	if !s.cfg.MCPInputScanning.Enabled {
		t.Errorf("MCPInputScanning should auto-enable in listener mode")
	}
	if !s.cfg.MCPToolScanning.Enabled {
		t.Errorf("MCPToolScanning should auto-enable in listener mode")
	}
	if !s.cfg.MCPToolPolicy.Enabled {
		t.Errorf("MCPToolPolicy should auto-enable in listener mode")
	}
	if s.bundleResult == nil {
		t.Errorf("bundleResult must be populated by ResolveRuntime merge callback")
	}
	if !buf.contains("auto-enabling MCP input scanning for listener mode") {
		t.Errorf("stderr missing MCP input scanning auto-enable notice: %q", buf.String())
	}
}

// TestServer_StartShutdown verifies that Start blocks, Shutdown releases
// it, and Start returns nil on clean shutdown. Uses an ephemeral listen
// address so nothing conflicts with a developer's already-running
// pipelock instance.
func TestServer_StartShutdown(t *testing.T) {
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.Listen = newServerTestFreePort(t)
		o.ListenChanged = true
	})

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- s.Start(ctx)
	}()

	waitForServerCancel(t, s)

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error after Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Start did not return within 5s of Shutdown")
	}
}

func TestServer_StateHelpers(t *testing.T) {
	s, _ := newTestServer(t, nil)

	if got := s.currentConfig(); got != s.cfg {
		t.Fatalf("currentConfig() = %p, want %p", got, s.cfg)
	}
	hash := s.cfg.Hash()
	if s.shouldSkipReload(hash) {
		t.Fatal("shouldSkipReload returned true before any successful reload")
	}
	s.recordReloadSuccess(hash)
	if !s.shouldSkipReload(hash) {
		t.Fatal("shouldSkipReload returned false immediately after recordReloadSuccess")
	}
}

func TestRuntimeMCPBuilders(t *testing.T) {
	if buildMCPInputCfg(nil) != nil {
		t.Fatal("nil config should not build MCP input config")
	}
	cfg := config.Defaults()
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = config.ActionBlock
	cfg.MCPToolScanning.Enabled = true
	cfg.MCPToolScanning.Action = config.ActionWarn
	cfg.MCPToolScanning.DetectDrift = true
	cfg.ToolChainDetection.Enabled = true
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 128
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 1
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 1024
	cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 1

	inputCfg := buildMCPInputCfg(cfg)
	if inputCfg == nil || inputCfg.Action != config.ActionBlock {
		t.Fatalf("input cfg = %+v, want block action", inputCfg)
	}
	baseline := mcptools.NewToolBaseline()
	extra := []*mcptools.ExtraPoisonPattern{{Name: "unsafe"}}
	toolCfg := buildMCPToolCfg(cfg, extra, baseline)
	if toolCfg == nil || toolCfg.Action != config.ActionWarn || !toolCfg.DetectDrift || toolCfg.Baseline != baseline {
		t.Fatalf("tool cfg = %+v", toolCfg)
	}
	if chain := buildMCPChainMatcher(cfg, metrics.New()); chain == nil {
		t.Fatal("expected chain matcher when tool chain detection is enabled")
	}
	cee := buildMCPCEE(cfg, metrics.New())
	if cee == nil || cee.Tracker == nil || cee.Buffer == nil {
		t.Fatalf("CEE deps = %+v, want tracker and buffer", cee)
	}
}

func TestServer_StartAuxiliaryListeners(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.Listen = newServerTestFreePort(t)
		o.ListenChanged = true
		o.MCPListen = newServerTestFreePort(t)
		o.MCPUpstream = serverTestUpstreamURL
		o.ReverseProxy = true
		o.ReverseUpstream = serverTestUpstreamURL
		o.ReverseListen = newServerTestFreePort(t)
		o.CaptureOutput = t.TempDir()
		o.CaptureDuration = 150 * time.Millisecond
		o.AgentArgs = []string{"agent", "--flag"}
	})
	s.cfg.MetricsListen = newServerTestFreePort(t)
	s.cfg.ScanAPI.Listen = newServerTestFreePort(t)
	s.cfg.ScanAPI.ConnectionLimit = 1
	s.cfg.ScanAPI.Timeouts = config.ScanAPITimeouts{
		Read:  "50ms",
		Write: "50ms",
	}
	s.cfg.KillSwitch.APIToken = "test-token"
	s.cfg.KillSwitch.APIListen = newServerTestFreePort(t)
	s.apiOnSeparatePort = true
	s.cfg.WebSocketProxy.Enabled = true

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(context.Background())
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after capture duration")
	}

	out := buf.String()
	for _, want := range []string{
		"Stats:",
		"API:",
		"MCP:",
		"RevPx:",
		"WS:",
		"Capture:",
		"Agent:",
		"metrics listening",
		"scan API listening",
		"reverse proxy listening",
		"capture duration reached",
		"Pipelock stopped.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("startup output missing %q:\n%s", want, out)
		}
	}
}

// TestServer_Reload_StrictRejectsDowngrade verifies that when the running
// config is strict, a reload that would flip a security-sensitive knob
// (here: downgrading mode to balanced) is rejected with an error and the
// proxy continues running its previous config.
func TestServer_Reload_StrictRejectsDowngrade(t *testing.T) {
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.Mode = config.ModeStrict
		o.ModeChanged = true
	})

	// Use the proxy's live config as the starting point so the clone
	// preserves every other invariant (api_allowlist, listeners, ...).
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.Mode = config.ModeBalanced

	err := s.Reload(newCfg)
	if err == nil {
		t.Fatalf("Reload should reject strict→balanced downgrade, got nil error")
	}
	if !strings.Contains(err.Error(), "security downgrade") {
		t.Errorf("error should mention security downgrade, got: %v", err)
	}

	// The live proxy config should still be strict.
	live := s.proxy.CurrentConfig()
	if live.Mode != config.ModeStrict {
		t.Errorf("live config mode after rejected reload: want %q, got %q", config.ModeStrict, live.Mode)
	}
}

// TestServer_Reload_StrictAllowsApiTokenRotation verifies that rotating the
// kill-switch api_token under strict mode is a clean reload (no security
// downgrade warnings) and the proxy picks up the new token value.
func TestServer_Reload_StrictAllowsApiTokenRotation(t *testing.T) {
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.Mode = config.ModeStrict
		o.ModeChanged = true
	})
	oldLive := s.proxy.CurrentConfig().Clone()
	oldLive.KillSwitch.APIToken = "old-token"
	if err := s.Reload(oldLive); err != nil {
		t.Fatalf("seed reload with initial token: %v", err)
	}
	// Advance past the 2s dedup window so the rotation is not silently
	// discarded by Reload's stacked-event dedup.
	s.lastReloadAt = time.Time{}

	rotated := s.proxy.CurrentConfig().Clone()
	rotated.KillSwitch.APIToken = "new-token"

	if err := s.Reload(rotated); err != nil {
		t.Fatalf("strict-mode api_token rotation should not error, got: %v", err)
	}

	live := s.proxy.CurrentConfig()
	if live.Mode != config.ModeStrict {
		t.Errorf("mode changed unexpectedly: want %q, got %q", config.ModeStrict, live.Mode)
	}
	if live.KillSwitch.APIToken != "new-token" {
		t.Errorf("api_token not rotated: want %q, got %q", "new-token", live.KillSwitch.APIToken)
	}
}

func TestServer_Reload_RejectsRestartRequiredProxyModes(t *testing.T) {
	s, _ := newTestServer(t, nil)

	for _, tt := range []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{
			name: "forward proxy",
			mutate: func(c *config.Config) {
				c.ForwardProxy.Enabled = true
			},
			want: "forward proxy cannot be enabled via reload",
		},
		{
			name: "websocket proxy",
			mutate: func(c *config.Config) {
				c.WebSocketProxy.Enabled = true
			},
			want: "WebSocket proxy cannot be enabled via reload",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newCfg := s.proxy.CurrentConfig().Clone()
			tt.mutate(newCfg)
			err := s.Reload(newCfg)
			if err == nil {
				t.Fatal("expected reload rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestServer_Reload_PreservesRestartOnlyFields(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.ReverseProxy = true
		o.ReverseUpstream = serverTestUpstreamURL
		o.ReverseListen = "127.0.0.1:18080"
	})

	oldCfg := s.proxy.CurrentConfig()
	oldCfg.KillSwitch.APIListen = "127.0.0.1:18081"
	oldCfg.MetricsListen = "127.0.0.1:18082"
	oldCfg.ScanAPI.Listen = "127.0.0.1:18083"
	oldCfg.ScanAPI.ConnectionLimit = 2
	oldCfg.ScanAPI.Timeouts = config.ScanAPITimeouts{Read: "1s", Write: "1s"}
	oldCfg.FlightRecorder.SigningKeyPath = "/tmp/old-signing-key"

	newCfg := oldCfg.Clone()
	newCfg.KillSwitch.APIListen = "127.0.0.1:28081"
	newCfg.MetricsListen = "127.0.0.1:28082"
	newCfg.ScanAPI.Listen = "127.0.0.1:28083"
	newCfg.ScanAPI.ConnectionLimit = 4
	newCfg.ScanAPI.Timeouts = config.ScanAPITimeouts{Read: "2s", Write: "2s"}
	newCfg.FlightRecorder.SigningKeyPath = "/tmp/new-signing-key"
	newCfg.ReverseProxy.Listen = "127.0.0.1:28084"
	newCfg.ReverseProxy.Upstream = "http://127.0.0.1:2"

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if live.KillSwitch.APIListen != oldCfg.KillSwitch.APIListen {
		t.Fatalf("kill switch API listen = %q, want %q", live.KillSwitch.APIListen, oldCfg.KillSwitch.APIListen)
	}
	if live.MetricsListen != oldCfg.MetricsListen {
		t.Fatalf("metrics listen = %q, want %q", live.MetricsListen, oldCfg.MetricsListen)
	}
	if live.ScanAPI.Listen != oldCfg.ScanAPI.Listen ||
		live.ScanAPI.ConnectionLimit != oldCfg.ScanAPI.ConnectionLimit ||
		live.ScanAPI.Timeouts != oldCfg.ScanAPI.Timeouts {
		t.Fatalf("scan API listener settings not preserved: %+v", live.ScanAPI)
	}
	if live.FlightRecorder.SigningKeyPath != oldCfg.FlightRecorder.SigningKeyPath {
		t.Fatalf("signing key path = %q, want %q", live.FlightRecorder.SigningKeyPath, oldCfg.FlightRecorder.SigningKeyPath)
	}
	if live.ReverseProxy != oldCfg.ReverseProxy {
		t.Fatalf("reverse proxy settings not preserved: %+v", live.ReverseProxy)
	}
	for _, want := range []string{
		"kill_switch.api_listen changed",
		"metrics_listen changed",
		"scan_api listener settings changed",
		"flight_recorder.signing_key_path changed",
		"reverse_proxy settings changed",
	} {
		if !buf.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, buf.String())
		}
	}
}

// TestServer_Reload_ProxyFailureStaysFailSafe verifies that when proxy.Reload
// aborts its internal swap, Server.Reload does not continue applying partial
// side effects such as kill switch state changes or success dedup markers.
func TestServer_Reload_ProxyFailureStaysFailSafe(t *testing.T) {
	s, _ := newTestServer(t, nil)

	oldCfg := s.proxy.CurrentConfig()
	oldScanner := s.proxy.ScannerPtr().Load()
	oldHash := s.lastReloadHash

	newCfg := oldCfg.Clone()
	newCfg.KillSwitch.Enabled = true
	newCfg.KillSwitch.Message = "new runtime"
	newCfg.MediationEnvelope.Enabled = true
	newCfg.MediationEnvelope.Sign = true
	newCfg.MediationEnvelope.SigningKeyPath = "/definitely/missing-signing-key"

	err := s.Reload(newCfg)
	if err == nil {
		t.Fatalf("Reload should fail when proxy keeps the previous config")
	}
	if !strings.Contains(err.Error(), "kept previous config") {
		t.Errorf("error should mention previous config preservation, got: %v", err)
	}
	if s.proxy.CurrentConfig() != oldCfg {
		t.Errorf("live proxy config changed despite failed reload")
	}
	if s.proxy.ScannerPtr().Load() != oldScanner {
		t.Errorf("live proxy scanner changed despite failed reload")
	}
	if s.cfg != oldCfg {
		t.Errorf("server cfg changed despite failed reload")
	}
	if s.killswitch.IsActive() {
		t.Errorf("kill switch became active despite failed reload")
	}
	if s.lastReloadHash != oldHash {
		t.Errorf("reload dedup state advanced on failed reload")
	}
}

// TestServer_MCPListener_ResponseScanningFallback verifies the
// ResolveRuntime interaction for --mcp-listen: listener mode does NOT
// trigger the response-scanning fallback (that is only for RuntimeMCPProxy
// and RuntimeMCPScan), and the MCP input scanning auto-enable fires with
// the "listener mode" operator-facing notice.
func TestServer_MCPListener_ResponseScanningFallback(t *testing.T) {
	// Build a config where response scanning is disabled on disk so we
	// can verify listener mode does NOT silently re-enable it (that is
	// MCP proxy mode's responsibility).
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.MCPListen = newServerTestFreePort(t)
		o.MCPUpstream = serverTestUpstreamURL
	})

	// Listener mode does WrapMCP, so input scanning auto-enables with
	// the emitResolveInfoLogs notice we emit for modeLabel="listener".
	if !s.cfg.MCPInputScanning.Enabled {
		t.Errorf("MCPInputScanning should auto-enable under --mcp-listen")
	}
	stderr := buf.String()
	if !strings.Contains(stderr, "auto-enabling MCP input scanning for listener mode") {
		t.Errorf("stderr missing listener-mode auto-enable notice, got: %q", stderr)
	}
	if strings.Contains(stderr, "response scanning was disabled in config, enabling with defaults") {
		t.Errorf("listener mode must NOT run the response-scanning fallback; stderr: %q", stderr)
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/runtimeconfig"
	"github.com/luckyPipewrench/pipelock/internal/config"
	mcptools "github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	serverTestUpstreamURL     = "http://127.0.0.1:1"
	serverTestEphemeralListen = "127.0.0.1:0"
)

type stringerFunc func() string

func (f stringerFunc) String() string { return f() }

func writeServerTestConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
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
	testwait.For(t, 2*time.Second, func() bool {
		s.cancelMu.Lock()
		ready := s.internalCancel != nil
		s.cancelMu.Unlock()
		return ready
	}, "server to publish internal cancel")
}

func waitForServerOutput(t *testing.T, buf *syncBuffer, want string) {
	t.Helper()
	testwait.For(t, 3*time.Second, func() bool {
		return buf.contains(want)
	}, "server output %q:\n%s", want, stringerFunc(buf.String))
}

// TestNewServer_AppliesCLIOverrides verifies that ModeChanged / ListenChanged
// drive Mode and FetchProxy.Listen overrides on the loaded config. This is
// the behavior RunCmd used to implement via cobra.Flag.Changed().
func TestNewServer_AppliesCLIOverrides(t *testing.T) {
	listenAddr := serverTestEphemeralListen
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

func TestNewServer_SurfacesValidateWarnings(t *testing.T) {
	_, buf := newTestServer(t, func(o *ServerOpts) {
		o.Listen = "0.0.0.0:0"
		o.ListenChanged = true
	})
	if !buf.contains("WARNING: fetch_proxy.listen") {
		t.Fatalf("stderr missing fetch_proxy.listen warning:\n%s", buf.String())
	}
}

func TestNewServer_ValidatesListenerFlagPairs(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts ServerOpts
		want string
	}{
		{
			name: "mcp listen without upstream",
			opts: ServerOpts{MCPListen: serverTestEphemeralListen},
			want: "--mcp-listen requires --mcp-upstream",
		},
		{
			name: "mcp upstream without listen",
			opts: ServerOpts{MCPUpstream: serverTestUpstreamURL},
			want: "--mcp-upstream requires --mcp-listen",
		},
		{
			name: "invalid mcp upstream",
			opts: ServerOpts{MCPListen: serverTestEphemeralListen, MCPUpstream: "ftp://127.0.0.1:1"},
			want: "invalid --mcp-upstream",
		},
		{
			name: "reverse proxy without upstream",
			opts: ServerOpts{ReverseProxy: true},
			want: "--reverse-proxy requires --reverse-upstream",
		},
		{
			name: "reverse upstream without proxy",
			opts: ServerOpts{ReverseUpstream: serverTestUpstreamURL},
			want: "--reverse-upstream requires --reverse-proxy",
		},
		{
			name: "invalid reverse upstream",
			opts: ServerOpts{ReverseProxy: true, ReverseUpstream: "ftp://127.0.0.1:1"},
			want: "invalid --reverse-upstream",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.opts)
			if err == nil {
				t.Fatal("NewServer succeeded, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestNewServer_RejectsDeferOnMCPListener(t *testing.T) {
	cfgPath := writeServerTestConfig(t, `
mcp_tool_policy:
  enabled: true
  action: defer
  defer_resolver_profiles:
    approve:
      exec: ["/bin/echo", "allow"]
  rules:
    - name: hold-tool
      tool_pattern: "^dangerous_tool$"
      resolution_policy:
        resolver_profile: approve
        allow_on:
          approval: true
`)
	_, err := NewServer(ServerOpts{
		ConfigFile:  cfgPath,
		MCPListen:   serverTestEphemeralListen,
		MCPUpstream: serverTestUpstreamURL,
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if err == nil {
		t.Fatal("NewServer succeeded, want defer surface validation error")
	}
	if !strings.Contains(err.Error(), "defer is not yet supported on mcp_http_listener") {
		t.Fatalf("error = %q, want mcp_http_listener defer rejection", err.Error())
	}
}

func TestNewServer_DefaultsWritersAndReverseListen(t *testing.T) {
	s, err := NewServer(ServerOpts{
		ReverseProxy:    true,
		ReverseUpstream: serverTestUpstreamURL,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })

	if s.opts.Stdout != io.Discard {
		t.Fatal("nil stdout should default to io.Discard")
	}
	// opts.Stderr is wrapped in a sync writer to serialize concurrent
	// producers (see NewServer); the underlying writer should still be
	// io.Discard when no stderr was provided.
	syncW, ok := s.opts.Stderr.(*stderrSyncWriter)
	if !ok {
		t.Fatalf("opts.Stderr type = %T, want *stderrSyncWriter", s.opts.Stderr)
	}
	if syncW.w != io.Discard {
		t.Fatal("nil stderr should default to io.Discard under the sync wrapper")
	}
	if s.cfg.ReverseProxy.Listen != ":8890" {
		t.Fatalf("reverse listen = %q, want default :8890", s.cfg.ReverseProxy.Listen)
	}
}

func TestNewServer_ReturnsConstructionErrors(t *testing.T) {
	captureFile := filepath.Join(t.TempDir(), "capture-file")
	if err := os.WriteFile(captureFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write capture file: %v", err)
	}
	auditDir := t.TempDir()
	auditCfg := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"logging:",
		"  output: file",
		"  file: " + strconv.Quote(auditDir),
		"",
	}, "\n"))
	missingKeyCfg := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(filepath.Join(t.TempDir(), "evidence")),
		"  signing_key_path: " + strconv.Quote(filepath.Join(t.TempDir(), "missing.key")),
		"",
	}, "\n"))

	for _, tt := range []struct {
		name string
		opts ServerOpts
		want string
	}{
		{
			name: "missing config file",
			opts: ServerOpts{ConfigFile: filepath.Join(t.TempDir(), "missing.yaml")},
			want: "loading config",
		},
		{
			name: "invalid config after CLI override",
			opts: ServerOpts{Mode: "invalid-mode", ModeChanged: true},
			want: "invalid config",
		},
		{
			name: "audit logger open error",
			opts: ServerOpts{ConfigFile: auditCfg},
			want: "creating audit logger",
		},
		{
			name: "invalid capture escrow key",
			opts: ServerOpts{CaptureOutput: t.TempDir(), CaptureEscrowKey: "not-hex"},
			want: "invalid --capture-escrow-public-key",
		},
		{
			name: "capture writer open error",
			opts: ServerOpts{CaptureOutput: captureFile},
			want: "creating capture writer",
		},
		{
			name: "flight recorder signing key load error",
			opts: ServerOpts{ConfigFile: missingKeyCfg},
			want: "loading flight recorder signing key",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.opts)
			if err == nil {
				t.Fatal("NewServer succeeded, want construction error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestNewServer_FlightRecorderAndEnvelopeFromConfig(t *testing.T) {
	tmp := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPath := filepath.Join(tmp, "receipt.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(filepath.Join(tmp, "evidence")),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"mediation_envelope:",
		"  enabled: true",
		"",
	}, "\n"))

	buf := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: buf, Stderr: buf})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })

	if s.recorder == nil {
		t.Fatal("recorder should be initialized")
	}
	if s.receiptEmitter == nil {
		t.Fatal("receipt emitter should be initialized when signing key is configured")
	}
	if s.envelopeEmitter == nil {
		t.Fatal("envelope emitter should be initialized")
	}
	for _, want := range []string{"Recorder:", "Receipts:", "Envelope:"} {
		if !buf.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, buf.String())
		}
	}
}

// TestNewServer_ResolveRuntimeRuns verifies the ResolveRuntime pipeline
// wired through NewServer. With --mcp-listen the runtime mode is
// RuntimeForwardWithMCPListener which WrapsMCP, so MCP input / tool /
// policy scanning auto-enable and the emitResolveInfoLogs helper writes
// "listener mode" notices to stderr.
func TestNewServer_ResolveRuntimeRuns(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.MCPListen = serverTestEphemeralListen
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
		o.Listen = serverTestEphemeralListen
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

func TestServer_StartArmsFileSentry(t *testing.T) {
	watchDir := t.TempDir()
	scanContent := "true"
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"file_sentry:",
		"  enabled: true",
		"  watch_paths:",
		"    - " + strconv.Quote(watchDir),
		"  scan_content: " + scanContent,
		"",
	}, "\n"))

	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.ConfigFile = cfgPath
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		errCh <- s.Start(ctx)
	}()

	waitForServerCancel(t, s)
	waitForServerOutput(t, buf, "file sentry watching 1 path(s)")

	proof := filepath.Join(watchDir, "file-sentry-run-proof.txt")
	content := strings.Join([]string{"AKIA", "IOSFODNN7", "EXAMPLE"}, "")
	if err := os.WriteFile(proof, []byte(content), 0o600); err != nil {
		t.Fatalf("write proof file: %v", err)
	}
	waitForServerOutput(t, buf, "DLP match in "+proof+": AWS Access ID")

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
	if buildMCPToolCfg(nil, nil, nil) != nil {
		t.Fatal("nil config should not build MCP tool config")
	}
	cfg := config.Defaults()
	cfg.MCPInputScanning.Enabled = false
	cfg.MCPInputScanning.ResponseTimeoutSeconds = 7
	timeoutOnlyCfg := buildMCPInputCfg(cfg)
	if timeoutOnlyCfg == nil || timeoutOnlyCfg.Enabled || timeoutOnlyCfg.ResponseTimeoutSeconds != 7 {
		t.Fatalf("timeout-only input cfg = %+v, want disabled scanner with timeout", timeoutOnlyCfg)
	}
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = config.ActionBlock
	cfg.MCPToolScanning.Enabled = true
	cfg.MCPToolScanning.Action = config.ActionWarn
	cfg.MCPToolScanning.DetectDrift = true
	cfg.MCPSessionBinding.Enabled = true
	cfg.MCPSessionBinding.UnknownToolAction = config.ActionBlock
	cfg.MCPSessionBinding.NoBaselineAction = config.ActionWarn
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
	if toolCfg.BindingUnknownAction != config.ActionBlock || toolCfg.BindingNoBaselineAction != config.ActionWarn {
		t.Fatalf("tool binding actions = %q/%q, want block/warn", toolCfg.BindingUnknownAction, toolCfg.BindingNoBaselineAction)
	}
	if chain := buildMCPChainMatcher(cfg, metrics.New()); chain == nil {
		t.Fatal("expected chain matcher when tool chain detection is enabled")
	}
	cee := buildMCPCEE(cfg, metrics.New())
	if cee == nil || cee.Tracker == nil || cee.Buffer == nil {
		t.Fatalf("CEE deps = %+v, want tracker and buffer", cee)
	}
}

func TestServer_RuntimeHelperFallbacksAndCopies(t *testing.T) {
	s := &Server{}
	if got := s.liveReceiptEmitter(); got != nil {
		t.Fatalf("liveReceiptEmitter without proxy = %p, want nil", got)
	}
	if got := s.liveV2ReceiptEmitter(); got != nil {
		t.Fatalf("liveV2ReceiptEmitter without proxy = %p, want nil", got)
	}
	if got := s.liveEnvelopeEmitter(); got != nil {
		t.Fatalf("liveEnvelopeEmitter without proxy = %p, want nil", got)
	}

	pattern := &mcptools.ExtraPoisonPattern{Name: "unsafe"}
	s.mcpToolExtraPoison = []*mcptools.ExtraPoisonPattern{pattern}
	got := s.currentMCPToolExtraPoison()
	if len(got) != 1 || got[0] != pattern {
		t.Fatalf("currentMCPToolExtraPoison() = %+v, want copied slice with pattern", got)
	}
	got[0] = nil
	if s.mcpToolExtraPoison[0] != pattern {
		t.Fatal("currentMCPToolExtraPoison should return a copy of the slice")
	}
}

func TestServer_RefreshRuntimeStateClearsBundleDerivedState(t *testing.T) {
	s, _ := newTestServer(t, nil)
	oldScanner := s.scanner
	s.mcpToolExtraPoison = []*mcptools.ExtraPoisonPattern{{Name: "unsafe"}}

	next := s.cfg.Clone()
	s.refreshRuntimeState(s.cfg, next, nil, nil)

	if s.cfg != next {
		t.Fatal("refreshRuntimeState did not publish new config")
	}
	if s.scanner != oldScanner {
		t.Fatal("nil live scanner should preserve existing scanner")
	}
	if s.bundleResult != nil {
		t.Fatal("nil bundle result should be published")
	}
	if got := s.currentMCPToolExtraPoison(); got != nil {
		t.Fatalf("extra poison = %+v, want nil after nil bundle result", got)
	}
}

func TestServer_StartAuxiliaryListeners(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
		o.MCPListen = serverTestEphemeralListen
		o.MCPUpstream = serverTestUpstreamURL
		o.ReverseProxy = true
		o.ReverseUpstream = serverTestUpstreamURL
		o.ReverseListen = serverTestEphemeralListen
		o.CaptureOutput = t.TempDir()
		o.CaptureDuration = 150 * time.Millisecond
		o.AgentArgs = []string{"agent", "--flag"}
	})
	s.cfg.MetricsListen = serverTestEphemeralListen
	s.cfg.ScanAPI.Listen = serverTestEphemeralListen
	s.cfg.ScanAPI.ConnectionLimit = 1
	s.cfg.ScanAPI.Timeouts = config.ScanAPITimeouts{
		Read:  "50ms",
		Write: "50ms",
	}
	s.cfg.KillSwitch.APIToken = "test-token"
	s.cfg.KillSwitch.APIListen = serverTestEphemeralListen
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

func TestServer_Reload_MCPResponseScanningFallbackEmitsNotice(t *testing.T) {
	s, buf := newTestServer(t, nil)
	s.runtimeMode = config.RuntimeMCPProxy

	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.ResponseScanning.Enabled = false
	newCfg.MCPInputScanning.Enabled = false
	buf.reset()

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !s.proxy.CurrentConfig().ResponseScanning.Enabled {
		t.Fatal("reload left response scanning disabled in MCP mode")
	}
	if !s.proxy.CurrentConfig().MCPInputScanning.Enabled {
		t.Fatal("reload left MCP input scanning disabled in MCP mode")
	}
	if !strings.Contains(buf.String(), runtimeconfig.ResponseScanningMCPDisabledWarning) {
		t.Fatalf("reload stderr missing response-scanning fallback notice:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "auto-enabling MCP input scanning for proxy mode") {
		t.Fatalf("reload stderr missing actual runtime mode label:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "for reload mode") {
		t.Fatalf("reload stderr used reload as a runtime mode label:\n%s", buf.String())
	}
}

func TestServer_Reload_StrictRejectsActionDowngrade(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.Mode = config.ModeStrict
		o.ModeChanged = true
	})
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.ResponseScanning.Enabled = true
	oldCfg.ResponseScanning.Action = config.ActionBlock
	oldScanner := s.proxy.ScannerPtr().Load()

	buf.reset()
	newCfg := oldCfg.Clone()
	newCfg.ResponseScanning.Action = config.ActionWarn

	err := s.Reload(newCfg)
	if err == nil {
		t.Fatal("Reload should reject strict response action downgrade, got nil error")
	}
	if !strings.Contains(err.Error(), "security downgrade") {
		t.Fatalf("error = %q, want security downgrade", err.Error())
	}
	if s.proxy.CurrentConfig() != oldCfg {
		t.Fatal("live config pointer changed after rejected action downgrade")
	}
	if s.proxy.ScannerPtr().Load() != oldScanner {
		t.Fatal("live scanner changed after rejected action downgrade")
	}
	if !buf.contains("response_scanning.action") {
		t.Fatalf("stderr missing action downgrade warning:\n%s", buf.String())
	}
}

func TestServer_Reload_BalancedAllowsActionTuningWithWarning(t *testing.T) {
	s, buf := newTestServer(t, nil)
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.ResponseScanning.Enabled = true
	oldCfg.ResponseScanning.Action = config.ActionBlock

	buf.reset()
	newCfg := oldCfg.Clone()
	newCfg.ResponseScanning.Action = config.ActionWarn

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("balanced reload should allow explicit action tuning, got: %v", err)
	}
	if live := s.proxy.CurrentConfig(); live.ResponseScanning.Action != config.ActionWarn {
		t.Fatalf("live response action = %q, want %q", live.ResponseScanning.Action, config.ActionWarn)
	}
	if !buf.contains("response_scanning.action") {
		t.Fatalf("balanced reload did not make action downgrade explicit:\n%s", buf.String())
	}
}

// In balanced mode ValidateReload only WARNS on response/body scanning being
// disabled, so the mode-independent implausible-teardown guard must catch it.
// Regression for the guard omitting response_scanning.enabled and
// request_body_scanning.enabled (a spurious/partial reload that explicitly
// disables them would otherwise silently turn off injection + body DLP).
func TestServer_Reload_RejectsResponseAndBodyScannerTeardown(t *testing.T) {
	s, _ := newTestServer(t, nil)
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.ResponseScanning.Enabled = true
	oldCfg.RequestBodyScanning.Enabled = true
	oldScanner := s.proxy.ScannerPtr().Load()

	newCfg := oldCfg.Clone()
	newCfg.ResponseScanning.Enabled = false
	newCfg.RequestBodyScanning.Enabled = false

	err := s.Reload(newCfg)
	if err == nil {
		t.Fatal("Reload should reject disabling response/body scanning as an implausible teardown")
	}
	if !strings.Contains(err.Error(), "implausibly empty") {
		t.Fatalf("error = %q, want implausibly empty rejection", err.Error())
	}
	for _, want := range []string{"response_scanning.enabled", "request_body_scanning.enabled"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want reason mentioning %q", err.Error(), want)
		}
	}
	live := s.proxy.CurrentConfig()
	if !live.ResponseScanning.Enabled || !live.RequestBodyScanning.Enabled {
		t.Fatal("response/body scanning disabled despite rejected reload")
	}
	if s.proxy.ScannerPtr().Load() != oldScanner {
		t.Fatal("scanner swapped despite rejected reload")
	}
}

func TestServer_Reload_RejectsGlobalEnforceDisableTeardown(t *testing.T) {
	s, _ := newTestServer(t, nil)
	oldCfg := s.proxy.CurrentConfig()
	oldScanner := s.proxy.ScannerPtr().Load()

	enforce := true
	oldCfg.Enforce = &enforce
	newCfg := oldCfg.Clone()
	detectOnly := false
	newCfg.Enforce = &detectOnly

	err := s.Reload(newCfg)
	if err == nil {
		t.Fatal("Reload should reject enforce=false as an implausible teardown")
	}
	if !strings.Contains(err.Error(), "implausibly empty") || !strings.Contains(err.Error(), "enforce disabled") {
		t.Fatalf("error = %q, want implausibly empty enforce rejection", err.Error())
	}
	if s.proxy.CurrentConfig() != oldCfg {
		t.Fatal("live config pointer changed after rejected enforce teardown")
	}
	if s.proxy.ScannerPtr().Load() != oldScanner {
		t.Fatal("scanner swapped despite rejected enforce teardown")
	}
}

func TestServer_Reload_StrictRejectsSuppressWidening(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.Mode = config.ModeStrict
		o.ModeChanged = true
	})
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.ResponseScanning.Enabled = true
	oldCfg.ResponseScanning.Action = config.ActionBlock
	oldScanner := s.proxy.ScannerPtr().Load()

	buf.reset()
	newCfg := oldCfg.Clone()
	newCfg.Suppress = append(newCfg.Suppress, config.SuppressEntry{
		Rule:   "Prompt Injection",
		Path:   "*",
		Reason: "review repro",
	})

	err := s.Reload(newCfg)
	if err == nil {
		t.Fatal("Reload should reject strict suppress widening, got nil error")
	}
	if !strings.Contains(err.Error(), "security downgrade") {
		t.Fatalf("error = %q, want security downgrade", err.Error())
	}
	if s.proxy.CurrentConfig() != oldCfg {
		t.Fatal("live config pointer changed after rejected suppress widening")
	}
	if s.proxy.ScannerPtr().Load() != oldScanner {
		t.Fatal("live scanner changed after rejected suppress widening")
	}
	if !buf.contains("suppress") {
		t.Fatalf("stderr missing suppress widening warning:\n%s", buf.String())
	}
}

func TestServer_Reload_RejectsImplausiblyEmptySecurityTeardown(t *testing.T) {
	s, buf := newTestServer(t, nil)
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.MCPInputScanning.Enabled = true
	oldCfg.MCPToolScanning.Enabled = true
	oldCfg.MCPToolPolicy.Enabled = true
	oldCfg.ForwardProxy.Enabled = true
	oldCfg.WebSocketProxy.Enabled = true
	oldCfg.MCPToolPolicy.Rules = append(oldCfg.MCPToolPolicy.Rules, config.ToolPolicyRule{
		Name:        "deny-shell",
		ToolPattern: `(?i)\b(sh|bash)\b`,
		Action:      config.ActionBlock,
	})
	oldCfg.SessionProfiling.Enabled = true
	oldCfg.AdaptiveEnforcement.Enabled = true
	oldCfg.MCPSessionBinding.Enabled = true
	oldCfg.A2AScanning.Enabled = true
	oldCfg.ToolChainDetection.Enabled = true
	oldCfg.CrossRequestDetection.Enabled = true
	oldCfg.CrossRequestDetection.EntropyBudget.Enabled = true
	oldCfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	oldCfg.AddressProtection.Enabled = true
	oldCfg.LicenseFile = "/etc/pipelock/license.token"
	oldCfg.ApplyDefaults()

	oldScanner := s.proxy.ScannerPtr().Load()
	buf.reset()

	nearEmpty := &config.Config{}
	err := s.Reload(nearEmpty)
	if err == nil {
		t.Fatal("Reload should reject an implausibly empty security teardown, got nil error")
	}
	if !strings.Contains(err.Error(), "implausibly empty") {
		t.Fatalf("error = %q, want implausibly empty rejection", err.Error())
	}
	if s.proxy.CurrentConfig() != oldCfg {
		t.Fatal("live config pointer changed after rejected near-empty reload")
	}
	if s.proxy.ScannerPtr().Load() != oldScanner {
		t.Fatal("live scanner changed after rejected near-empty reload")
	}
	live := s.proxy.CurrentConfig()
	for _, tt := range []struct {
		name string
		got  bool
	}{
		{"forward_proxy", live.ForwardProxy.Enabled},
		{"websocket_proxy", live.WebSocketProxy.Enabled},
		{"mcp_input_scanning", live.MCPInputScanning.Enabled},
		{"mcp_tool_scanning", live.MCPToolScanning.Enabled},
		{"mcp_tool_policy", live.MCPToolPolicy.Enabled},
		{"adaptive_enforcement", live.AdaptiveEnforcement.Enabled},
		{"mcp_session_binding", live.MCPSessionBinding.Enabled},
		{"a2a_scanning", live.A2AScanning.Enabled},
		{"tool_chain_detection", live.ToolChainDetection.Enabled},
		{"cross_request_detection", live.CrossRequestDetection.Enabled},
		{"address_protection", live.AddressProtection.Enabled},
	} {
		if !tt.got {
			t.Fatalf("%s was disabled despite rejected near-empty reload", tt.name)
		}
	}
	if !buf.contains("implausibly empty") {
		t.Fatalf("stderr/audit path missing implausibly empty rejection:\n%s", buf.String())
	}
}

func TestServer_Reload_DedupSkipsValidateWarnings(t *testing.T) {
	s, buf := newTestServer(t, nil)
	buf.reset()

	// Add an exempt domain to trigger a ValidateReload warning WITHOUT disabling
	// the scanner (disabling response_scanning is now a rejected teardown).
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.ResponseScanning.ExemptDomains = []string{"api.openai.com"}

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("first Reload: %v", err)
	}
	if !buf.contains("response_scanning.exempt_domains") {
		t.Fatalf("first reload stderr missing validation warning:\n%s", buf.String())
	}

	buf.reset()
	if err := s.Reload(newCfg.Clone()); err != nil {
		t.Fatalf("deduped Reload: %v", err)
	}
	if buf.contains("response_scanning.exempt_domains") {
		t.Fatalf("deduped reload printed validation warning:\n%s", buf.String())
	}
}

func TestServer_Reload_PreservesLicenseIntermediateOnContentChange(t *testing.T) {
	s, buf := newTestServer(t, nil)
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.LicenseIntermediateFile = "/tmp/license-intermediate.json"
	oldCfg.LicenseIntermediateCert = []byte("cert-v1")
	oldCfg.LicenseIntermediateLoadError = ""

	for _, tt := range []struct {
		name    string
		mutate  func(*config.Config)
		wantLog string
	}{
		{
			name: "cert bytes changed",
			mutate: func(c *config.Config) {
				c.LicenseIntermediateCert = []byte("cert-v2")
			},
			wantLog: "license key inputs changed",
		},
		{
			name: "cert load became stale",
			mutate: func(c *config.Config) {
				c.LicenseIntermediateCert = []byte("configured intermediate certificate unavailable")
				c.LicenseIntermediateLoadError = "stat license_intermediate_file: missing"
			},
			wantLog: "license key inputs changed",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			buf.reset()
			s.lastReloadAt = time.Time{}
			newCfg := oldCfg.Clone()
			tt.mutate(newCfg)
			if err := s.Reload(newCfg); err != nil {
				t.Fatalf("Reload: %v", err)
			}
			live := s.proxy.CurrentConfig()
			if !bytes.Equal(live.LicenseIntermediateCert, []byte("cert-v1")) {
				t.Fatalf("live intermediate cert = %q, want cert-v1", string(live.LicenseIntermediateCert))
			}
			if live.LicenseIntermediateLoadError != "" {
				t.Fatalf("live intermediate load error = %q, want empty", live.LicenseIntermediateLoadError)
			}
			if !buf.contains(tt.wantLog) {
				t.Fatalf("reload stderr missing %q:\n%s", tt.wantLog, buf.String())
			}
		})
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

func TestServer_Reload_RequireReceiptsRejectsSecurityDowngrade(t *testing.T) {
	s, buf := newTestServer(t, nil)
	oldLive := s.proxy.CurrentConfig()
	oldLive.Mode = config.ModeBalanced
	oldLive.FlightRecorder.RequireReceipts = true
	oldLive.ResponseScanning.Enabled = true
	oldLive.ResponseScanning.Action = config.ActionBlock

	downgraded := oldLive.Clone()
	downgraded.ResponseScanning.Action = config.ActionWarn

	err := s.Reload(downgraded)
	if err == nil {
		t.Fatal("expected require_receipts mode to reject response action downgrade reload")
	}
	if !strings.Contains(err.Error(), "required security mode") ||
		!strings.Contains(err.Error(), "flight_recorder.require_receipts") {
		t.Fatalf("error = %q, want required receipt downgrade context", err.Error())
	}
	if !buf.contains("response_scanning.action") {
		t.Fatalf("stderr missing downgrade warning:\n%s", buf.String())
	}
	live := s.proxy.CurrentConfig()
	if live.ResponseScanning.Action != config.ActionBlock {
		t.Fatalf("rejected reload changed response action to %q", live.ResponseScanning.Action)
	}
	if !live.FlightRecorder.RequireReceipts {
		t.Fatal("rejected reload cleared require_receipts in live config")
	}
}

func TestServer_Reload_RequireReceiptsAllowsNonDowngradeReload(t *testing.T) {
	s, _ := newTestServer(t, nil)
	oldLive := s.proxy.CurrentConfig()
	oldLive.Mode = config.ModeBalanced
	oldLive.FlightRecorder.RequireReceipts = true

	rotated := oldLive.Clone()
	rotated.KillSwitch.APIToken = "new-token"

	if err := s.Reload(rotated); err != nil {
		t.Fatalf("require_receipts non-downgrade reload should not error, got: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if live.KillSwitch.APIToken != "new-token" {
		t.Fatalf("api token reload did not apply: got %q", live.KillSwitch.APIToken)
	}
	if !live.FlightRecorder.RequireReceipts {
		t.Fatal("require_receipts was not preserved")
	}
}

func TestServer_Reload_RequireReceiptsAllowsRestartOnlyWarning(t *testing.T) {
	s, buf := newTestServer(t, nil)
	oldLive := s.proxy.CurrentConfig()
	oldLive.Mode = config.ModeBalanced
	oldLive.FlightRecorder.RequireReceipts = true

	restartOnly := oldLive.Clone()
	restartOnly.HealthWatchdog.IntervalSeconds = oldLive.HealthWatchdog.IntervalSeconds + 1

	if err := s.Reload(restartOnly); err != nil {
		t.Fatalf("require_receipts restart-only warning reload should not error, got: %v", err)
	}
	if !buf.contains("health_watchdog") {
		t.Fatalf("stderr missing health_watchdog restart-only warning:\n%s", buf.String())
	}
	live := s.proxy.CurrentConfig()
	if !live.FlightRecorder.RequireReceipts {
		t.Fatal("require_receipts was not preserved")
	}
}

func TestServer_Reload_MCPBinaryRequireSignatureRejectsDowngrade(t *testing.T) {
	s, buf := newTestServer(t, nil)
	oldLive := s.proxy.CurrentConfig()
	oldLive.Mode = config.ModeBalanced
	oldLive.MCPBinaryIntegrity.Enabled = true
	oldLive.MCPBinaryIntegrity.Action = config.ActionBlock
	oldLive.MCPBinaryIntegrity.RequireSignature = true
	oldLive.MCPBinaryIntegrity.ManifestPath = "/tmp/pipelock-test-manifest.json"
	oldLive.MCPBinaryIntegrity.TrustedSigner = "release"

	downgraded := oldLive.Clone()
	downgraded.MCPBinaryIntegrity.RequireSignature = false

	err := s.Reload(downgraded)
	if err == nil {
		t.Fatal("expected require_signature mode to reject MCP binary integrity downgrade reload")
	}
	if !strings.Contains(err.Error(), "required security mode") ||
		!strings.Contains(err.Error(), "mcp_binary_integrity.require_signature") {
		t.Fatalf("error = %q, want MCP binary required-signature downgrade context", err.Error())
	}
	if !buf.contains("mcp_binary_integrity.require_signature") {
		t.Fatalf("stderr missing MCP binary signature downgrade warning:\n%s", buf.String())
	}
	live := s.proxy.CurrentConfig()
	if !live.MCPBinaryIntegrity.RequireSignature {
		t.Fatal("rejected reload cleared MCP binary signature requirement in live config")
	}
}

func TestServer_Reload_MediationVerifyInboundRejectsDowngrade(t *testing.T) {
	s, buf := newTestServer(t, nil)
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	oldLive := s.proxy.CurrentConfig()
	oldLive.Mode = config.ModeBalanced
	oldLive.MediationEnvelope.VerifyInbound.Enabled = true
	oldLive.MediationEnvelope.VerifyInbound.TrustList = []config.MediationEnvelopeTrustedKey{{
		KeyID:     "peer",
		PublicKey: signing.EncodePublicKey(pub),
	}}
	oldLive.MediationEnvelope.VerifyInbound.ReplayCache.Window = "2m"
	oldLive.MediationEnvelope.VerifyInbound.ReplayCache.MaxEntries = 16

	downgraded := oldLive.Clone()
	downgraded.MediationEnvelope.VerifyInbound.Enabled = false

	err = s.Reload(downgraded)
	if err == nil {
		t.Fatal("expected inbound mediation verification mode to reject disable reload")
	}
	if !strings.Contains(err.Error(), "required security mode") ||
		!strings.Contains(err.Error(), "mediation_envelope.verify_inbound.enabled") {
		t.Fatalf("error = %q, want inbound mediation verification downgrade context", err.Error())
	}
	if !buf.contains("mediation_envelope.verify_inbound.enabled") {
		t.Fatalf("stderr missing inbound mediation verification downgrade warning:\n%s", buf.String())
	}
	live := s.proxy.CurrentConfig()
	if !live.MediationEnvelope.VerifyInbound.Enabled {
		t.Fatal("rejected reload disabled inbound mediation verification in live config")
	}
}

func TestReloadDowngradeRejectReason(t *testing.T) {
	downgrade := []config.ReloadWarning{{Field: "enforce", Message: "enforcement disabled"}}
	restartOnly := []config.ReloadWarning{{
		Field:   "health_watchdog",
		Message: "health_watchdog config changes require restart — ignored on reload",
	}}

	for _, tt := range []struct {
		name   string
		cfg    func() *config.Config
		warns  []config.ReloadWarning
		wantIn string
	}{
		{
			name: "balanced without required contract allows warning-only reload",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.Mode = config.ModeBalanced
				return c
			},
		},
		{
			name: "warnings are required",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.Mode = config.ModeStrict
				return c
			},
			warns: nil,
		},
		{
			name: "strict rejects",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.Mode = config.ModeStrict
				return c
			},
			warns:  downgrade,
			wantIn: "strict mode",
		},
		{
			name: "required receipts reject",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.FlightRecorder.RequireReceipts = true
				return c
			},
			warns:  downgrade,
			wantIn: "flight_recorder.require_receipts",
		},
		{
			name: "required receipts allows restart-only warning",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.FlightRecorder.RequireReceipts = true
				return c
			},
			warns: restartOnly,
		},
		{
			name: "license require-intermediate rejects",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.LicenseRequireIntermediateResolved = true
				return c
			},
			warns:  downgrade,
			wantIn: "license_require_intermediate",
		},
		{
			name: "A2A signed cards reject",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.A2AScanning.Enabled = true
				c.A2AScanning.RequireSignedAgentCards = true
				return c
			},
			warns:  downgrade,
			wantIn: "a2a_scanning.require_signed_agent_cards",
		},
		{
			name: "MCP binary signature rejects",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.MCPBinaryIntegrity.Enabled = true
				c.MCPBinaryIntegrity.RequireSignature = true
				return c
			},
			warns:  downgrade,
			wantIn: "mcp_binary_integrity.require_signature",
		},
		{
			name: "MCP binary signature allows restart-only warning",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.MCPBinaryIntegrity.Enabled = true
				c.MCPBinaryIntegrity.RequireSignature = true
				return c
			},
			warns: restartOnly,
		},
		{
			name: "disabled MCP binary integrity stale require flag does not reject",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.MCPBinaryIntegrity.Enabled = false
				c.MCPBinaryIntegrity.RequireSignature = true
				return c
			},
			warns: downgrade,
		},
		{
			name: "inbound mediation verification rejects",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.MediationEnvelope.VerifyInbound.Enabled = true
				return c
			},
			warns:  downgrade,
			wantIn: "mediation_envelope.verify_inbound.enabled",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := reloadDowngradeRejectReason(tt.cfg(), tt.warns)
			if tt.wantIn == "" {
				if got != "" {
					t.Fatalf("reject reason = %q, want empty", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantIn) {
				t.Fatalf("reject reason = %q, want substring %q", got, tt.wantIn)
			}
		})
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
	oldCfg.FetchProxy.Listen = "127.0.0.1:18079"
	oldCfg.KillSwitch.APIListen = "127.0.0.1:18081"
	oldCfg.MetricsListen = "127.0.0.1:18082"
	oldCfg.ScanAPI.Listen = "127.0.0.1:18083"
	oldCfg.ScanAPI.ConnectionLimit = 2
	oldCfg.ScanAPI.Timeouts = config.ScanAPITimeouts{Read: "1s", Write: "1s"}
	oldCfg.FlightRecorder.SigningKeyPath = "/tmp/old-signing-key"
	oldCfg.FlightRecorder.RequireReceipts = false
	oldCfg.Conductor.ConductorURL = "https://boss-old.example"
	oldCfg.FileSentry.Enabled = true
	oldCfg.FileSentry.Action = config.ActionWarn

	newCfg := oldCfg.Clone()
	newCfg.FetchProxy.Listen = "127.0.0.1:28079"
	newCfg.KillSwitch.APIListen = "127.0.0.1:28081"
	newCfg.MetricsListen = "127.0.0.1:28082"
	newCfg.ScanAPI.Listen = "127.0.0.1:28083"
	newCfg.ScanAPI.ConnectionLimit = 4
	newCfg.ScanAPI.Timeouts = config.ScanAPITimeouts{Read: "2s", Write: "2s"}
	newCfg.FlightRecorder.SigningKeyPath = "/tmp/new-signing-key"
	newCfg.FlightRecorder.RequireReceipts = true
	newCfg.Conductor.ConductorURL = "https://boss-new.example"
	newCfg.FileSentry.Action = config.ActionBlock // file_sentry is restart-only; this change must be ignored
	newCfg.ReverseProxy.Listen = "127.0.0.1:28084"
	newCfg.ReverseProxy.Upstream = "http://127.0.0.1:2"

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if live.FetchProxy.Listen != oldCfg.FetchProxy.Listen {
		t.Fatalf("fetch proxy listen = %q, want %q", live.FetchProxy.Listen, oldCfg.FetchProxy.Listen)
	}
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
	if !live.FlightRecorder.RequireReceipts {
		t.Fatal("flight_recorder.require_receipts reload change was not applied")
	}
	if !reflect.DeepEqual(live.Conductor, oldCfg.Conductor) {
		t.Fatalf("conductor settings not preserved: %+v", live.Conductor)
	}
	if !reflect.DeepEqual(live.FileSentry, oldCfg.FileSentry) {
		t.Fatalf("file_sentry settings not preserved (watcher cannot rebind at runtime): %+v", live.FileSentry)
	}
	if !reflect.DeepEqual(live.ReverseProxy, oldCfg.ReverseProxy) {
		t.Fatalf("reverse proxy settings not preserved: %+v", live.ReverseProxy)
	}
	for _, want := range []string{
		"fetch_proxy.listen changed",
		"kill_switch.api_listen changed",
		"metrics_listen changed",
		"scan_api listener settings changed",
		"conductor settings changed",
		"flight_recorder.signing_key_path changed",
		"reverse_proxy settings changed",
		"file_sentry settings changed",
	} {
		if !buf.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, buf.String())
		}
	}
}

func TestServer_ReloadLicenseRevocationStripsAgents(t *testing.T) {
	s, buf := newTestServer(t, nil)
	// A genuine revoked token: the reload path must CONFIRM the revocation by
	// re-verifying the inputs (ProvesLoss), not just trust that the agents were
	// stripped, before shutting the listeners down. Fake placeholder tokens
	// would classify as unverifiable and be preserved restart-only instead.
	tok, pubHex, crlPath := realRevokedAgentsLicense(t)
	oldCfg := s.proxy.CurrentConfig()
	oldCfg.Agents = map[string]config.AgentProfile{
		"_default": {Mode: config.ModeBalanced},
		"agent-a":  {Mode: config.ModeStrict},
	}
	oldCfg.LicenseKey = tok
	oldCfg.LicensePublicKey = pubHex
	oldCfg.LicenseCRLFile = crlPath
	oldCfg.LicenseExpiresAt = time.Now().Add(time.Hour).Unix()
	oldCfg.LicenseAgentsFeature = true

	// Simulate EnforceLicenseGate's strip at reload-Load (the revoked token left
	// no named agents); the license inputs are otherwise unchanged.
	newCfg := oldCfg.Clone()
	newCfg.Agents = map[string]config.AgentProfile{
		"_default": {Mode: config.ModeBalanced},
	}

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if _, ok := live.Agents["agent-a"]; ok {
		t.Fatalf("named agent survived license revocation reload: %+v", live.Agents)
	}
	if _, ok := live.Agents["_default"]; !ok {
		t.Fatalf("_default did not survive license revocation reload: %+v", live.Agents)
	}
	if live.LicenseAgentsFeature {
		t.Fatal("LicenseAgentsFeature stayed true after named agents were stripped")
	}
	if !buf.contains("license revoked agents, shutting down agent listeners") {
		t.Fatalf("stderr missing agents revocation warning:\n%s", buf.String())
	}
}

// TestServer_Reload_ReverseProxyProfileOnlyIgnored isolates the profile-only
// reload case. The previous field-by-field guard only preserved ReverseProxy
// when listen/enabled/upstream changed, so a reload that flipped ONLY the
// profile slipped through: the submit gate would read the new profile from the
// live config while the SSRF-safe dialer - installed on the transport at
// startup - stayed frozen. With the whole struct compared, a profile-only
// change is preserved until restart like every other reverse_proxy field.
func TestServer_Reload_ReverseProxyProfileOnlyIgnored(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.ReverseProxy = true
		o.ReverseUpstream = serverTestUpstreamURL
		o.ReverseListen = "127.0.0.1:18084"
	})

	oldCfg := s.proxy.CurrentConfig()

	// Change ONLY the profile (and a submit-listener field). Listen, enabled,
	// and upstream are untouched - the old guard would not have fired.
	newCfg := oldCfg.Clone()
	newCfg.ReverseProxy.Profile = "submit"
	newCfg.ReverseProxy.RequestTimeoutSeconds = 30

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	live := s.proxy.CurrentConfig()
	if live.ReverseProxy.Profile != oldCfg.ReverseProxy.Profile {
		t.Fatalf("reverse_proxy.profile changed via reload to %q (dial path is startup-frozen)", live.ReverseProxy.Profile)
	}
	if !reflect.DeepEqual(live.ReverseProxy, oldCfg.ReverseProxy) {
		t.Fatalf("reverse proxy settings not preserved on profile-only reload: %+v", live.ReverseProxy)
	}
	if !buf.contains("reverse_proxy settings changed") {
		t.Fatalf("stderr missing reverse_proxy reload warning:\n%s", buf.String())
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
	oldKillSwitchEnabled := oldCfg.KillSwitch.Enabled
	oldKillSwitchMessage := oldCfg.KillSwitch.Message
	oldKillSwitchActive := s.killswitch.IsActive()
	oldEnvelopeEnabled := oldCfg.MediationEnvelope.Enabled
	oldEnvelopeSign := oldCfg.MediationEnvelope.Sign
	oldEnvelopeSigningKeyPath := oldCfg.MediationEnvelope.SigningKeyPath

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
	live := s.proxy.CurrentConfig()
	if live.KillSwitch.Enabled != oldKillSwitchEnabled ||
		live.KillSwitch.Message != oldKillSwitchMessage ||
		live.MediationEnvelope.Enabled != oldEnvelopeEnabled ||
		live.MediationEnvelope.Sign != oldEnvelopeSign ||
		live.MediationEnvelope.SigningKeyPath != oldEnvelopeSigningKeyPath {
		t.Errorf("live proxy config mutated despite failed reload: kill_switch=%+v mediation_envelope=%+v",
			live.KillSwitch, live.MediationEnvelope)
	}
	if s.proxy.ScannerPtr().Load() != oldScanner {
		t.Errorf("live proxy scanner changed despite failed reload")
	}
	if s.cfg != oldCfg {
		t.Errorf("server cfg changed despite failed reload")
	}
	if s.killswitch.IsActive() != oldKillSwitchActive {
		t.Errorf("kill switch active state changed despite failed reload")
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
		o.MCPListen = serverTestEphemeralListen
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

// TestServer_StartJoinsLicenseExpiryWatcher exercises the lifecycle join for
// the license expiry watcher goroutine, which Start spawns whenever
// cfg.LicenseExpiresAt > 0. A future expiry keeps the watcher selecting on
// ctx.Done(); the WaitGroup must join it during shutdown so cleanup() does not
// race the watcher's read of s.logger/s.sentry.
func TestServer_StartJoinsLicenseExpiryWatcher(t *testing.T) {
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	// Set before launching Start: goroutine creation establishes the
	// happens-before edge, so currentConfig() reads this value.
	s.cfg.LicenseExpiresAt = time.Now().Add(time.Hour).Unix()

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

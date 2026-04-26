// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanapi"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	plsentry "github.com/luckyPipewrench/pipelock/internal/sentry"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// ServerOpts carries the CLI-flag surface and I/O bindings for a runtime
// server. ModeChanged / ListenChanged distinguish "CLI override" from "use
// config default", matching the cobra.Flag.Changed semantics RunCmd relied on
// before the extraction.
type ServerOpts struct {
	ConfigFile       string
	Mode             string
	Listen           string
	MCPListen        string
	MCPUpstream      string
	ReverseProxy     bool
	ReverseUpstream  string
	ReverseListen    string
	CaptureOutput    string
	CaptureDuration  time.Duration
	CaptureEscrowKey string

	// ModeChanged is set when the --mode flag was supplied on the command
	// line (cobra.Flag.Changed("mode")). Only then does Mode override the
	// loaded config's mode.
	ModeChanged bool
	// ListenChanged mirrors ModeChanged for --listen.
	ListenChanged bool

	// AgentArgs is the command+args that followed "--" on the CLI, or nil
	// when "--" was absent. Used only for the Phase 2 "Agent: ..." note
	// emitted during startup.
	AgentArgs []string

	Stdout io.Writer
	Stderr io.Writer
}

// Server owns the runtime lifecycle for `pipelock run`. NewServer loads and
// validates the config, builds every runtime component (scanner, metrics,
// kill switch, proxy, flight recorder, receipt/envelope emitters, capture
// writer), but binds no listeners. Start performs the listener bind + serve
// loop and blocks until ctx is cancelled. Reload drives a single
// hot-reload cycle against newCfg. Shutdown cancels the internal context
// so Start unblocks.
type Server struct {
	opts ServerOpts

	runtimeMode       config.RuntimeMode
	hasMCPListen      bool
	apiOnSeparatePort bool
	hasApprover       bool

	cfg          *config.Config
	bundleResult *rules.LoadResult

	sentry          *plsentry.Client
	logger          *audit.Logger
	emitter         *emit.Emitter
	scanner         *scanner.Scanner
	metrics         *metrics.Metrics
	killswitch      *killswitch.Controller
	ksAPI           *killswitch.APIHandler
	proxy           *proxy.Proxy
	receiptEmitter  *receipt.Emitter
	envelopeEmitter *envelope.Emitter
	captureWriter   *capture.Writer
	recorder        *recorder.Recorder
	approver        *hitl.Approver

	// lastReloadHash / lastReloadAt dedup fsnotify + SIGHUP stacking
	// inside Reload. Two stacked Changes() events with the same hash
	// within 2s skip silently; a single no-op SIGHUP still logs.
	lastReloadHash string
	lastReloadAt   time.Time

	// cancelMu guards internalCancel against the Start-writes /
	// Shutdown-reads race. Start publishes the cancel func under the
	// lock; Shutdown reads and invokes it outside the lock so the
	// cancel itself does not synchronously deadlock on Start's defers.
	cancelMu       sync.Mutex
	internalCancel context.CancelFunc

	stateMu            sync.RWMutex
	toolPolicyCfg      *policy.Config
	mcpChainMatcher    *chains.Matcher
	mcpCEE             *mcp.CEEDeps
	mcpToolExtraPoison []*tools.ExtraPoisonPattern
}

func buildToolPolicyCfg(cfg *config.Config) *policy.Config {
	if cfg == nil || !cfg.MCPToolPolicy.Enabled {
		return nil
	}
	return policy.New(cfg.MCPToolPolicy)
}

func buildMCPInputCfg(cfg *config.Config) *mcp.InputScanConfig {
	if cfg == nil || !cfg.MCPInputScanning.Enabled {
		return nil
	}
	return &mcp.InputScanConfig{
		Enabled:      cfg.MCPInputScanning.Enabled,
		Action:       cfg.MCPInputScanning.Action,
		OnParseError: cfg.MCPInputScanning.OnParseError,
	}
}

func buildMCPToolCfg(
	cfg *config.Config,
	extraPoison []*tools.ExtraPoisonPattern,
	baseline *tools.ToolBaseline,
) *tools.ToolScanConfig {
	if cfg == nil || !cfg.MCPToolScanning.Enabled {
		return nil
	}
	return &tools.ToolScanConfig{
		Baseline:    baseline,
		Action:      cfg.MCPToolScanning.Action,
		DetectDrift: cfg.MCPToolScanning.DetectDrift,
		ExtraPoison: extraPoison,
	}
}

func buildMCPChainMatcher(cfg *config.Config, m *metrics.Metrics) *chains.Matcher {
	if cfg == nil || !cfg.ToolChainDetection.Enabled {
		return nil
	}
	return chains.New(&cfg.ToolChainDetection).WithMetrics(m)
}

func buildMCPCEE(cfg *config.Config, m *metrics.Metrics) *mcp.CEEDeps {
	if cfg == nil || !cfg.CrossRequestDetection.Enabled {
		return nil
	}
	ceeCfg := cfg.CrossRequestDetection
	deps := &mcp.CEEDeps{Config: &ceeCfg, Metrics: m}
	if ceeCfg.EntropyBudget.Enabled {
		deps.Tracker = scanner.NewEntropyTracker(
			ceeCfg.EntropyBudget.BitsPerWindow,
			ceeCfg.EntropyBudget.WindowMinutes*60,
		)
	}
	if ceeCfg.FragmentReassembly.Enabled {
		deps.Buffer = scanner.NewFragmentBuffer(
			ceeCfg.FragmentReassembly.MaxBufferBytes,
			10000,
			ceeCfg.FragmentReassembly.WindowMinutes*60,
		)
	}
	return deps
}

func (s *Server) liveReceiptEmitter() *receipt.Emitter {
	if s.proxy != nil {
		return s.proxy.ReceiptEmitterPtr().Load()
	}
	return s.receiptEmitter
}

func (s *Server) liveEnvelopeEmitter() *envelope.Emitter {
	if s.proxy != nil {
		return s.proxy.EnvelopeEmitterPtr().Load()
	}
	return s.envelopeEmitter
}

func (s *Server) currentConfig() *config.Config {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.cfg
}

func (s *Server) shouldSkipReload(hash string) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return hash == s.lastReloadHash && time.Since(s.lastReloadAt) < 2*time.Second
}

func (s *Server) recordReloadSuccess(hash string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastReloadHash = hash
	s.lastReloadAt = time.Now()
}

func (s *Server) currentToolPolicyCfg() *policy.Config {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.toolPolicyCfg
}

func (s *Server) currentMCPChainMatcher() *chains.Matcher {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.mcpChainMatcher
}

func (s *Server) currentMCPCEE() *mcp.CEEDeps {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.mcpCEE
}

func (s *Server) currentMCPToolExtraPoison() []*tools.ExtraPoisonPattern {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if len(s.mcpToolExtraPoison) == 0 {
		return nil
	}
	return append([]*tools.ExtraPoisonPattern(nil), s.mcpToolExtraPoison...)
}

func (s *Server) refreshRuntimeState(
	oldCfg, newCfg *config.Config,
	bundleResult *rules.LoadResult,
	liveScanner *scanner.Scanner,
) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	s.cfg = newCfg
	if liveScanner != nil {
		s.scanner = liveScanner
	}
	s.bundleResult = bundleResult
	s.receiptEmitter = s.liveReceiptEmitter()
	s.envelopeEmitter = s.liveEnvelopeEmitter()
	s.toolPolicyCfg = buildToolPolicyCfg(newCfg)
	if bundleResult != nil {
		s.mcpToolExtraPoison = rules.ConvertToolPoison(bundleResult.ToolPoison)
	} else {
		s.mcpToolExtraPoison = nil
	}
	if oldCfg == nil || !reflect.DeepEqual(oldCfg.ToolChainDetection, newCfg.ToolChainDetection) {
		s.mcpChainMatcher = buildMCPChainMatcher(newCfg, s.metrics)
	}
	if oldCfg == nil || !reflect.DeepEqual(oldCfg.CrossRequestDetection, newCfg.CrossRequestDetection) {
		s.mcpCEE = buildMCPCEE(newCfg, s.metrics)
	}
}

// NewServer validates opts, loads config, applies CLI overrides, and builds
// every runtime component. No ports are bound; that is Start's job. On any
// construction failure NewServer closes whatever was partially built and
// returns the error.
func NewServer(opts ServerOpts) (*Server, error) {
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}

	hasMCPListen := opts.MCPListen != ""
	hasMCPUpstream := opts.MCPUpstream != ""
	if hasMCPListen && !hasMCPUpstream {
		return nil, errors.New("--mcp-listen requires --mcp-upstream")
	}
	if hasMCPUpstream && !hasMCPListen {
		return nil, errors.New("--mcp-upstream requires --mcp-listen")
	}
	if hasMCPUpstream {
		u, uErr := url.Parse(opts.MCPUpstream)
		if uErr != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
			return nil, fmt.Errorf("invalid --mcp-upstream %q: must be http:// or https:// with a host", opts.MCPUpstream)
		}
	}

	if opts.ReverseProxy && opts.ReverseUpstream == "" {
		return nil, errors.New("--reverse-proxy requires --reverse-upstream")
	}
	if opts.ReverseUpstream != "" && !opts.ReverseProxy {
		return nil, errors.New("--reverse-upstream requires --reverse-proxy")
	}
	if opts.ReverseProxy {
		u, uErr := url.Parse(opts.ReverseUpstream)
		if uErr != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
			return nil, fmt.Errorf("invalid --reverse-upstream %q: must be http:// or https:// with a host", opts.ReverseUpstream)
		}
		if opts.ReverseListen == "" {
			opts.ReverseListen = ":8890"
		}
	}

	var cfg *config.Config
	var err error
	if opts.ConfigFile != "" {
		cfg, err = config.Load(opts.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("loading config: %w", err)
		}
	} else {
		cfg = config.Defaults()
	}

	if opts.ModeChanged {
		cfg.Mode = opts.Mode
	}
	if opts.ListenChanged {
		cfg.FetchProxy.Listen = opts.Listen
	}
	if opts.ReverseProxy {
		cfg.ReverseProxy.Enabled = true
		cfg.ReverseProxy.Listen = opts.ReverseListen
		cfg.ReverseProxy.Upstream = opts.ReverseUpstream
	}

	cfg.ApplyDefaults()
	warnings, err := cfg.ValidateWithWarnings()
	for _, wn := range warnings {
		_, _ = fmt.Fprintf(opts.Stderr, "WARNING: %s: %s\n", wn.Field, wn.Message)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	s := &Server{
		opts:         opts,
		hasMCPListen: hasMCPListen,
	}

	sentryClient, sentryErr := plsentry.Init(cfg, cliutil.Version)
	if sentryErr != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "warning: sentry init failed: %v\n", sentryErr)
	}
	s.sentry = sentryClient

	logger, err := audit.New(
		cfg.Logging.Format,
		cfg.Logging.Output,
		cfg.Logging.File,
		cfg.Logging.IncludeAllowed,
		cfg.Logging.IncludeBlocked,
	)
	if err != nil {
		s.cleanup()
		return nil, fmt.Errorf("creating audit logger: %w", err)
	}
	s.logger = logger

	emitSinks, emitErr := BuildEmitSinks(cfg)
	if emitErr != nil {
		s.cleanup()
		return nil, fmt.Errorf("creating emit sinks: %w", emitErr)
	}
	instanceID := cfg.Emit.InstanceID
	if instanceID == "" {
		instanceID = emit.DefaultInstanceID()
	}
	emitter := emit.NewEmitter(instanceID, emitSinks...)
	logger.SetEmitter(emitter)
	s.emitter = emitter

	runtimeMode := config.RuntimeForward
	if hasMCPListen {
		runtimeMode = config.RuntimeForwardWithMCPListener
	}
	s.runtimeMode = runtimeMode

	var bundleResult *rules.LoadResult
	var resolveInfo config.ResolveRuntimeInfo
	cfg, resolveInfo = cfg.ResolveRuntime(config.RuntimeResolveOpts{
		Mode: runtimeMode,
		MergeBundles: func(c *config.Config) {
			bundleResult = rules.MergeIntoConfig(c, cliutil.Version)
		},
		DefaultToolPolicyRules: policy.DefaultToolPolicyRules,
	})
	for _, e := range bundleResult.Errors {
		_, _ = fmt.Fprintf(opts.Stderr, "pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
	}
	for _, w := range bundleResult.Warnings {
		_, _ = fmt.Fprintf(opts.Stderr, "pipelock: %s\n", w)
	}
	if bundleResult.Degraded {
		_, _ = fmt.Fprintf(opts.Stderr, "pipelock: DEGRADED — standard pack failed, running core patterns only\n")
	}
	emitResolveInfoLogs(opts.Stderr, resolveInfo, "listener")

	sc := scanner.New(cfg)
	s.scanner = sc
	m := metrics.New()
	s.metrics = m
	sc.SetDLPWarnHook(func(ctx context.Context, patternName, severity string) {
		emitDLPWarn(s.logger, s.metrics, s.liveReceiptEmitter(), ctx, patternName, severity)
	})

	ks := killswitch.New(cfg)
	m.RegisterKillSwitchState(ks.Sources)
	m.RegisterInfo(cliutil.Version)
	s.killswitch = ks

	ksAPI := killswitch.NewAPIHandler(ks)
	s.ksAPI = ksAPI

	var proxyOpts []proxy.Option
	s.hasApprover = cfg.ResponseScanning.Action == config.ActionAsk
	if s.hasApprover {
		approver := hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
		s.approver = approver
		proxyOpts = append(proxyOpts, proxy.WithApprover(approver))
	}
	proxyOpts = append(proxyOpts, proxy.WithKillSwitch(ks))

	s.apiOnSeparatePort = cfg.KillSwitch.APIListen != ""
	if !s.apiOnSeparatePort {
		proxyOpts = append(proxyOpts, proxy.WithKillSwitchAPI(ksAPI))
	} else {
		ks.SetSeparateAPIPort(true)
	}

	if opts.CaptureOutput != "" {
		var escrowPub *[32]byte
		if opts.CaptureEscrowKey != "" {
			keyBytes, hexErr := hex.DecodeString(opts.CaptureEscrowKey)
			if hexErr != nil || len(keyBytes) != 32 {
				s.cleanup()
				return nil, fmt.Errorf("invalid --capture-escrow-public-key: must be 64 hex chars (32 bytes)")
			}
			escrowPub = (*[32]byte)(keyBytes)
		}

		cw, cwErr := capture.NewWriter(capture.WriterConfig{
			RecorderConfig: recorder.Config{
				Enabled:           true,
				Dir:               opts.CaptureOutput,
				MaxEntriesPerFile: 10000, // 10k entries per file before rotation
			},
			EscrowPublicKey: escrowPub,
			DropSink:        m,
			QueueSize:       4096, // bounded channel capacity
			BuildVersion:    cliutil.Version,
			BuildSHA:        cliutil.GitCommit,
		})
		if cwErr != nil {
			s.cleanup()
			return nil, fmt.Errorf("creating capture writer: %w", cwErr)
		}
		s.captureWriter = cw
		proxyOpts = append(proxyOpts, proxy.WithCaptureObserver(cw))
	}

	// Flight recorder: create a tamper-evident evidence recorder when
	// enabled in YAML config. The --capture-output CLI flag uses a
	// separate code path (capture.Writer above). This path wires the
	// YAML-config-driven recorder into the proxy so enforcement decisions
	// are hash-chained to disk.
	if cfg.FlightRecorder.Enabled && cfg.FlightRecorder.Dir != "" {
		recCfg := recorder.Config{
			Enabled:            cfg.FlightRecorder.Enabled,
			Dir:                cfg.FlightRecorder.Dir,
			CheckpointInterval: cfg.FlightRecorder.CheckpointInterval,
			RetentionDays:      cfg.FlightRecorder.RetentionDays,
			Redact:             cfg.FlightRecorder.Redact,
			SignCheckpoints:    cfg.FlightRecorder.SignCheckpoints,
			MaxEntriesPerFile:  cfg.FlightRecorder.MaxEntriesPerFile,
			RawEscrow:          cfg.FlightRecorder.RawEscrow,
			EscrowPublicKey:    cfg.FlightRecorder.EscrowPublicKey,
		}

		var redactFn recorder.RedactFunc
		if cfg.FlightRecorder.Redact {
			redactFn = sc.ScanTextForDLP
		}

		var recPrivKey ed25519.PrivateKey
		if cfg.FlightRecorder.SigningKeyPath != "" {
			k, kErr := signing.LoadPrivateKeyFile(cfg.FlightRecorder.SigningKeyPath)
			if kErr != nil {
				s.cleanup()
				return nil, fmt.Errorf("loading flight recorder signing key: %w", kErr)
			}
			recPrivKey = k
		}

		rec, recErr := recorder.New(recCfg, redactFn, recPrivKey)
		if recErr != nil {
			s.cleanup()
			return nil, fmt.Errorf("creating flight recorder: %w", recErr)
		}
		s.recorder = rec
		proxyOpts = append(proxyOpts, proxy.WithRecorder(rec))

		// Action receipt emitter: ConfigHash uses cfg.Hash() (raw YAML
		// bytes) because the receipt is a point-in-time audit
		// fingerprint of the loaded configuration file. Two deployments
		// that happened to produce the same effective policy through
		// different YAML should still be distinguishable in a forensic
		// trail. Envelope attestation (below) uses the policy-semantic
		// hash because its contract is the opposite — identical
		// effective policy should produce identical envelope ph
		// regardless of YAML formatting.
		s.receiptEmitter = receipt.NewEmitter(receipt.EmitterConfig{
			Recorder:   rec,
			PrivKey:    recPrivKey,
			ConfigHash: cfg.Hash(),
			Principal:  "local",
			Actor:      "pipelock",
		})
		if s.receiptEmitter != nil {
			proxyOpts = append(proxyOpts, proxy.WithReceiptEmitter(s.receiptEmitter))
			if cfg.FlightRecorder.SigningKeyPath != "" {
				proxyOpts = append(proxyOpts, proxy.WithReceiptKeyPath(cfg.FlightRecorder.SigningKeyPath))
			}
			_, _ = fmt.Fprintf(opts.Stderr, "  Receipts: enabled (action receipts signed)\n")
		}

		_, _ = fmt.Fprintf(opts.Stderr, "  Recorder: %s (flight recorder enabled)\n", cfg.FlightRecorder.Dir)
	}

	if cfg.MediationEnvelope.Enabled {
		s.envelopeEmitter = envelope.NewEmitter(envelope.EmitterConfig{
			ConfigHash: cfg.CanonicalPolicyHash(),
		})
		proxyOpts = append(proxyOpts, proxy.WithEnvelopeEmitter(s.envelopeEmitter))
		_, _ = fmt.Fprintf(opts.Stderr, "  Envelope: enabled (mediation envelopes injected)\n")
	}

	p, pErr := proxy.New(cfg, logger, sc, m, proxyOpts...)
	if pErr != nil {
		s.cleanup()
		return nil, fmt.Errorf("creating proxy: %w", pErr)
	}
	s.proxy = p

	if err := p.LoadCertCache(cfg); err != nil {
		if sentryClient != nil {
			sentryClient.CaptureError(err)
		}
		s.cleanup()
		return nil, err
	}

	s.refreshRuntimeState(nil, cfg, bundleResult, sc)

	return s, nil
}

// Start binds all configured listeners, launches the reload/signal/
// capture-timer goroutines, prints the startup banner, and runs the fetch
// proxy. Start blocks until ctx is cancelled or the proxy returns an
// error, then drains listener error channels, closes owned resources, and
// returns.
func (s *Server) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelMu.Lock()
	s.internalCancel = cancel
	s.cancelMu.Unlock()
	defer cancel()

	// Cleanup order mirrors the original RunCmd deferred closures so
	// shutdown sequencing (reloader → recorder → capture writer →
	// approver → scanner → emitter → logger → sentry) is preserved.
	defer s.cleanup()

	var reloadWG sync.WaitGroup
	defer reloadWG.Wait()

	// Capture duration timer: cancel context after the specified capture
	// duration so the proxy shuts down automatically.
	if s.opts.CaptureOutput != "" && s.opts.CaptureDuration > 0 {
		go func() {
			select {
			case <-time.After(s.opts.CaptureDuration):
				_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: capture duration reached (%s), shutting down\n", s.opts.CaptureDuration)
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	cleanupSignal := RegisterKillSwitchSignal(s.killswitch, s.opts.Stderr)
	defer cleanupSignal()

	if s.opts.ConfigFile != "" {
		reloader := config.NewReloader(s.opts.ConfigFile)
		defer reloader.Close()

		reloadWG.Add(1)
		go func() {
			defer reloadWG.Done()
			if err := reloader.Start(ctx); err != nil {
				s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), err)
			}
		}()

		reloadWG.Add(1)
		go func() {
			defer reloadWG.Done()
			for newCfg := range reloader.Changes() {
				if err := s.Reload(newCfg); err != nil {
					s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), err)
				}
			}
		}()
	}

	if !IsContainerized() {
		_, _ = fmt.Fprintln(s.opts.Stderr, "WARNING: running outside a container - consider using Docker/Podman for network isolation")
	}

	cfg := s.currentConfig()
	_, _ = fmt.Fprintf(s.opts.Stderr, "Pipelock v%s starting\n", cliutil.Version)
	_, _ = fmt.Fprintf(s.opts.Stderr, "  Mode:   %s\n", cfg.Mode)
	_, _ = fmt.Fprintf(s.opts.Stderr, "  Listen: %s\n", cfg.FetchProxy.Listen)
	_, _ = fmt.Fprintf(s.opts.Stderr, "  Fetch:  http://%s/fetch?url=<url>\n", cfg.FetchProxy.Listen)
	_, _ = fmt.Fprintf(s.opts.Stderr, "  Health: http://%s/health\n", cfg.FetchProxy.Listen)
	if cfg.MetricsListen != "" {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Stats:  http://%s/stats (separate port)\n", cfg.MetricsListen)
	} else {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Stats:  http://%s/stats\n", cfg.FetchProxy.Listen)
	}
	if cfg.ForwardProxy.Enabled {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Proxy:  HTTP/HTTPS forward proxy enabled (CONNECT + absolute-URI)\n")
	}
	if cfg.WebSocketProxy.Enabled {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  WS:     http://%s/ws?url=<ws-url> (WebSocket proxy enabled)\n", cfg.FetchProxy.Listen)
	}
	if cfg.Emit.Webhook.URL != "" {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Emit:   webhook -> %s (min_severity: %s)\n", RedactEndpoint(cfg.Emit.Webhook.URL), cfg.Emit.Webhook.MinSeverity)
	}
	if cfg.Emit.Syslog.Address != "" {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Emit:   syslog -> %s (min_severity: %s)\n", RedactEndpoint(cfg.Emit.Syslog.Address), cfg.Emit.Syslog.MinSeverity)
	}
	if cfg.KillSwitch.APIToken != "" {
		if s.apiOnSeparatePort {
			_, _ = fmt.Fprintf(s.opts.Stderr, "  API:    http://%s/api/v1/killswitch (kill switch remote control, separate port)\n", cfg.KillSwitch.APIListen)
		} else {
			_, _ = fmt.Fprintf(s.opts.Stderr, "  API:    http://%s/api/v1/killswitch (kill switch remote control)\n", cfg.FetchProxy.Listen)
		}
	}
	if s.opts.ConfigFile != "" {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Config: %s (hot-reload enabled%s)\n", s.opts.ConfigFile, ReloadSignalHint())
	}
	if s.hasMCPListen {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  MCP:    http://%s -> %s\n", s.opts.MCPListen, s.opts.MCPUpstream)
	}
	if cfg.ReverseProxy.Enabled {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  RevPx:  http://%s -> %s (reverse proxy with body scanning)\n",
			cfg.ReverseProxy.Listen, RedactEndpoint(cfg.ReverseProxy.Upstream))
	}
	if s.opts.CaptureOutput != "" {
		if s.opts.CaptureDuration > 0 {
			_, _ = fmt.Fprintf(s.opts.Stderr, "  Capture: %s (duration: %s)\n", s.opts.CaptureOutput, s.opts.CaptureDuration)
		} else {
			_, _ = fmt.Fprintf(s.opts.Stderr, "  Capture: %s (until interrupted)\n", s.opts.CaptureOutput)
		}
	}
	for addr, name := range s.proxy.Ports() {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Agent:  %s -> http://%s\n", name, addr)
	}

	if len(s.opts.AgentArgs) > 0 {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Agent:  %v\n", s.opts.AgentArgs)
		_, _ = fmt.Fprintln(s.opts.Stderr, "\nNote: agent process launching is not yet implemented (Phase 2).")
		_, _ = fmt.Fprintln(s.opts.Stderr, "The fetch proxy is running — configure your agent to use:")
		_, _ = fmt.Fprintf(s.opts.Stderr, "  PIPELOCK_FETCH_URL=http://%s/fetch\n\n", cfg.FetchProxy.Listen)
	}

	// Start kill switch API on a separate port if configured. Follows
	// the same pattern as the MCP listener: bind synchronously so port
	// conflicts are caught early, serve in a goroutine, and drain the
	// error channel after the main proxy exits.
	var ksAPIErr chan error
	if s.apiOnSeparatePort {
		apiMux := http.NewServeMux()
		apiMux.HandleFunc("/api/v1/killswitch", s.ksAPI.HandleToggle)
		apiMux.HandleFunc("/api/v1/killswitch/status", s.ksAPI.HandleStatus)

		// Session admin API on the dedicated port. Mount the proxy's
		// existing handler rather than building a second one so
		// Reload's SetAPIToken rotation covers the dedicated-port
		// mount too. p.SessionAPI() returns nil when no api_token is
		// configured — in that case we skip registration and the
		// admin routes simply don't exist on the listener.
		if sessionAPI := s.proxy.SessionAPI(); sessionAPI != nil {
			apiMux.HandleFunc("/api/v1/sessions", sessionAPI.HandleList)
			apiMux.HandleFunc("/api/v1/sessions/", func(w http.ResponseWriter, r *http.Request) {
				path := r.URL.EscapedPath()
				switch {
				case killswitch.IsSessionActionPath(path, "airlock"):
					sessionAPI.HandleAirlock(w, r)
				case killswitch.IsSessionActionPath(path, "task"):
					sessionAPI.HandleTask(w, r)
				case killswitch.IsSessionActionPath(path, "trust"):
					sessionAPI.HandleTrust(w, r)
				case killswitch.IsSessionActionPath(path, "reset"):
					sessionAPI.HandleReset(w, r)
				case killswitch.IsSessionActionPath(path, "explain"):
					sessionAPI.HandleExplain(w, r)
				case killswitch.IsSessionActionPath(path, "terminate"):
					sessionAPI.HandleTerminate(w, r)
				case killswitch.IsSessionKeyPath(path):
					sessionAPI.HandleInspect(w, r)
				default:
					http.NotFound(w, r)
				}
			})
		}

		apiLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.KillSwitch.APIListen)
		if lnErr != nil {
			err := fmt.Errorf("kill switch API bind %s: %w", cfg.KillSwitch.APIListen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
		}

		apiSrv := newHTTPServer(apiMux)
		go func() {
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = apiSrv.Shutdown(shutdownCtx) //nolint:errcheck // best-effort shutdown
		}()

		ksAPIErr = make(chan error, 1)
		go func() {
			err := apiSrv.Serve(apiLn)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			ksAPIErr <- err
		}()
	}

	var metricsErr chan error
	if cfg.MetricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", s.metrics.PrometheusHandler())
		metricsMux.HandleFunc("/stats", s.metrics.StatsHandler())

		metricsLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.MetricsListen)
		if lnErr != nil {
			err := fmt.Errorf("metrics bind %s: %w", cfg.MetricsListen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
		}
		metricsSrv := newHTTPServer(metricsMux)
		go func() {
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
		metricsErr = make(chan error, 1)
		go func() {
			srvErr := metricsSrv.Serve(metricsLn)
			if errors.Is(srvErr, http.ErrServerClosed) {
				srvErr = nil
			}
			metricsErr <- srvErr
		}()
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: metrics listening on %s\n", cfg.MetricsListen)
	}

	// Scan API server on a dedicated port: same bind-synchronously +
	// serve-in-goroutine pattern as the kill switch API.
	var scanAPIErr chan error
	if cfg.ScanAPI.Listen != "" {
		scanAPIMux := http.NewServeMux()
		scanHandler := scanapi.NewHandler(cfg, s.proxy.ScannerPtr().Load(), s.currentToolPolicyCfg(), s.metrics, cliutil.Version)
		scanHandler.SetKillSwitchFn(s.killswitch.IsActive)
		scanHandler.SetRuntimeGetters(
			func() *config.Config { return s.proxy.CurrentConfig() },
			func() *scanner.Scanner { return s.proxy.ScannerPtr().Load() },
			s.currentToolPolicyCfg,
		)
		scanAPIMux.Handle("/api/v1/scan", scanHandler)

		scanAPILn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ScanAPI.Listen)
		if lnErr != nil {
			return fmt.Errorf("scan API bind %s: %w", cfg.ScanAPI.Listen, lnErr)
		}
		if cfg.ScanAPI.ConnectionLimit > 0 {
			scanAPILn = netutil.LimitListener(scanAPILn, cfg.ScanAPI.ConnectionLimit)
		}

		readTimeout := 2 * time.Second
		writeTimeout := 2 * time.Second
		if d, parseErr := time.ParseDuration(cfg.ScanAPI.Timeouts.Read); parseErr == nil {
			readTimeout = d
		}
		if d, parseErr := time.ParseDuration(cfg.ScanAPI.Timeouts.Write); parseErr == nil {
			writeTimeout = d
		}

		scanAPISrv := newHTTPServer(scanAPIMux)
		scanAPISrv.ReadTimeout = readTimeout
		scanAPISrv.ReadHeaderTimeout = readTimeout
		scanAPISrv.WriteTimeout = writeTimeout
		go func() {
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = scanAPISrv.Shutdown(shutdownCtx)
		}()

		scanAPIErr = make(chan error, 1)
		go func() {
			srvErr := scanAPISrv.Serve(scanAPILn)
			if errors.Is(srvErr, http.ErrServerClosed) {
				srvErr = nil
			}
			scanAPIErr <- srvErr
		}()
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: scan API listening on %s\n", cfg.ScanAPI.Listen)
	}

	var mcpErr chan error
	if s.hasMCPListen {
		// MCP scanning sections auto-enable inside ResolveRuntime above
		// when the operator did not configure them; the effective cfg
		// already reflects those defaults.
		mcpToolBaseline := tools.NewToolBaseline()
		// mcpDriftEdge detects detect_drift false→true transitions for
		// the server-level tool baseline shared across stdio / WS / forward
		// MCP sessions. On false→true reload, ResetDriftState clears stale
		// drift hashes so a subsequent session does not evaluate post-flip
		// tools/list against pre-disable ground truth. See proxy_http.go
		// for the equivalent detector on the per-listener baseline.
		var mcpDriftEdge tools.DetectDriftRisingEdge
		mcpScannerFn := func() *scanner.Scanner { return s.proxy.ScannerPtr().Load() }
		mcpInputCfgFn := func() *mcp.InputScanConfig { return buildMCPInputCfg(s.proxy.CurrentConfig()) }
		mcpToolCfgFn := func() *tools.ToolScanConfig {
			cfg := buildMCPToolCfg(s.proxy.CurrentConfig(), s.currentMCPToolExtraPoison(), mcpToolBaseline)
			if cfg != nil && mcpDriftEdge.Observe(cfg.DetectDrift) {
				mcpToolBaseline.ResetDriftState()
			}
			return cfg
		}
		mcpRedirectRTFn := func() *mcp.RedirectRuntime {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return nil
			}
			return buildRedirectRT(c)
		}
		mcpProvenanceCfgFn := func() *config.MCPToolProvenance {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return nil
			}
			return &c.MCPToolProvenance
		}
		mcpRedactionCfgFn := func() mcp.MCPRedactionConfig {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return mcp.MCPRedactionConfig{}
			}
			matcher, limits, required := s.proxy.CurrentRedactionConfigFor(c)
			return mcp.MCPRedactionConfig{
				Matcher:  matcher,
				Limits:   limits,
				Profile:  c.Redaction.DefaultProfile,
				Required: required,
			}
		}
		mcpTaintCfgFn := func() *config.TaintConfig {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return nil
			}
			return &c.Taint
		}
		mcpA2ACfgFn := func() *config.A2AScanning {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return nil
			}
			return &c.A2AScanning
		}
		mcpMediaPolicyFn := func() *config.MediaPolicy {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return nil
			}
			return &c.MediaPolicy
		}

		var mcpApprover *hitl.Approver
		if s.scanner.ResponseAction() == config.ActionAsk {
			mcpApprover = hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
			defer mcpApprover.Close()
		}

		// Bind MCP listener synchronously so port conflicts are caught
		// before the fetch proxy starts. Without this, a bind failure
		// would be silently swallowed until shutdown.
		mcpLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", s.opts.MCPListen)
		if lnErr != nil {
			err := fmt.Errorf("MCP listener bind %s: %w", s.opts.MCPListen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
		}

		// Share the proxy's session manager with the MCP listener so
		// both use the same store and the sessions gauge is not
		// double-counted. p.SessionStore() reads from the atomic
		// pointer, so it returns the live store even after hot-reloads.
		mcpStore := s.proxy.SessionStore() // nil when session profiling is disabled

		// Pass a function that reads the adaptive config from the live
		// proxy config on each request. This ensures the long-lived
		// MCP listener picks up hot-reload changes instead of being
		// frozen to the startup snapshot.
		mcpAdaptiveFn := mcp.AdaptiveConfigFunc(func() *config.AdaptiveEnforcement {
			c := s.proxy.CurrentConfig()
			if c != nil && c.AdaptiveEnforcement.Enabled {
				return &c.AdaptiveEnforcement
			}
			return nil
		})

		mcpErr = make(chan error, 1)
		go func() {
			var mcpCaptureObs capture.CaptureObserver
			if s.captureWriter != nil {
				mcpCaptureObs = s.captureWriter
			}
			mcpErr <- mcp.RunHTTPListenerProxy(ctx, mcpLn, s.opts.MCPUpstream, s.opts.Stderr, mcp.MCPProxyOpts{
				ScannerFn:           mcpScannerFn,
				Approver:            mcpApprover,
				InputCfgFn:          mcpInputCfgFn,
				ToolCfgFn:           mcpToolCfgFn,
				PolicyCfgFn:         s.currentToolPolicyCfg,
				KillSwitch:          s.killswitch,
				ChainMatcherFn:      s.currentMCPChainMatcher,
				AuditLogger:         s.logger,
				CEEFn:               s.currentMCPCEE,
				Store:               mcpStore,
				AdaptiveCfgFn:       mcpAdaptiveFn,
				Metrics:             s.metrics,
				RedirectRTFn:        mcpRedirectRTFn,
				CaptureObs:          mcpCaptureObs,
				ProvenanceCfgFn:     mcpProvenanceCfgFn,
				ReceiptEmitterFn:    s.liveReceiptEmitter,
				EnvelopeEmitterFn:   s.liveEnvelopeEmitter,
				RedactionCfgFn:      mcpRedactionCfgFn,
				TaintCfgFn:          mcpTaintCfgFn,
				A2ACfgFn:            mcpA2ACfgFn,
				MediaPolicyFn:       mcpMediaPolicyFn,
				ToolFreezer:         s.proxy.FrozenTools(),
				FrozenToolStableKey: s.opts.MCPUpstream,
			})
		}()
	}

	var reverseProxyErr chan error
	if cfg.ReverseProxy.Enabled {
		rpUpstream, rpErr := url.Parse(cfg.ReverseProxy.Upstream)
		if rpErr != nil {
			return fmt.Errorf("reverse proxy upstream: %w", rpErr)
		}

		var rpCaptureObs capture.CaptureObserver
		if s.captureWriter != nil {
			rpCaptureObs = s.captureWriter
		}
		rpHandler := proxy.NewReverseProxy(
			rpUpstream, s.proxy.ConfigPtr(), s.proxy.ScannerPtr(),
			s.logger, s.metrics, s.killswitch, rpCaptureObs, s.proxy.ShieldEngine(),
		)
		rpHandler.SetEnvelopeEmitter(s.proxy.EnvelopeEmitterPtr())
		rpHandler.SetReceiptEmitter(s.proxy.ReceiptEmitterPtr())
		rpHandler.SetReloadLock(s.proxy.ReloadLock())
		rpHandler.SetRedactionRuntimePtr(s.proxy.RedactionRuntimePtr())

		rpLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ReverseProxy.Listen)
		if lnErr != nil {
			err := fmt.Errorf("reverse proxy bind %s: %w", cfg.ReverseProxy.Listen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
		}

		rpSrv := newHTTPServer(rpHandler)
		rpSrv.WriteTimeout = 30 * time.Second // reverse proxy upstream requests need more time
		go func() {
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = rpSrv.Shutdown(shutdownCtx)
		}()

		reverseProxyErr = make(chan error, 1)
		go func() {
			srvErr := rpSrv.Serve(rpLn)
			if errors.Is(srvErr, http.ErrServerClosed) {
				srvErr = nil
			}
			reverseProxyErr <- srvErr
		}()
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: reverse proxy listening on %s -> %s\n",
			cfg.ReverseProxy.Listen, RedactEndpoint(cfg.ReverseProxy.Upstream))
	}

	// Per-agent listener servers. Each listener injects the agent profile
	// via context so identity is port-based, not header-based
	// (spoof-proof). Ports() returns addr->profile mapping from the
	// edition (empty in OSS mode).
	agentPorts := s.proxy.Ports()
	agentListenerCount := len(agentPorts)
	var agentListenerErrs chan error
	if agentListenerCount > 0 {
		handler := s.proxy.Handler()
		agentListenerErrs = make(chan error, agentListenerCount)

		// Agent listeners use the same WriteTimeout logic as the main
		// server: disabled when forward proxy or WebSocket proxy is
		// enabled (CONNECT tunnels and /ws sessions are long-lived).
		agentWriteTimeout := time.Duration(cfg.FetchProxy.TimeoutSeconds+10) * time.Second
		if cfg.ForwardProxy.Enabled || cfg.WebSocketProxy.Enabled {
			agentWriteTimeout = 0
		}

		for addr, name := range agentPorts {
			ln, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
			if lnErr != nil {
				err := fmt.Errorf("agent %q listener bind %s: %w", name, addr, lnErr)
				if s.sentry != nil {
					s.sentry.CaptureError(err)
				}
				return err
			}
			srv := newHTTPServer(AgentHandler(name, handler))
			srv.WriteTimeout = agentWriteTimeout
			// Register with proxy so its shutdown goroutine gracefully
			// stops agent servers alongside the main server.
			s.proxy.RegisterAgentServer(srv)
			go func(srv *http.Server, listener net.Listener) {
				srvErr := srv.Serve(listener)
				if errors.Is(srvErr, http.ErrServerClosed) {
					srvErr = nil
				}
				agentListenerErrs <- srvErr
			}(srv, ln)
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: agent %q listening on %s\n", name, addr)
		}
	}

	// License expiry watchdog: shut down agent listeners when the
	// enterprise license expires at runtime. Only active when agent
	// listeners exist and the license has a non-zero expiry.
	if agentListenerCount > 0 && cfg.LicenseExpiresAt > 0 {
		go func() {
			remaining := time.Until(time.Unix(cfg.LicenseExpiresAt, 0))
			if remaining <= 0 {
				_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: license expired, shutting down agent listeners\n")
				s.proxy.ShutdownAgentServers()
				return
			}
			timer := time.NewTimer(remaining)
			defer timer.Stop()
			select {
			case <-timer.C:
				_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: license expired, shutting down agent listeners\n")
				s.proxy.ShutdownAgentServers()
			case <-ctx.Done():
			}
		}()
	}

	// Start the fetch proxy (blocks until context cancelled or error).
	if err := s.proxy.Start(ctx); err != nil {
		if s.sentry != nil {
			s.sentry.CaptureError(err)
		}
		return fmt.Errorf("proxy error: %w", err)
	}

	for range agentListenerCount {
		if aErr := <-agentListenerErrs; aErr != nil {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: agent listener error: %v\n", aErr)
		}
	}

	if mcpErr != nil {
		if mErr := <-mcpErr; mErr != nil {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: MCP listener error: %v\n", mErr)
		}
	}

	if scanAPIErr != nil {
		if sErr := <-scanAPIErr; sErr != nil {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: scan API listener error: %v\n", sErr)
		}
	}

	if metricsErr != nil {
		if mErr := <-metricsErr; mErr != nil {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: metrics listener error: %v\n", mErr)
		}
	}

	if ksAPIErr != nil {
		if aErr := <-ksAPIErr; aErr != nil {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: kill switch API listener error: %v\n", aErr)
		}
	}

	if reverseProxyErr != nil {
		if rpErr := <-reverseProxyErr; rpErr != nil {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: reverse proxy listener error: %v\n", rpErr)
		}
	}

	s.logger.LogShutdown("signal received")
	_, _ = fmt.Fprintln(s.opts.Stderr, "\nPipelock stopped.")
	return nil
}

// Shutdown cancels Start's internal context so the serve loop unblocks.
// Safe to call before Start has begun (it is a no-op in that case).
// Cleanup of owned resources happens inside Start's deferred cleanup.
func (s *Server) Shutdown(_ context.Context) error {
	s.cancelMu.Lock()
	cancel := s.internalCancel
	s.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Reload applies a single hot-reload cycle against newCfg. Mirrors the
// goroutine body the pre-refactor RunCmd launched from reloader.Changes():
// gates restart-only fields, resolves runtime policy on a clone, runs
// ValidateReload, blocks strict-mode downgrades, swaps scanner + emit
// sinks + kill switch state, and dedups fsnotify + SIGHUP event stacking.
//
// Errors returned here correspond to the reload-rejected branches the
// original code logged via logger.LogError and then `return`-ed on, plus the
// "proxy kept the previous config" fail-safe path when proxy.Reload aborts its
// internal swap. Silent no-ops (dedup, restart-only field changes) return nil.
func (s *Server) Reload(newCfg *config.Config) (err error) {
	defer func() {
		if r := recover(); r != nil {
			ReloadPanicHandler(r, s.sentry, s.logger, s.opts.ConfigFile)
			err = fmt.Errorf("scanner construction panic during config reload: %v", r)
		}
	}()

	oldCfg := s.proxy.CurrentConfig()
	if oldCfg != nil {
		// Block enabling forward proxy via reload. WriteTimeout is set
		// at server start and cannot change at runtime; tunnels would
		// be killed prematurely. Restart to enable.
		if !oldCfg.ForwardProxy.Enabled && newCfg.ForwardProxy.Enabled {
			rejectErr := fmt.Errorf("rejected: forward proxy cannot be enabled via reload (requires restart)")
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
		// Block enabling WebSocket proxy via reload for the same
		// reason: WriteTimeout must be 0 at server start.
		if !oldCfg.WebSocketProxy.Enabled && newCfg.WebSocketProxy.Enabled {
			rejectErr := fmt.Errorf("rejected: WebSocket proxy cannot be enabled via reload (requires restart)")
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
		// Block api_listen changes via reload. The API server binds at
		// startup and can't rebind at runtime.
		if oldCfg.KillSwitch.APIListen != newCfg.KillSwitch.APIListen {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: kill_switch.api_listen changed from %q to %q — requires restart, ignoring\n",
				oldCfg.KillSwitch.APIListen, newCfg.KillSwitch.APIListen)
			newCfg.KillSwitch.APIListen = oldCfg.KillSwitch.APIListen
		}
		// Block metrics_listen changes via reload. The metrics server
		// binds at startup and can't rebind at runtime.
		if oldCfg.MetricsListen != newCfg.MetricsListen {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: metrics_listen changed from %q to %q — requires restart, ignoring\n",
				oldCfg.MetricsListen, newCfg.MetricsListen)
			newCfg.MetricsListen = oldCfg.MetricsListen
		}
		// Block scan_api listener setting changes via reload. The Scan
		// API server binds at startup and cannot rebind or reconfigure
		// connection limits / deadlines at runtime.
		if oldCfg.ScanAPI.Listen != newCfg.ScanAPI.Listen ||
			oldCfg.ScanAPI.ConnectionLimit != newCfg.ScanAPI.ConnectionLimit ||
			oldCfg.ScanAPI.Timeouts.Read != newCfg.ScanAPI.Timeouts.Read ||
			oldCfg.ScanAPI.Timeouts.Write != newCfg.ScanAPI.Timeouts.Write {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: scan_api listener settings changed — requires restart, ignoring\n")
			newCfg.ScanAPI.Listen = oldCfg.ScanAPI.Listen
			newCfg.ScanAPI.ConnectionLimit = oldCfg.ScanAPI.ConnectionLimit
			newCfg.ScanAPI.Timeouts = oldCfg.ScanAPI.Timeouts
		}
		// Block signing key rotation via reload. The receipt chain
		// state is anchored to the current signing key; rotation
		// mid-chain causes tail-signature verification to fail on
		// resume, which in turn drops receipt persistence for every
		// subsequent action. Proper chain rollover with a key-rotation
		// marker is tracked for v2.2.1. Until then, preserve the old
		// key and warn — operators must restart pipelock to rotate the
		// receipt signing key.
		if oldCfg.FlightRecorder.SigningKeyPath != newCfg.FlightRecorder.SigningKeyPath {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: flight_recorder.signing_key_path changed from %q to %q — receipt chain cannot rotate at runtime, ignoring (restart required)\n",
				oldCfg.FlightRecorder.SigningKeyPath, newCfg.FlightRecorder.SigningKeyPath)
			newCfg.FlightRecorder.SigningKeyPath = oldCfg.FlightRecorder.SigningKeyPath
		}

		// Dedupe identical-hash reload EVENTS within a short window.
		// fsnotify + SIGHUP stack up so a single `echo cfg > path;
		// kill -HUP` sequence triggers two reload Changes() events in
		// quick succession; the second is pure noise. Switch to a
		// time-windowed dedup keyed on the LAST EMITTED reload event:
		// the first of a stacked pair still logs, any event with the
		// same hash inside 2s skips silently.
		if s.shouldSkipReload(newCfg.Hash()) {
			return nil
		}

		// Block reverse proxy listener/upstream changes via reload.
		// The listener binds at startup and the upstream is pinned in
		// the handler. Requires restart.
		if oldCfg.ReverseProxy.Listen != newCfg.ReverseProxy.Listen ||
			oldCfg.ReverseProxy.Enabled != newCfg.ReverseProxy.Enabled ||
			oldCfg.ReverseProxy.Upstream != newCfg.ReverseProxy.Upstream {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: reverse_proxy settings changed — requires restart, ignoring\n")
			newCfg.ReverseProxy = oldCfg.ReverseProxy
		}
		// Block agent listener changes via reload. Listener sockets
		// are bound at startup and cannot be rebound at runtime. Warn
		// and preserve old listener config.
		//
		// Respect the license gate: if EnforceLicenseGate disabled
		// agents on reload, do not re-add them via listener
		// preservation.
		agentsRevokedByLicense := oldCfg.Agents != nil && newCfg.Agents == nil
		licenseInputsChanged := oldCfg.LicenseKey != newCfg.LicenseKey || oldCfg.LicensePublicKey != newCfg.LicensePublicKey || oldCfg.LicenseFile != newCfg.LicenseFile

		if agentsRevokedByLicense {
			// License gate disabled agents on reload. Shut down
			// already-bound listener servers so the agent ports
			// stop accepting traffic.
			s.proxy.ShutdownAgentServers()
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: license revoked agents, shutting down agent listeners\n")
		} else if licenseInputsChanged {
			// License inputs changed but agents were not revoked.
			// Preserve ALL old license state so a reload cannot
			// activate licensed features without a restart. We
			// must also preserve the old license input fields
			// themselves; otherwise the new values get committed
			// to the live config and a subsequent unrelated reload
			// would see no diff, silently applying the staged
			// license.
			newCfg.Agents = oldCfg.Agents
			newCfg.LicenseKey = oldCfg.LicenseKey
			newCfg.LicenseFile = oldCfg.LicenseFile
			newCfg.LicensePublicKey = oldCfg.LicensePublicKey
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: license key inputs changed (license_key, license_file, or license_public_key) - requires restart for license re-verification\n")
		} else if AgentListenersChanged(oldCfg, newCfg) {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: agents[*].listeners changed — requires restart, ignoring listener changes\n")
			PreserveAgentListeners(oldCfg, newCfg)
		}
		// Carry forward runtime-derived license expiry.
		// LicenseExpiresAt is set by EnforceLicenseGate at startup,
		// not parsed from YAML. Always preserve the old value until
		// restart.
		newCfg.LicenseExpiresAt = oldCfg.LicenseExpiresAt
	}

	// Surface advisory warnings on reload the same way NewServer does at
	// startup. The Reloader discards warnings from Load()'s internal
	// Validate() call, so re-run the idempotent validator after deduping
	// stacked reload events and after preserving restart-only fields.
	if reloadWarns, _ := newCfg.ValidateWithWarnings(); len(reloadWarns) > 0 {
		for _, wn := range reloadWarns {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: %s: %s\n", wn.Field, wn.Message)
		}
	}

	// Resolve runtime policy on a clone of the newly loaded config so
	// the reloaded cfg stored in the proxy reflects the same
	// bundle-merge + auto-enable pipeline startup uses and its
	// canonical hash is computed fresh. The live runtime mode tracks
	// the startup flags: reload cannot toggle MCP listener or forward
	// proxy enablement (both gated above).
	var reloadBundleResult *rules.LoadResult
	newCfg, _ = newCfg.ResolveRuntime(config.RuntimeResolveOpts{
		Mode: s.runtimeMode,
		MergeBundles: func(c *config.Config) {
			reloadBundleResult = rules.MergeIntoConfig(c, cliutil.Version)
		},
		DefaultToolPolicyRules: policy.DefaultToolPolicyRules,
	})
	for _, e := range reloadBundleResult.Errors {
		_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: bundle %s: %s\n", e.Name, e.Reason)
	}
	for _, w := range reloadBundleResult.Warnings {
		_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: %s\n", w)
	}
	if reloadBundleResult.Degraded {
		_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: DEGRADED — standard pack failed after reload, running core patterns only\n")
	}
	if oldCfg != nil {
		// Compare resolved-vs-resolved configs so bundle merges and
		// MCP listener auto-enable do not look like policy downgrades
		// during hot reload.
		warnings := config.ValidateReload(oldCfg, newCfg)
		for _, w := range warnings {
			_, _ = fmt.Fprintf(s.opts.Stderr, "WARNING: config reload: %s - %s\n", w.Field, w.Message)
		}
		// Block downgrades from strict mode (security-critical).
		if oldCfg.Mode == config.ModeStrict && len(warnings) > 0 {
			rejectErr := fmt.Errorf("rejected: security downgrade from strict mode")
			s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), rejectErr)
			return rejectErr
		}
	}
	newSc := scanner.New(newCfg)
	newSc.SetDLPWarnHook(func(ctx context.Context, patternName, severity string) {
		emitDLPWarn(s.logger, s.metrics, s.liveReceiptEmitter(), ctx, patternName, severity)
	})
	if !s.proxy.Reload(newCfg, newSc) {
		return errors.New("reload failed: proxy kept previous config")
	}
	s.refreshRuntimeState(oldCfg, newCfg, reloadBundleResult, s.proxy.ScannerPtr().Load())
	if reloadErr := s.proxy.LoadCertCache(newCfg); reloadErr != nil {
		s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile),
			fmt.Errorf("TLS cert cache reload failed: %w", reloadErr))
	}
	s.killswitch.Reload(newCfg)

	// Reload emit sinks: build new sinks from config, swap into
	// emitter, close old sinks.
	newSinks, sinkErr := BuildEmitSinks(newCfg)
	if sinkErr != nil {
		s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile),
			fmt.Errorf("emit sink rebuild failed: %w", sinkErr))
	} else {
		oldSinks := s.emitter.ReloadSinks(newSinks)
		for _, old := range oldSinks {
			if closeErr := old.Close(); closeErr != nil {
				s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile),
					fmt.Errorf("closing old emit sink: %w", closeErr))
			}
		}
	}

	if newCfg.ResponseScanning.Action == config.ActionAsk && !s.hasApprover {
		_, _ = fmt.Fprintln(s.opts.Stderr, "WARNING: config reloaded to ask mode but HITL approver was not initialized at startup; detections will be blocked")
	}
	reloadHash := newCfg.Hash()
	s.logger.LogConfigReload("success", fmt.Sprintf("mode=%s", newCfg.Mode), reloadHash)
	s.recordReloadSuccess(reloadHash)
	return nil
}

// cleanup closes all owned resources. Safe to call multiple times: each
// field is niled after its close so repeat calls are no-ops. LIFO order
// mirrors the original RunCmd deferred closures so shutdown sequencing is
// preserved.
func (s *Server) cleanup() {
	if s.recorder != nil {
		_ = s.recorder.Close()
		s.recorder = nil
	}
	if s.captureWriter != nil {
		_ = s.captureWriter.Close()
		s.captureWriter = nil
	}
	if s.approver != nil {
		s.approver.Close()
		s.approver = nil
	}
	liveScanner := s.scanner
	if s.proxy != nil {
		if current := s.proxy.ScannerPtr().Load(); current != nil {
			liveScanner = current
		}
	}
	if liveScanner != nil {
		liveScanner.Close()
		s.scanner = nil
	}
	if s.emitter != nil {
		_ = s.emitter.Close()
		s.emitter = nil
	}
	if s.logger != nil {
		s.logger.Close()
		s.logger = nil
	}
	if s.sentry != nil {
		s.sentry.Close()
		s.sentry = nil
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/rules"
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
	// conductorApply holds *applycache.Cache in the enterprise build (nil
	// in the core build). Stored as any so server.go has no compile-time
	// dependency on the enterprise conductor packages; the build-tagged
	// ApplyConductorPolicyBundle type-asserts back to the concrete type.
	conductorApply any
	// conductorAuditQueue holds *auditbatcher.Queue in the enterprise
	// build. The producer setup that runs after the flight recorder is
	// constructed needs this handle; stash it on the server so the two
	// build-tagged init methods can share state without touching server.go.
	conductorAuditQueue any
	conductorAudit      conductorRunner
	conductorRemoteKill conductorRunner
	conductorBundle     conductorRunner
	conductorProducer   conductorCloser

	// conductorLifeMu guards conductorCancel and conductorWait.
	// teardownConductor may be invoked concurrently from the runtime CRL watcher
	// and the config reload path, so lifecycle handles are published and read
	// under the lock.
	conductorLifeMu sync.Mutex
	conductorCancel context.CancelFunc
	conductorWait   func()
	// conductorDown is set by teardownConductor when a runtime fleet-license
	// revocation, expiry, or downgrade stops the follower-side Conductor
	// runtime. It gates ApplyConductorPolicyBundle (no further policy bundles
	// apply once down) and makes teardown idempotent. Losing the paid fleet
	// entitlement stops Conductor but never the proxy/detection path.
	// Conductor stays down until process restart, matching the restart-only
	// conductor invariant (a reload cannot re-activate it).
	conductorDown atomic.Bool

	approver *hitl.Approver

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

	// conductorApplyMu serializes ApplyConductorPolicyBundle so the
	// stage -> reload -> activate sequence is atomic. Concurrent applies
	// would otherwise be able to interleave such that one bundle wins the
	// Reload while another wins Activate, leaving the durable last-known-good
	// pointer out of sync with the running config.
	conductorApplyMu sync.Mutex

	stateMu            sync.RWMutex
	toolPolicyCfg      *policy.Config
	mcpChainMatcher    *chains.Matcher
	mcpCEE             *mcp.CEEDeps
	mcpToolExtraPoison []*tools.ExtraPoisonPattern
}

// stderrSyncWriter wraps the operator-facing stderr writer with a mutex so
// concurrent producers (Reload's warning emitter and the MCP listener
// startup log path) cannot interleave or race a shared bytes.Buffer when
// tests substitute one.
type stderrSyncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *stderrSyncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// NewServer validates opts, loads config, applies CLI overrides, and builds
// every runtime component. No ports are bound; that is Start's job. On any
// construction failure NewServer closes whatever was partially built and
// returns the error.
func NewServer(opts ServerOpts) (*Server, error) {
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	opts.Stderr = &stderrSyncWriter{w: opts.Stderr}
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
	emitLicenseExpiryWarning(cfg, logger, sentryClient, opts.Stderr)

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
	// License gate for the follower-side Conductor runtime. When
	// conductor.enabled is true the operator has explicitly opted into
	// central governance (remote kill, audit ingest, policy distribution);
	// fail-closed if the license does not grant the fleet feature, so the
	// process does not silently start a half-wired follower the operator
	// expects to be participating.
	if cfg.Conductor.Enabled {
		lic, err := license.VerifyFleetWithIntermediate(cfg.LicenseKey, cfg.LicensePublicKey, cfg.LicenseCRLFile, cfg.LicenseIntermediateFile)
		if err != nil {
			s.cleanup()
			return nil, err
		}
		cfg.LicenseID = lic.ID
		cfg.LicenseExpiresAt = lic.ExpiresAt
	}
	if err := s.initConductorApplyAndAudit(cfg, m); err != nil {
		s.cleanup()
		return nil, err
	}
	sc.SetDLPWarnHook(func(ctx context.Context, patternName, severity string) {
		emitDLPWarn(s.logger, s.metrics, s.liveReceiptEmitter(), ctx, patternName, severity)
	})

	ks := killswitch.New(cfg)
	m.RegisterKillSwitchState(ks.Sources)
	m.RegisterInfo(cliutil.Version)
	s.killswitch = ks

	ksAPI := killswitch.NewAPIHandler(ks)
	s.ksAPI = ksAPI
	if err := s.initConductorRemoteKill(cfg, ks, opts.Stderr); err != nil {
		s.cleanup()
		return nil, err
	}
	if err := s.initConductorBundlePoller(cfg, opts.Stderr); err != nil {
		s.cleanup()
		return nil, err
	}

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
		// Redaction parity with the MCP proxy: DLP-scrub captured payloads
		// before they hit disk unless flight_recorder.redact is disabled.
		// Previously the HTTP --capture-output path passed no RedactFn, so
		// tool args / bodies were written un-redacted regardless of the
		// redact knob; buildCaptureWriter now honors it on both surfaces.
		var captureRedactFn recorder.RedactFunc
		if cfg.FlightRecorder.Redact {
			captureRedactFn = sc.ScanTextForDLP
		}
		cw, cwErr := buildCaptureWriter(opts.CaptureOutput, opts.CaptureEscrowKey, cfg.FlightRecorder.FileMode, captureRedactFn, m)
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
	var recPrivKey ed25519.PrivateKey
	if cfg.FlightRecorder.Enabled && cfg.FlightRecorder.Dir != "" {
		recCfg := recorder.Config{
			Enabled:            cfg.FlightRecorder.Enabled,
			Dir:                cfg.FlightRecorder.Dir,
			CheckpointInterval: cfg.FlightRecorder.CheckpointInterval,
			RetentionDays:      cfg.FlightRecorder.RetentionDays,
			Redact:             cfg.FlightRecorder.Redact,
			SignCheckpoints:    cfg.FlightRecorder.SignCheckpoints,
			MaxEntriesPerFile:  cfg.FlightRecorder.MaxEntriesPerFile,
			FileMode:           cfg.FlightRecorder.FileMode,
			RawEscrow:          cfg.FlightRecorder.RawEscrow,
			EscrowPublicKey:    cfg.FlightRecorder.EscrowPublicKey,
		}

		var redactFn recorder.RedactFunc
		if cfg.FlightRecorder.Redact {
			redactFn = sc.ScanTextForDLP
		}

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
		// hash because its contract is the opposite - identical
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

			// v2 proxy_decision emitter: dual-emitted alongside the v1 action
			// receipt on every proxy decision, signed with the same key and
			// gated on the same receipt intent (no separate flag). Sanitizes
			// targets with the recorder's redactor (#676) before signing.
			if v2Emitter := proxydecision.NewEmitter(proxydecision.EmitterConfig{
				Recorder:  rec,
				Signer:    proxydecision.NewKeyedSigner(recPrivKey),
				Sanitize:  proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()),
				Principal: "local",
				Actor:     "pipelock",
			}); v2Emitter != nil {
				proxyOpts = append(proxyOpts, proxy.WithV2ReceiptEmitter(v2Emitter))
				_, _ = fmt.Fprintf(opts.Stderr, "  Receipts: v2 proxy_decision dual-emit enabled\n")
			}
		}

		_, _ = fmt.Fprintf(opts.Stderr, "  Recorder: %s (flight recorder enabled)\n", cfg.FlightRecorder.Dir)
	}
	if err := s.initConductorProducer(cfg, m, recPrivKey, opts.Stderr); err != nil {
		s.cleanup()
		return nil, err
	}

	if cfg.MediationEnvelope.Enabled {
		s.envelopeEmitter = envelope.NewEmitter(envelope.EmitterConfig{
			ConfigHash:  cfg.CanonicalPolicyHash(),
			ActorFormat: cfg.MediationEnvelope.ActorFormat,
			TrustDomain: cfg.MediationEnvelope.TrustDomain,
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

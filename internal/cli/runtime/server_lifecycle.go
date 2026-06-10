// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/filesentry"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanapi"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func (s *Server) startFileSentry(ctx context.Context, cfg *config.Config, cancel context.CancelFunc) (func(), error) {
	if cfg == nil || !cfg.FileSentry.Enabled {
		return func() {}, nil
	}

	onErr := func(err error) {
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: [file_sentry] %v\n", err)
	}
	watcher, err := filesentry.NewWatcher(&cfg.FileSentry, liveFileSentryScanner{
		load: func() *scanner.Scanner {
			if s.proxy == nil {
				return nil
			}
			return s.proxy.ScannerPtr().Load()
		},
	}, nil, onErr)
	if err != nil {
		if cfg.FileSentry.BestEffort {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: file sentry init failed (best_effort: continuing without file monitoring): %v\n", err)
			return func() {}, nil
		}
		return nil, fmt.Errorf("file sentry init failed (feature is enabled): %w", err)
	}

	if err := watcher.Arm(); err != nil {
		_ = watcher.Close()
		if cfg.FileSentry.BestEffort {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: file sentry failed to arm watches (best_effort: continuing without file monitoring): %v\n", err)
			return func() {}, nil
		}
		return nil, fmt.Errorf("file sentry failed to arm watches (feature is enabled): %w", err)
	}

	var findingHook filesentry.FindingHook
	if s.metrics != nil {
		findingHook = s.metrics.RecordFileSentryFinding
	}
	waitConsumer := filesentry.ConsumeFindings(filesentry.ConsumerOpts{
		Watcher:   watcher,
		Action:    cfg.FileSentry.Action,
		Log:       s.opts.Stderr,
		OnFinding: findingHook,
		Cancel:    cancel,
	})

	go func() {
		if err := watcher.Start(ctx); err != nil {
			_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: file sentry fatal: %v — cancelling runtime\n", err)
			cancel()
		}
	}()

	_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: file sentry watching %d path(s) (action=%s)\n",
		len(cfg.FileSentry.WatchPaths), cfg.FileSentry.Action)

	return func() {
		_ = watcher.Close()
		waitConsumer()
	}, nil
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

	// lifecycleWG joins every long-lived listener/watcher goroutine spawned
	// below (kill-switch API, metrics, scan API, MCP, reverse proxy, agent
	// listeners, license watchers). This deferred join is registered after
	// s.cleanup(), so in LIFO order it runs BEFORE cleanup() closes and nils
	// shared Server fields (s.logger, s.scanner, s.emitter, ...). Without it,
	// an early-error return (e.g. a fetch_proxy bind failure) races cleanup()
	// against an in-flight listener goroutine still reading those fields.
	// Order matters: cancel() first so ctx-driven goroutines and the HTTP
	// shutdown goroutines wake, then ShutdownAgentServers() to unblock agent
	// listener Serve loops on early-error paths where proxy.Start never ran its
	// own shutdown, then Wait() for every goroutine to finish (HTTP shutdown
	// goroutines complete only after in-flight handlers drain).
	var lifecycleWG sync.WaitGroup
	defer func() {
		cancel()
		s.proxy.ShutdownAgentServers()
		lifecycleWG.Wait()
		// Drain-then-seal: the main proxy server (s.proxy.Start below) has
		// already returned and every auxiliary receipt-emitting listener has now
		// joined lifecycleWG, so no Emit can race the seal. Write the transcript
		// root here, before the deferred s.cleanup() (registered earlier, so it
		// runs after this) closes the recorder. Sealing the completeness anchor
		// on clean exit is the whole point of F4; it is a no-op when receipts are
		// off or none were emitted.
		s.sealTranscriptRoot()
	}()

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

		// Block until the config file watch is established before continuing to
		// bind and serve. Without this, the proxy can report healthy while the
		// watch is not yet active, and a config edit made in that window is
		// silently missed until the next write. Ready() also closes if the
		// reloader exits without establishing the watch, so this never deadlocks
		// on a watcher-setup failure (the error is logged above).
		select {
		case <-reloader.Ready():
		case <-ctx.Done():
		}

		reloadWG.Add(1)
		go func() {
			defer reloadWG.Done()
			for newCfg := range reloader.Changes() {
				if err := s.Reload(newCfg); err != nil {
					s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), err)
				}
				// Signal reload-cycle completion for tests (no-op in
				// production). Fires per delivered config so reload tests can
				// block on the event instead of polling stderr on a deadline.
				fireReloadCompletedHook()
			}
		}()
	}

	if !IsContainerized() {
		_, _ = fmt.Fprintln(s.opts.Stderr, "WARNING: running outside a container - consider using Docker/Podman for network isolation")
	}

	cfg := s.currentConfig()
	stopFileSentry, fsErr := s.startFileSentry(ctx, cfg, cancel)
	if fsErr != nil {
		return fsErr
	}
	defer stopFileSentry()

	_, _ = fmt.Fprintf(s.opts.Stderr, "Pipelock %s starting\n", cliutil.DisplayVersion())
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
	if s.conductorAudit != nil {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Conductor: audit transport enabled -> %s\n", RedactEndpoint(cfg.Conductor.ConductorURL))
	}
	if s.conductorRemoteKill != nil {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Conductor: remote kill polling enabled -> %s\n", RedactEndpoint(cfg.Conductor.ConductorURL))
	}
	if s.conductorBundle != nil {
		_, _ = fmt.Fprintf(s.opts.Stderr, "  Conductor: policy bundle polling enabled -> %s\n", RedactEndpoint(cfg.Conductor.ConductorURL))
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

	var conductorWG sync.WaitGroup
	// conductorCtx is a child of the process context so teardownConductor can
	// stop the follower-side Conductor pollers on a runtime fleet-license
	// revocation/expiry/downgrade WITHOUT tearing down the proxy/detection
	// path. Process shutdown still cancels them via the parent ctx. When a
	// poller's Run returns context.Canceled (the teardown signal) the error
	// branches below intentionally skip the process-wide cancel().
	conductorCtx := ctx
	if s.conductorAudit != nil || s.conductorRemoteKill != nil || s.conductorBundle != nil {
		var conductorCancel context.CancelFunc
		conductorCtx, conductorCancel = context.WithCancel(ctx)
		s.setConductorCancel(conductorCancel)
		if s.conductorRemoteKill != nil {
			conductorWG.Add(1)
		}
		if s.conductorAudit != nil {
			conductorWG.Add(1)
		}
		if s.conductorBundle != nil {
			conductorWG.Add(1)
		}
		s.setConductorWait(conductorWG.Wait)
	}
	if s.conductorAudit != nil || s.conductorRemoteKill != nil || s.conductorBundle != nil {
		if s.conductorRemoteKill != nil {
			go func() {
				defer conductorWG.Done()
				defer func() {
					if r := recover(); r != nil {
						_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: conductor remote kill poller panic: %v\n", r)
						cancel()
					}
				}()
				if err := s.conductorRemoteKill.Run(conductorCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					s.logger.LogError(audit.NewResourceLogContext("conductor_remote_kill_poller", cfg.Conductor.ConductorURL), err)
					_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: conductor remote kill poller stopped: %v\n", err)
					cancel()
				}
			}()
		}
	}
	if s.conductorAudit != nil {
		go func() {
			defer conductorWG.Done()
			defer func() {
				if r := recover(); r != nil {
					_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: conductor audit transport panic: %v\n", r)
				}
			}()
			if err := s.conductorAudit.Run(conductorCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.logger.LogError(audit.NewResourceLogContext("conductor_audit_transport", cfg.Conductor.ConductorURL), err)
				_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: conductor audit transport stopped: %v\n", err)
			}
		}()
	}
	if s.conductorBundle != nil {
		go func() {
			defer conductorWG.Done()
			defer func() {
				if r := recover(); r != nil {
					_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: conductor policy bundle poller panic: %v\n", r)
					cancel()
				}
			}()
			if err := s.conductorBundle.Run(conductorCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.logger.LogError(audit.NewResourceLogContext("conductor_policy_bundle_poller", cfg.Conductor.ConductorURL), err)
				_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: conductor policy bundle poller stopped: %v\n", err)
				cancel()
			}
		}()
	}
	if s.conductorAudit != nil || s.conductorRemoteKill != nil || s.conductorBundle != nil {
		defer func() {
			cancel()
			conductorWG.Wait()
		}()
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
		// configured - in that case we skip registration and the
		// admin routes simply don't exist on the listener.
		if sessionAPI := s.proxy.SessionAPI(); sessionAPI != nil {
			apiMux.HandleFunc("/api/v1/adaptive/status", sessionAPI.HandleAdaptiveStatus)
			apiMux.HandleFunc("/api/v1/adaptive/flush", sessionAPI.HandleAdaptiveFlush)
			apiMux.HandleFunc("/api/v1/adaptive/whoami", sessionAPI.HandleAdaptiveWhoami)
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
			err := wrapBindError("kill_switch.api_listen", cfg.KillSwitch.APIListen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
		}

		apiSrv := newHTTPServer(apiMux)
		lifecycleWG.Add(1)
		go func() { //nolint:gosec // G118: graceful shutdown after <-ctx.Done(); using ctx as parent would skip the grace period
			defer lifecycleWG.Done()
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = apiSrv.Shutdown(shutdownCtx) //nolint:errcheck // best-effort shutdown
		}()

		ksAPIErr = make(chan error, 1)
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
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
			err := wrapBindError("metrics_listen", cfg.MetricsListen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
		}
		metricsSrv := newHTTPServer(metricsMux)
		lifecycleWG.Add(1)
		go func() { //nolint:gosec // G118: graceful shutdown after <-ctx.Done(); using ctx as parent would skip the grace period
			defer lifecycleWG.Done()
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
		metricsErr = make(chan error, 1)
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
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
			err := wrapBindError("scan_api.listen", cfg.ScanAPI.Listen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
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
		lifecycleWG.Add(1)
		go func() { //nolint:gosec // G118: graceful shutdown after <-ctx.Done(); using ctx as parent would skip the grace period
			defer lifecycleWG.Done()
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = scanAPISrv.Shutdown(shutdownCtx)
		}()

		scanAPIErr = make(chan error, 1)
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
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
			// Closed inside the MCP listener goroutine below, after
			// RunHTTPListenerProxy returns, so the approver outlives every
			// request the listener hands it. A function-scoped defer would
			// close it while the listener goroutine is still serving.
		}

		// Bind MCP listener synchronously so port conflicts are caught
		// before the fetch proxy starts. Without this, a bind failure
		// would be silently swallowed until shutdown.
		mcpLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", s.opts.MCPListen)
		if lnErr != nil {
			err := wrapBindErrorNoDoctorHint("mcp_listen", s.opts.MCPListen, lnErr)
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
		mcpConfigHashFn := func() string {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return ""
			}
			return c.CanonicalPolicyHash()
		}
		mcpRequestBodyFn := func() *config.RequestBodyScanning {
			c := s.proxy.CurrentConfig()
			if c == nil {
				return nil
			}
			return &c.RequestBodyScanning
		}

		mcpErr = make(chan error, 1)
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
			if mcpApprover != nil {
				defer mcpApprover.Close()
			}
			var mcpCaptureObs capture.CaptureObserver
			if s.captureWriter != nil {
				mcpCaptureObs = s.captureWriter
			}
			mcpErr <- mcp.RunHTTPListenerProxy(ctx, mcpLn, s.opts.MCPUpstream, s.opts.Stderr, mcp.MCPProxyOpts{
				ScannerFn:              mcpScannerFn,
				Approver:               mcpApprover,
				InputCfgFn:             mcpInputCfgFn,
				RequestBodyFn:          mcpRequestBodyFn,
				ToolCfgFn:              mcpToolCfgFn,
				PolicyCfgFn:            s.currentToolPolicyCfg,
				KillSwitch:             s.killswitch,
				ChainMatcherFn:         s.currentMCPChainMatcher,
				AuditLogger:            s.logger,
				CEEFn:                  s.currentMCPCEE,
				Store:                  mcpStore,
				AdaptiveCfgFn:          mcpAdaptiveFn,
				Metrics:                s.metrics,
				RedirectRTFn:           mcpRedirectRTFn,
				CaptureObs:             mcpCaptureObs,
				ConfigHashFn:           mcpConfigHashFn,
				Profile:                edition.ProfileDefault,
				AddressProtectionAgent: edition.ProfileDefault,
				ProvenanceCfgFn:        mcpProvenanceCfgFn,
				ReceiptEmitterFn:       s.liveReceiptEmitter,
				V2ReceiptEmitterFn:     s.liveV2ReceiptEmitter,
				PolicyHashFn:           mcpConfigHashFn,
				EnvelopeEmitterFn:      s.liveEnvelopeEmitter,
				RedactionCfgFn:         mcpRedactionCfgFn,
				TaintCfgFn:             mcpTaintCfgFn,
				A2ACfgFn:               mcpA2ACfgFn,
				MediaPolicyFn:          mcpMediaPolicyFn,
				ToolFreezer:            s.proxy.FrozenTools(),
				FrozenToolStableKey:    s.opts.MCPUpstream,
				ContractLoaderPtr:      s.proxy.ContractLoaderPtr(),
				ContractAgent:          edition.ProfileDefault,
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
		rpHandler.SetEnvelopeVerifier(s.proxy.EnvelopeVerifierPtr())
		rpHandler.SetReceiptEmitter(s.proxy.ReceiptEmitterPtr())
		rpHandler.SetV2ReceiptEmitter(s.proxy.V2EmitterPtr())
		rpHandler.SetContractLoader(s.proxy.ContractLoaderPtr())
		rpHandler.SetReloadLock(s.proxy.ReloadLock())
		rpHandler.SetRequestPolicyFn(s.proxy.ApplyRequestPolicy)
		rpHandler.SetRequestPolicyPrepareFn(s.proxy.PrepareRequestPolicyBody)
		rpHandler.SetRedactionRuntimePtr(s.proxy.RedactionRuntimePtr())
		// Submit profile dials through the SSRF-safe dial path (resolve +
		// validate every IP against internal CIDRs before connecting),
		// matching the fetch/forward transports. Generic reverse-proxy mode
		// keeps the default dialer: the operator chose that upstream.
		if cfg.ReverseProxy.Profile == config.ReverseProxyProfileSubmit {
			rpHandler.SetSafeDialer(s.proxy.SafeDialer())
		}

		rpLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ReverseProxy.Listen)
		if lnErr != nil {
			err := wrapBindError("reverse_proxy.listen", cfg.ReverseProxy.Listen, lnErr)
			if s.sentry != nil {
				s.sentry.CaptureError(err)
			}
			return err
		}

		rpSrv := newHTTPServer(rpHandler)
		rpSrv.WriteTimeout = 30 * time.Second // reverse proxy upstream requests need more time
		lifecycleWG.Add(1)
		go func() { //nolint:gosec // G118: graceful shutdown after <-ctx.Done(); using ctx as parent would skip the grace period
			defer lifecycleWG.Done()
			<-ctx.Done()
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer shutCancel()
			_ = rpSrv.Shutdown(shutdownCtx)
		}()

		reverseProxyErr = make(chan error, 1)
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
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
				err := wrapBindErrorNoDoctorHint(fmt.Sprintf("agents[%s].listen", name), addr, lnErr)
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
			lifecycleWG.Add(1)
			go func(srv *http.Server, listener net.Listener) {
				defer lifecycleWG.Done()
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
	// enterprise license expires at runtime. Agent shutdown only matters
	// when listeners exist, but renewal warnings still emit for long-running
	// proxy-only processes.
	if (agentListenerCount > 0 || cfg.Conductor.Enabled) && cfg.LicenseExpiresAt > 0 {
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
			remaining := time.Until(time.Unix(cfg.LicenseExpiresAt, 0))
			if remaining <= 0 {
				s.expireLicensedRuntime()
				return
			}
			timer := time.NewTimer(remaining)
			defer timer.Stop()
			select {
			case <-timer.C:
				s.expireLicensedRuntime()
			case <-ctx.Done():
			}
		}()
	}
	if cfg.LicenseExpiresAt > 0 {
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
			s.startLicenseExpiryWatcher(ctx)
		}()
	}
	if (agentListenerCount > 0 || cfg.Conductor.Enabled) && cfg.LicenseCRLFile != "" {
		lifecycleWG.Add(1)
		go func() {
			defer lifecycleWG.Done()
			s.startLicenseCRLWatcher(ctx)
		}()
	}

	// Start the fetch proxy (blocks until context cancelled or error).
	if err := s.proxy.Start(ctx); err != nil {
		err = wrapBindError("fetch_proxy.listen", cfg.FetchProxy.Listen, err)
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

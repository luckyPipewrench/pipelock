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
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"golang.org/x/net/netutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanapi"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	plsentry "github.com/luckyPipewrench/pipelock/internal/sentry"
)

// RunCmd returns the run cobra command.
func RunCmd() *cobra.Command {
	var configFile string
	var mode string
	var listen string
	var mcpListen string
	var mcpUpstream string
	var reverseProxy bool
	var reverseUpstream string
	var reverseListen string

	cmd := &cobra.Command{
		Use:   "run [flags]",
		Short: "Start the Pipelock proxy",
		Long: `Start the proxy server that scans and controls agent HTTP traffic.

Supports two proxy modes on the same port:
  - Fetch proxy:   /fetch?url=... (extracts text, scans responses)
  - Forward proxy: CONNECT tunnels + absolute-URI (set HTTPS_PROXY, zero agent changes)

Optionally runs an MCP HTTP listener alongside the fetch proxy. The MCP listener
accepts JSON-RPC POST requests and proxies them to an upstream MCP server with
bidirectional scanning (DLP, injection, tool poisoning, policy).

The proxy runs until interrupted (SIGINT/SIGTERM). When started with --config,
file changes (and SIGHUP on Unix) trigger a hot-reload of config and scanner.

Examples:
  pipelock run                                       # standalone proxy
  pipelock run --config pipelock.yaml                # with config file (hot-reload)
  pipelock run --mode strict --listen 0.0.0.0:9999   # override mode and listen address
  pipelock run --mcp-listen 0.0.0.0:8889 --mcp-upstream http://mcp-server:3000/mcp`,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // args used via ArgsLenAtDash
			// Validate MCP listener flags.
			hasMCPListen := mcpListen != ""
			hasMCPUpstream := mcpUpstream != ""
			if hasMCPListen && !hasMCPUpstream {
				return errors.New("--mcp-listen requires --mcp-upstream")
			}
			if hasMCPUpstream && !hasMCPListen {
				return errors.New("--mcp-upstream requires --mcp-listen")
			}
			if hasMCPUpstream {
				u, uErr := url.Parse(mcpUpstream)
				if uErr != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
					return fmt.Errorf("invalid --mcp-upstream %q: must be http:// or https:// with a host", mcpUpstream)
				}
			}

			// Validate reverse proxy flags.
			if reverseProxy && reverseUpstream == "" {
				return errors.New("--reverse-proxy requires --reverse-upstream")
			}
			if reverseUpstream != "" && !reverseProxy {
				return errors.New("--reverse-upstream requires --reverse-proxy")
			}
			var reverseUpstreamURL *url.URL
			if reverseProxy {
				var uErr error
				reverseUpstreamURL, uErr = url.Parse(reverseUpstream)
				if uErr != nil || (reverseUpstreamURL.Scheme != schemeHTTP && reverseUpstreamURL.Scheme != schemeHTTPS) || reverseUpstreamURL.Host == "" {
					return fmt.Errorf("invalid --reverse-upstream %q: must be http:// or https:// with a host", reverseUpstream)
				}
				if reverseListen == "" {
					reverseListen = ":8890"
				}
			}

			// Load config
			var cfg *config.Config
			var err error

			if configFile != "" {
				cfg, err = config.Load(configFile)
				if err != nil {
					return fmt.Errorf("loading config: %w", err)
				}
			} else {
				cfg = config.Defaults()
			}

			// Override flags if provided
			if cmd.Flags().Changed("mode") {
				cfg.Mode = mode
			}
			if cmd.Flags().Changed("listen") {
				cfg.FetchProxy.Listen = listen
			}

			// Override reverse proxy config from CLI flags.
			if reverseProxy {
				cfg.ReverseProxy.Enabled = true
				cfg.ReverseProxy.Listen = reverseListen
				cfg.ReverseProxy.Upstream = reverseUpstream
			}

			cfg.ApplyDefaults()
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}

			// Set up Sentry error reporting
			sentryClient, sentryErr := plsentry.Init(cfg, cliutil.Version)
			if sentryErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: sentry init failed: %v\n", sentryErr)
			}
			if sentryClient != nil {
				defer sentryClient.Close()
			}

			// Set up audit logger
			logger, err := audit.New(
				cfg.Logging.Format,
				cfg.Logging.Output,
				cfg.Logging.File,
				cfg.Logging.IncludeAllowed,
				cfg.Logging.IncludeBlocked,
			)
			if err != nil {
				return fmt.Errorf("creating audit logger: %w", err)
			}
			defer logger.Close()

			// Set up event emission (webhooks, syslog).
			// Always create the emitter (even with 0 sinks) so hot-reload
			// can add sinks later without needing to recreate it.
			emitSinks, emitErr := BuildEmitSinks(cfg)
			if emitErr != nil {
				return fmt.Errorf("creating emit sinks: %w", emitErr)
			}

			instanceID := cfg.Emit.InstanceID
			if instanceID == "" {
				instanceID = emit.DefaultInstanceID()
			}
			emitter := emit.NewEmitter(instanceID, emitSinks...)
			defer func() { _ = emitter.Close() }()
			logger.SetEmitter(emitter)

			// Merge community rule bundles before building the scanner.
			bundleResult := rules.MergeIntoConfig(cfg, cliutil.Version)
			for _, e := range bundleResult.Errors {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
			}

			// Set up scanner, metrics, kill switch, and proxy
			sc := scanner.New(cfg)
			defer sc.Close()
			m := metrics.New()

			ks := killswitch.New(cfg)
			m.RegisterKillSwitchState(ks.Sources)
			m.RegisterInfo(cliutil.Version)

			// Always create the API handler so routes are registered at startup.
			// The handler returns 503 when no api_token is configured, and reads
			// the token from the live config on each request -- so adding a token
			// via hot-reload makes the endpoint functional without a restart.
			ksAPI := killswitch.NewAPIHandler(ks)

			var proxyOpts []proxy.Option
			hasApprover := cfg.ResponseScanning.Action == config.ActionAsk
			if hasApprover {
				approver := hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
				defer approver.Close()
				proxyOpts = append(proxyOpts, proxy.WithApprover(approver))
			}
			proxyOpts = append(proxyOpts, proxy.WithKillSwitch(ks))

			// Only register kill switch API routes on the main proxy port
			// when api_listen is NOT configured. When api_listen is set,
			// the API runs on a dedicated port and the main port returns 404.
			apiOnSeparatePort := cfg.KillSwitch.APIListen != ""
			if !apiOnSeparatePort {
				proxyOpts = append(proxyOpts, proxy.WithKillSwitchAPI(ksAPI))
			} else {
				ks.SetSeparateAPIPort(true)
			}
			p, pErr := proxy.New(cfg, logger, sc, m, proxyOpts...)
			if pErr != nil {
				return fmt.Errorf("creating proxy: %w", pErr)
			}

			// Load TLS interception CA if configured.
			if err := p.LoadCertCache(cfg); err != nil {
				if sentryClient != nil {
					sentryClient.CaptureError(err)
				}
				return err
			}

			// Context with signal handling for graceful shutdown.
			// Uses cmd.Context() as parent so tests can inject a cancellable context.
			ctx, cancel := signal.NotifyContext(
				cmd.Context(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer cancel()

			// Toggle kill switch via SIGUSR1 on Unix (no-op on Windows).
			cleanupSignal := RegisterKillSwitchSignal(ks, cmd)
			defer cleanupSignal()

			// Start config hot-reload if a config file is provided
			if configFile != "" {
				reloader := config.NewReloader(configFile)
				defer reloader.Close()

				go func() {
					if err := reloader.Start(ctx); err != nil {
						logger.LogError("CONFIG_RELOAD", configFile, "", "", "", err)
					}
				}()

				go func() {
					for newCfg := range reloader.Changes() {
						func() {
							defer func() {
								if r := recover(); r != nil {
									ReloadPanicHandler(r, sentryClient, logger, configFile)
								}
							}()
							// Check for security downgrades before applying
							oldCfg := p.CurrentConfig()
							if oldCfg != nil {
								warnings := config.ValidateReload(oldCfg, newCfg)
								for _, w := range warnings {
									cmd.PrintErrf("WARNING: config reload: %s - %s\n", w.Field, w.Message)
								}
								// Block downgrades from strict mode (security-critical).
								if oldCfg.Mode == config.ModeStrict && len(warnings) > 0 {
									logger.LogError("CONFIG_RELOAD", configFile, "", "", "",
										fmt.Errorf("rejected: security downgrade from strict mode"))
									return
								}
								// Block enabling forward proxy via reload. WriteTimeout is
								// set at server start and cannot change at runtime; tunnels
								// would be killed prematurely. Restart to enable.
								if !oldCfg.ForwardProxy.Enabled && newCfg.ForwardProxy.Enabled {
									logger.LogError("CONFIG_RELOAD", configFile, "", "", "",
										fmt.Errorf("rejected: forward proxy cannot be enabled via reload (requires restart)"))
									return
								}
								// Block enabling WebSocket proxy via reload for the same
								// reason: WriteTimeout must be 0 at server start.
								if !oldCfg.WebSocketProxy.Enabled && newCfg.WebSocketProxy.Enabled {
									logger.LogError("CONFIG_RELOAD", configFile, "", "", "",
										fmt.Errorf("rejected: WebSocket proxy cannot be enabled via reload (requires restart)"))
									return
								}
								// Block api_listen changes via reload. The API server
								// binds at startup and can't rebind at runtime.
								if oldCfg.KillSwitch.APIListen != newCfg.KillSwitch.APIListen {
									cmd.PrintErrf("WARNING: config reload: kill_switch.api_listen changed from %q to %q — requires restart, ignoring\n",
										oldCfg.KillSwitch.APIListen, newCfg.KillSwitch.APIListen)
									newCfg.KillSwitch.APIListen = oldCfg.KillSwitch.APIListen
								}
								// Block metrics_listen changes via reload. The metrics
								// server binds at startup and can't rebind at runtime.
								if oldCfg.MetricsListen != newCfg.MetricsListen {
									cmd.PrintErrf("WARNING: config reload: metrics_listen changed from %q to %q — requires restart, ignoring\n",
										oldCfg.MetricsListen, newCfg.MetricsListen)
									newCfg.MetricsListen = oldCfg.MetricsListen
								}
								// Block scan_api listener setting changes via reload. The
								// Scan API server binds at startup and cannot rebind or
								// reconfigure connection limits / deadlines at runtime.
								if oldCfg.ScanAPI.Listen != newCfg.ScanAPI.Listen ||
									oldCfg.ScanAPI.ConnectionLimit != newCfg.ScanAPI.ConnectionLimit ||
									oldCfg.ScanAPI.Timeouts.Read != newCfg.ScanAPI.Timeouts.Read ||
									oldCfg.ScanAPI.Timeouts.Write != newCfg.ScanAPI.Timeouts.Write {
									cmd.PrintErrf("WARNING: config reload: scan_api listener settings changed — requires restart, ignoring\n")
									newCfg.ScanAPI.Listen = oldCfg.ScanAPI.Listen
									newCfg.ScanAPI.ConnectionLimit = oldCfg.ScanAPI.ConnectionLimit
									newCfg.ScanAPI.Timeouts = oldCfg.ScanAPI.Timeouts
								}
								// Block reverse proxy listener/upstream changes via reload.
								// The listener binds at startup and the upstream is
								// pinned in the handler. Requires restart.
								if oldCfg.ReverseProxy.Listen != newCfg.ReverseProxy.Listen ||
									oldCfg.ReverseProxy.Enabled != newCfg.ReverseProxy.Enabled ||
									oldCfg.ReverseProxy.Upstream != newCfg.ReverseProxy.Upstream {
									cmd.PrintErrf("WARNING: config reload: reverse_proxy settings changed — requires restart, ignoring\n")
									newCfg.ReverseProxy = oldCfg.ReverseProxy
								}
								// Block agent listener changes via reload. Listener
								// sockets are bound at startup and cannot be rebound
								// at runtime. Warn and preserve old listener config.
								//
								// Respect the license gate: if EnforceLicenseGate
								// disabled agents on reload, do not re-add them via
								// listener preservation.
								agentsRevokedByLicense := oldCfg.Agents != nil && newCfg.Agents == nil
								licenseInputsChanged := oldCfg.LicenseKey != newCfg.LicenseKey || oldCfg.LicensePublicKey != newCfg.LicensePublicKey || oldCfg.LicenseFile != newCfg.LicenseFile

								if agentsRevokedByLicense {
									// License gate disabled agents on reload.
									// Shut down already-bound listener servers so
									// the agent ports stop accepting traffic.
									p.ShutdownAgentServers()
									cmd.PrintErrf("pipelock: license revoked agents, shutting down agent listeners\n")
								} else if licenseInputsChanged {
									// License inputs changed but agents were not
									// revoked. Preserve ALL old license state so a
									// reload cannot activate licensed features without
									// a restart. We must also preserve the old license
									// input fields themselves; otherwise the new values
									// get committed to the live config and a subsequent
									// unrelated reload would see no diff, silently
									// applying the staged license.
									newCfg.Agents = oldCfg.Agents
									newCfg.LicenseKey = oldCfg.LicenseKey
									newCfg.LicenseFile = oldCfg.LicenseFile
									newCfg.LicensePublicKey = oldCfg.LicensePublicKey
									cmd.PrintErrf("WARNING: config reload: license key inputs changed (license_key, license_file, or license_public_key) - requires restart for license re-verification\n")
								} else if AgentListenersChanged(oldCfg, newCfg) {
									cmd.PrintErrf("WARNING: config reload: agents[*].listeners changed — requires restart, ignoring listener changes\n")
									PreserveAgentListeners(oldCfg, newCfg)
								}
								// Carry forward runtime-derived license expiry.
								// LicenseExpiresAt is set by EnforceLicenseGate at
								// startup, not parsed from YAML. Always preserve the
								// old value until restart.
								newCfg.LicenseExpiresAt = oldCfg.LicenseExpiresAt
							}
							reloadBundleResult := rules.MergeIntoConfig(newCfg, cliutil.Version)
							for _, e := range reloadBundleResult.Errors {
								cmd.PrintErrf("WARNING: config reload: bundle %s: %s\n", e.Name, e.Reason)
							}
							newSc := scanner.New(newCfg)
							p.Reload(newCfg, newSc)
							if reloadErr := p.LoadCertCache(newCfg); reloadErr != nil {
								logger.LogError("CONFIG_RELOAD", configFile, "", "", "",
									fmt.Errorf("TLS cert cache reload failed: %w", reloadErr))
							}
							ks.Reload(newCfg)

							// Reload emit sinks: build new sinks from config,
							// swap into emitter, close old sinks.
							newSinks, sinkErr := BuildEmitSinks(newCfg)
							if sinkErr != nil {
								logger.LogError("CONFIG_RELOAD", configFile, "", "", "",
									fmt.Errorf("emit sink rebuild failed: %w", sinkErr))
							} else {
								oldSinks := emitter.ReloadSinks(newSinks)
								for _, s := range oldSinks {
									if closeErr := s.Close(); closeErr != nil {
										logger.LogError("CONFIG_RELOAD", configFile, "", "", "",
											fmt.Errorf("closing old emit sink: %w", closeErr))
									}
								}
							}

							if newCfg.ResponseScanning.Action == config.ActionAsk && !hasApprover {
								cmd.PrintErrln("WARNING: config reloaded to ask mode but HITL approver was not initialized at startup; detections will be blocked")
							}
							logger.LogConfigReload("success", fmt.Sprintf("mode=%s", newCfg.Mode), newCfg.Hash())
						}()
					}
				}()
			}

			// Warn if running outside a container (reduced isolation)
			if !IsContainerized() {
				cmd.PrintErrln("WARNING: running outside a container - consider using Docker/Podman for network isolation")
			}

			cmd.PrintErrf("Pipelock v%s starting\n", cliutil.Version)
			cmd.PrintErrf("  Mode:   %s\n", cfg.Mode)
			cmd.PrintErrf("  Listen: %s\n", cfg.FetchProxy.Listen)
			cmd.PrintErrf("  Fetch:  http://%s/fetch?url=<url>\n", cfg.FetchProxy.Listen)
			cmd.PrintErrf("  Health: http://%s/health\n", cfg.FetchProxy.Listen)
			if cfg.MetricsListen != "" {
				cmd.PrintErrf("  Stats:  http://%s/stats (separate port)\n", cfg.MetricsListen)
			} else {
				cmd.PrintErrf("  Stats:  http://%s/stats\n", cfg.FetchProxy.Listen)
			}
			if cfg.ForwardProxy.Enabled {
				cmd.PrintErrf("  Proxy:  HTTP/HTTPS forward proxy enabled (CONNECT + absolute-URI)\n")
			}
			if cfg.WebSocketProxy.Enabled {
				cmd.PrintErrf("  WS:     http://%s/ws?url=<ws-url> (WebSocket proxy enabled)\n", cfg.FetchProxy.Listen)
			}
			if cfg.Emit.Webhook.URL != "" {
				cmd.PrintErrf("  Emit:   webhook -> %s (min_severity: %s)\n", RedactEndpoint(cfg.Emit.Webhook.URL), cfg.Emit.Webhook.MinSeverity)
			}
			if cfg.Emit.Syslog.Address != "" {
				cmd.PrintErrf("  Emit:   syslog -> %s (min_severity: %s)\n", RedactEndpoint(cfg.Emit.Syslog.Address), cfg.Emit.Syslog.MinSeverity)
			}
			if cfg.KillSwitch.APIToken != "" {
				if apiOnSeparatePort {
					cmd.PrintErrf("  API:    http://%s/api/v1/killswitch (kill switch remote control, separate port)\n", cfg.KillSwitch.APIListen)
				} else {
					cmd.PrintErrf("  API:    http://%s/api/v1/killswitch (kill switch remote control)\n", cfg.FetchProxy.Listen)
				}
			}
			if configFile != "" {
				cmd.PrintErrf("  Config: %s (hot-reload enabled%s)\n", configFile, ReloadSignalHint())
			}
			if hasMCPListen {
				cmd.PrintErrf("  MCP:    http://%s -> %s\n", mcpListen, mcpUpstream)
			}
			if cfg.ReverseProxy.Enabled {
				cmd.PrintErrf("  RevPx:  http://%s -> %s (reverse proxy with body scanning)\n",
					cfg.ReverseProxy.Listen, RedactEndpoint(cfg.ReverseProxy.Upstream))
			}
			for addr, name := range p.Ports() {
				cmd.PrintErrf("  Agent:  %s -> http://%s\n", name, addr)
			}

			// Check for agent command after --
			dashIdx := cmd.ArgsLenAtDash()
			if dashIdx >= 0 && dashIdx < len(args) {
				agentCmd := args[dashIdx:]
				cmd.PrintErrf("  Agent:  %v\n", agentCmd)
				cmd.PrintErrln("\nNote: agent process launching is not yet implemented (Phase 2).")
				cmd.PrintErrln("The fetch proxy is running — configure your agent to use:")
				cmd.PrintErrf("  PIPELOCK_FETCH_URL=http://%s/fetch\n\n", cfg.FetchProxy.Listen)
			}

			// Start kill switch API on a separate port if configured.
			// Follows the same pattern as the MCP listener: bind synchronously
			// so port conflicts are caught early, serve in a goroutine, and
			// drain the error channel after the main proxy exits.
			var ksAPIErr chan error
			if apiOnSeparatePort {
				apiMux := http.NewServeMux()
				apiMux.HandleFunc("/api/v1/killswitch", ksAPI.HandleToggle)
				apiMux.HandleFunc("/api/v1/killswitch/status", ksAPI.HandleStatus)

				// Session admin API on the dedicated port. Resolves the API
				// token using the same env-var override as the kill switch.
				apiToken := cfg.KillSwitch.APIToken
				if envToken := os.Getenv(killswitch.EnvAPIToken); envToken != "" {
					apiToken = envToken
				}
				if apiToken != "" {
					sessionAPI := proxy.NewSessionAPIHandler(
						p.SessionMgrPtr(),
						p.EntropyTrackerPtr(),
						p.FragmentBufferPtr(),
						m,
						logger,
						apiToken,
					)
					apiMux.HandleFunc("/api/v1/sessions", sessionAPI.HandleList)
					apiMux.HandleFunc("/api/v1/sessions/", sessionAPI.HandleReset)
				}

				apiLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.KillSwitch.APIListen)
				if lnErr != nil {
					err := fmt.Errorf("kill switch API bind %s: %w", cfg.KillSwitch.APIListen, lnErr)
					if sentryClient != nil {
						sentryClient.CaptureError(err)
					}
					return err
				}

				apiSrv := &http.Server{
					Handler:           apiMux,
					ReadTimeout:       10 * time.Second,
					ReadHeaderTimeout: 5 * time.Second,
					WriteTimeout:      10 * time.Second,
					IdleTimeout:       120 * time.Second,
				}
				go func() {
					<-ctx.Done()
					shutdownCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
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

			// Start metrics server on a separate port if configured.
			var metricsErr chan error
			if cfg.MetricsListen != "" {
				metricsMux := http.NewServeMux()
				metricsMux.Handle("/metrics", m.PrometheusHandler())
				metricsMux.HandleFunc("/stats", m.StatsHandler())

				metricsLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.MetricsListen)
				if lnErr != nil {
					err := fmt.Errorf("metrics bind %s: %w", cfg.MetricsListen, lnErr)
					if sentryClient != nil {
						sentryClient.CaptureError(err)
					}
					return err
				}
				metricsSrv := &http.Server{
					Handler:           metricsMux,
					ReadTimeout:       10 * time.Second,
					ReadHeaderTimeout: 5 * time.Second,
					WriteTimeout:      10 * time.Second,
					IdleTimeout:       120 * time.Second,
				}
				go func() {
					<-ctx.Done()
					shutdownCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
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
				cmd.PrintErrf("pipelock: metrics listening on %s\n", cfg.MetricsListen)
			}

			// Start Scan API server on a dedicated port if configured.
			// Follows the same pattern as kill switch API and metrics server:
			// bind synchronously so port conflicts are caught early.
			var scanAPIErr chan error
			if cfg.ScanAPI.Listen != "" {
				scanAPIMux := http.NewServeMux()
				var scanPolicyCfg *policy.Config
				if cfg.MCPToolPolicy.Enabled {
					scanPolicyCfg = policy.New(cfg.MCPToolPolicy)
				}
				scanHandler := scanapi.NewHandler(cfg, sc, scanPolicyCfg, m, cliutil.Version)
				scanHandler.SetKillSwitchFn(ks.IsActive)
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

				scanAPISrv := &http.Server{
					Handler:           scanAPIMux,
					ReadTimeout:       readTimeout,
					ReadHeaderTimeout: readTimeout,
					WriteTimeout:      writeTimeout,
					IdleTimeout:       120 * time.Second, // matches main server idle timeout
				}
				go func() {
					<-ctx.Done()
					shutdownCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
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
				cmd.PrintErrf("pipelock: scan API listening on %s\n", cfg.ScanAPI.Listen)
			}

			// Start MCP HTTP listener in background if configured.
			var mcpErr chan error
			if hasMCPListen {
				// Auto-enable MCP scanning features for listener mode.
				if !cfg.MCPInputScanning.Enabled && cfg.MCPInputScanning.Action == "" {
					cmd.PrintErrln("pipelock: auto-enabling MCP input scanning for listener mode")
					cfg.MCPInputScanning.Enabled = true
					cfg.MCPInputScanning.Action = config.ActionBlock
				}
				if !cfg.MCPToolScanning.Enabled && cfg.MCPToolScanning.Action == "" {
					cmd.PrintErrln("pipelock: auto-enabling MCP tool scanning for listener mode")
					cfg.MCPToolScanning.Enabled = true
					cfg.MCPToolScanning.Action = config.ActionWarn
					cfg.MCPToolScanning.DetectDrift = true
				}
				if !cfg.MCPToolPolicy.Enabled && cfg.MCPToolPolicy.Action == "" && len(cfg.MCPToolPolicy.Rules) == 0 {
					cmd.PrintErrln("pipelock: auto-enabling MCP tool call policy for listener mode")
					cfg.MCPToolPolicy.Enabled = true
					cfg.MCPToolPolicy.Action = config.ActionWarn
					cfg.MCPToolPolicy.Rules = policy.DefaultToolPolicyRules()
				}

				inputCfg := &mcp.InputScanConfig{
					Enabled:      cfg.MCPInputScanning.Enabled,
					Action:       cfg.MCPInputScanning.Action,
					OnParseError: cfg.MCPInputScanning.OnParseError,
				}
				var toolCfg *tools.ToolScanConfig
				if cfg.MCPToolScanning.Enabled {
					toolCfg = &tools.ToolScanConfig{
						Action:      cfg.MCPToolScanning.Action,
						DetectDrift: cfg.MCPToolScanning.DetectDrift,
						ExtraPoison: rules.ConvertToolPoison(bundleResult.ToolPoison),
					}
				}
				var policyCfg *policy.Config
				if cfg.MCPToolPolicy.Enabled {
					policyCfg = policy.New(cfg.MCPToolPolicy)
				}

				var mcpApprover *hitl.Approver
				if sc.ResponseAction() == config.ActionAsk {
					mcpApprover = hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
					defer mcpApprover.Close()
				}

				// Bind MCP listener synchronously so port conflicts are caught
				// before the fetch proxy starts. Without this, a bind failure
				// would be silently swallowed until shutdown.
				mcpLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", mcpListen)
				if lnErr != nil {
					err := fmt.Errorf("MCP listener bind %s: %w", mcpListen, lnErr)
					if sentryClient != nil {
						sentryClient.CaptureError(err)
					}
					return err
				}

				// Initialize chain matcher for MCP listener if configured.
				var mcpChainMatcher *chains.Matcher
				if cfg.ToolChainDetection.Enabled {
					mcpChainMatcher = chains.New(&cfg.ToolChainDetection).WithMetrics(m)
				}

				// Build CEE deps for the MCP listener path.
				var mcpCEE *mcp.CEEDeps
				if cfg.CrossRequestDetection.Enabled {
					ceeCfg := cfg.CrossRequestDetection
					mcpCEE = &mcp.CEEDeps{Config: &ceeCfg, Metrics: m}
					if ceeCfg.EntropyBudget.Enabled {
						mcpCEE.Tracker = scanner.NewEntropyTracker(
							ceeCfg.EntropyBudget.BitsPerWindow,
							ceeCfg.EntropyBudget.WindowMinutes*60,
						)
					}
					if ceeCfg.FragmentReassembly.Enabled {
						mcpCEE.Buffer = scanner.NewFragmentBuffer(
							ceeCfg.FragmentReassembly.MaxBufferBytes,
							10000,
							ceeCfg.FragmentReassembly.WindowMinutes*60,
						)
					}
				}

				// Share the proxy's session manager with the MCP listener so both
				// use the same store and the sessions gauge is not double-counted.
				// p.SessionStore() reads from the atomic pointer, so it returns the
				// live store even after hot-reloads.
				mcpStore := p.SessionStore() // nil when session profiling is disabled

				// Pass a function that reads the adaptive config from the live
				// proxy config on each request. This ensures the long-lived MCP
				// listener picks up hot-reload changes instead of being frozen
				// to the startup snapshot.
				mcpAdaptiveFn := mcp.AdaptiveConfigFunc(func() *config.AdaptiveEnforcement {
					c := p.CurrentConfig()
					if c != nil && c.AdaptiveEnforcement.Enabled {
						return &c.AdaptiveEnforcement
					}
					return nil
				})

				mcpErr = make(chan error, 1)
				go func() {
					mcpErr <- mcp.RunHTTPListenerProxy(ctx, mcpLn, mcpUpstream, cmd.ErrOrStderr(), sc, mcpApprover, inputCfg, toolCfg, policyCfg, ks, mcpChainMatcher, logger, mcpCEE, mcpStore, mcpAdaptiveFn, m, buildRedirectRT(cfg))
				}()
			}

			// Start reverse proxy on a dedicated port if configured.
			var reverseProxyErr chan error
			if cfg.ReverseProxy.Enabled {
				rpUpstream, rpErr := url.Parse(cfg.ReverseProxy.Upstream)
				if rpErr != nil {
					return fmt.Errorf("reverse proxy upstream: %w", rpErr)
				}

				rpHandler := proxy.NewReverseProxy(
					rpUpstream, p.ConfigPtr(), p.ScannerPtr(),
					logger, m, ks,
				)

				rpLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ReverseProxy.Listen)
				if lnErr != nil {
					err := fmt.Errorf("reverse proxy bind %s: %w", cfg.ReverseProxy.Listen, lnErr)
					if sentryClient != nil {
						sentryClient.CaptureError(err)
					}
					return err
				}

				rpSrv := &http.Server{
					Handler:           rpHandler,
					ReadTimeout:       10 * time.Second,
					ReadHeaderTimeout: 5 * time.Second,
					WriteTimeout:      30 * time.Second,
					IdleTimeout:       120 * time.Second,
				}
				go func() {
					<-ctx.Done()
					shutdownCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
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
				cmd.PrintErrf("pipelock: reverse proxy listening on %s -> %s\n",
					cfg.ReverseProxy.Listen, RedactEndpoint(cfg.ReverseProxy.Upstream))
			}

			// Bind per-agent listener servers. Each listener injects the
			// agent profile via context so identity is port-based, not
			// header-based (spoof-proof). Ports() returns addr->profile
			// mapping from the edition (empty in OSS mode).
			agentPorts := p.Ports()
			agentListenerCount := len(agentPorts)
			var agentListenerErrs chan error
			if agentListenerCount > 0 {
				handler := p.Handler()
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
						if sentryClient != nil {
							sentryClient.CaptureError(err)
						}
						return err
					}
					srv := &http.Server{
						Handler:           AgentHandler(name, handler),
						ReadTimeout:       10 * time.Second,
						ReadHeaderTimeout: 5 * time.Second,
						WriteTimeout:      agentWriteTimeout,
						IdleTimeout:       120 * time.Second, // matches main server idle timeout
					}
					// Register with proxy so its shutdown goroutine
					// gracefully stops agent servers alongside the main server.
					p.RegisterAgentServer(srv)
					errCh := agentListenerErrs
					go func(s *http.Server, listener net.Listener) {
						srvErr := s.Serve(listener)
						if errors.Is(srvErr, http.ErrServerClosed) {
							srvErr = nil
						}
						errCh <- srvErr
					}(srv, ln)
					cmd.PrintErrf("pipelock: agent %q listening on %s\n", name, addr)
				}
			}

			// License expiry watchdog: shut down agent listeners when the
			// enterprise license expires at runtime. Only active when agent
			// listeners exist and the license has a non-zero expiry.
			if agentListenerCount > 0 && cfg.LicenseExpiresAt > 0 {
				go func() {
					remaining := time.Until(time.Unix(cfg.LicenseExpiresAt, 0))
					if remaining <= 0 {
						// Already expired; shut down immediately.
						cmd.PrintErrf("pipelock: license expired, shutting down agent listeners\n")
						p.ShutdownAgentServers()
						return
					}
					timer := time.NewTimer(remaining)
					defer timer.Stop()
					select {
					case <-timer.C:
						cmd.PrintErrf("pipelock: license expired, shutting down agent listeners\n")
						p.ShutdownAgentServers()
					case <-ctx.Done():
						// Normal shutdown; agent servers handled by proxy.
					}
				}()
			}

			// Start the fetch proxy (blocks until context cancelled or error).
			if err := p.Start(ctx); err != nil {
				if sentryClient != nil {
					sentryClient.CaptureError(err)
				}
				return fmt.Errorf("proxy error: %w", err)
			}

			// If agent listeners were running, drain their error channels.
			for range agentListenerCount {
				if aErr := <-agentListenerErrs; aErr != nil {
					cmd.PrintErrf("pipelock: agent listener error: %v\n", aErr)
				}
			}

			// If MCP listener was running, check for errors.
			if mcpErr != nil {
				if mErr := <-mcpErr; mErr != nil {
					cmd.PrintErrf("pipelock: MCP listener error: %v\n", mErr)
				}
			}

			// If Scan API server was running, check for errors.
			if scanAPIErr != nil {
				if sErr := <-scanAPIErr; sErr != nil {
					cmd.PrintErrf("pipelock: scan API listener error: %v\n", sErr)
				}
			}

			// If metrics was running on a separate port, check for errors.
			if metricsErr != nil {
				if mErr := <-metricsErr; mErr != nil {
					cmd.PrintErrf("pipelock: metrics listener error: %v\n", mErr)
				}
			}

			// If kill switch API was running on a separate port, check for errors.
			if ksAPIErr != nil {
				if aErr := <-ksAPIErr; aErr != nil {
					cmd.PrintErrf("pipelock: kill switch API listener error: %v\n", aErr)
				}
			}

			// If reverse proxy was running, check for errors.
			if reverseProxyErr != nil {
				if rpErr := <-reverseProxyErr; rpErr != nil {
					cmd.PrintErrf("pipelock: reverse proxy listener error: %v\n", rpErr)
				}
			}

			logger.LogShutdown("signal received")
			cmd.PrintErrln("\nPipelock stopped.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().StringVarP(&mode, "mode", "m", "balanced", "operating mode: strict, balanced, audit")
	cmd.Flags().StringVarP(&listen, "listen", "l", "", "listen address (default 127.0.0.1:8888)")
	cmd.Flags().StringVar(&mcpListen, "mcp-listen", "", "MCP HTTP listener address (e.g. 0.0.0.0:8889)")
	cmd.Flags().StringVar(&mcpUpstream, "mcp-upstream", "", "upstream MCP server URL for HTTP listener")
	cmd.Flags().BoolVar(&reverseProxy, "reverse-proxy", false, "enable reverse proxy mode with body scanning")
	cmd.Flags().StringVar(&reverseUpstream, "reverse-upstream", "", "upstream URL for reverse proxy (e.g. http://localhost:7899)")
	cmd.Flags().StringVar(&reverseListen, "reverse-listen", ":8890", "listen address for reverse proxy")

	return cmd
}

// BuildEmitSinks creates emit sinks from the current config.
// Used at startup and during hot-reload.
func BuildEmitSinks(cfg *config.Config) ([]emit.Sink, error) {
	var sinks []emit.Sink

	if cfg.Emit.Webhook.URL != "" {
		var opts []emit.WebhookOption
		opts = append(opts, emit.WithMinSeverity(emit.ParseSeverity(cfg.Emit.Webhook.MinSeverity)))
		if cfg.Emit.Webhook.AuthToken != "" {
			opts = append(opts, emit.WithBearerToken(cfg.Emit.Webhook.AuthToken))
		}
		if cfg.Emit.Webhook.QueueSize > 0 {
			opts = append(opts, emit.WithQueueSize(cfg.Emit.Webhook.QueueSize))
		}
		if cfg.Emit.Webhook.TimeoutSecs > 0 {
			opts = append(opts, emit.WithWebhookTimeout(time.Duration(cfg.Emit.Webhook.TimeoutSecs)*time.Second))
		}
		sinks = append(sinks, emit.NewWebhookSink(cfg.Emit.Webhook.URL, opts...))
	}

	if cfg.Emit.Syslog.Address != "" {
		syslogSink, err := emit.NewSyslogSinkFromConfig(
			cfg.Emit.Syslog.Address,
			cfg.Emit.Syslog.Facility,
			cfg.Emit.Syslog.Tag,
			cfg.Emit.Syslog.MinSeverity,
		)
		if err != nil {
			// Close already-created sinks to prevent goroutine leaks.
			for _, s := range sinks {
				_ = s.Close()
			}
			return nil, fmt.Errorf("creating syslog sink: %w", err)
		}
		sinks = append(sinks, syslogSink)
	}

	if cfg.Emit.OTLP.Endpoint != "" {
		otlpSink, otlpErr := emit.NewOTLPSink(
			cfg.Emit.OTLP.Endpoint,
			cliutil.Version,
			emit.ParseSeverity(cfg.Emit.OTLP.MinSeverity),
			cfg.Emit.OTLP.Headers,
			time.Duration(cfg.Emit.OTLP.TimeoutSeconds)*time.Second,
			cfg.Emit.OTLP.QueueSize,
			cfg.Emit.OTLP.Gzip,
		)
		if otlpErr != nil {
			for _, s := range sinks {
				_ = s.Close()
			}
			return nil, fmt.Errorf("creating otlp sink: %w", otlpErr)
		}
		sinks = append(sinks, otlpSink)
	}

	return sinks, nil
}

// RedactEndpoint strips userinfo, query, and fragment from an endpoint URL
// to prevent leaking tokens/secrets in startup logs.
func RedactEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// AgentHandler wraps a proxy handler with a context-injected agent profile.
// Requests through this handler are identified by the bound port, not by
// the X-Pipelock-Agent header, making them spoof-proof.
func AgentHandler(profile string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := edition.WithAgentOverride(r.Context(), profile)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AgentListenersChanged returns true if any agent's listener addresses differ
// between old and new config. Listener sockets bind at startup and cannot be
// rebound at runtime, so changes require a restart.
func AgentListenersChanged(oldCfg, newCfg *config.Config) bool {
	if len(oldCfg.Agents) != len(newCfg.Agents) {
		// Agent count changed; check if any had listeners.
		for _, p := range oldCfg.Agents {
			if len(p.Listeners) > 0 {
				return true
			}
		}
		for _, p := range newCfg.Agents {
			if len(p.Listeners) > 0 {
				return true
			}
		}
		return false
	}
	for name, oldProfile := range oldCfg.Agents {
		newProfile, ok := newCfg.Agents[name]
		if !ok {
			if len(oldProfile.Listeners) > 0 {
				return true
			}
			continue
		}
		if !slices.Equal(oldProfile.Listeners, newProfile.Listeners) {
			return true
		}
	}
	// Check for new agents with listeners.
	for name, newProfile := range newCfg.Agents {
		if _, ok := oldCfg.Agents[name]; !ok && len(newProfile.Listeners) > 0 {
			return true
		}
	}
	return false
}

// ReloadPanicHandler captures panics during config reload, reports them to
// Sentry, and logs the error. Extracted from the reload goroutine for
// testability.
func ReloadPanicHandler(r any, sentryClient *plsentry.Client, logger *audit.Logger, configFile string) {
	if r == nil {
		return
	}
	reloadErr := fmt.Errorf("scanner construction panic during config reload: %v", r)
	if sentryClient != nil {
		sentryClient.CaptureError(reloadErr)
	}
	logger.LogError("CONFIG_RELOAD", configFile, "", "", "", reloadErr)
}

// PreserveAgentListeners keeps the new config's agent listener state
// consistent with the actually-bound sockets from startup. Three cases:
//
//  1. Agent in both configs: copy old listeners into new entry.
//  2. Listener-bearing agent removed: re-add old entry so the bound
//     socket keeps its policy (prevents fallback to default profile).
//  3. Listener-bearing agent added: strip listeners (can't bind without
//     restart).
func PreserveAgentListeners(oldCfg, newCfg *config.Config) {
	if newCfg.Agents == nil {
		newCfg.Agents = make(map[string]config.AgentProfile)
	}

	// Case 1 + 2: iterate old agents.
	for name, oldProfile := range oldCfg.Agents {
		if newProfile, ok := newCfg.Agents[name]; ok {
			// Case 1: agent in both configs. Preserve old listeners,
			// keep other new config fields.
			newProfile.Listeners = oldProfile.Listeners
			newCfg.Agents[name] = newProfile
		} else if len(oldProfile.Listeners) > 0 {
			// Case 2: listener-bearing agent removed. Socket is still
			// bound, so re-add the full old entry to prevent policy
			// downgrade on the spoof-proof port.
			newCfg.Agents[name] = oldProfile
		}
	}

	// Case 3: new agents with listeners that weren't in old config.
	// Can't bind sockets without restart, so strip the listeners.
	for name, newProfile := range newCfg.Agents {
		if _, ok := oldCfg.Agents[name]; !ok && len(newProfile.Listeners) > 0 {
			newProfile.Listeners = nil
			newCfg.Agents[name] = newProfile
		}
	}
}

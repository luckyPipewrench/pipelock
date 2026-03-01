package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func runCmd() *cobra.Command {
	var configFile string
	var mode string
	var listen string
	var mcpListen string
	var mcpUpstream string

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
file changes and SIGHUP signals trigger a hot-reload of config and scanner.

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
				if uErr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return fmt.Errorf("invalid --mcp-upstream %q: must be http:// or https:// with a host", mcpUpstream)
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

			cfg.ApplyDefaults()
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid config: %w", err)
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
			emitSinks, emitErr := buildEmitSinks(cfg)
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

			// Set up scanner, metrics, kill switch, and proxy
			sc := scanner.New(cfg)
			defer sc.Close()
			m := metrics.New()

			ks := killswitch.New(cfg)

			// Always create the API handler so routes are registered at startup.
			// The handler returns 503 when no api_token is configured, and reads
			// the token from the live config on each request — so adding a token
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
			p := proxy.New(cfg, logger, sc, m, proxyOpts...)

			// Context with signal handling for graceful shutdown.
			// Uses cmd.Context() as parent so tests can inject a cancellable context.
			ctx, cancel := signal.NotifyContext(
				cmd.Context(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer cancel()

			// SIGUSR1 toggles the kill switch (separate from SIGINT/SIGTERM).
			sigusr1Ch := make(chan os.Signal, 1)
			signal.Notify(sigusr1Ch, syscall.SIGUSR1)
			defer signal.Stop(sigusr1Ch)
			defer close(sigusr1Ch)
			go func() {
				for sig := range sigusr1Ch {
					if sig == nil {
						return
					}
					active := ks.ToggleSignal()
					if active {
						cmd.PrintErrln("pipelock: kill switch ACTIVATED via SIGUSR1")
					} else {
						cmd.PrintErrln("pipelock: kill switch DEACTIVATED via SIGUSR1")
					}
				}
			}()

			// Start config hot-reload if a config file is provided
			if configFile != "" {
				reloader := config.NewReloader(configFile)
				defer reloader.Close()

				go func() {
					if err := reloader.Start(ctx); err != nil {
						logger.LogError("CONFIG_RELOAD", configFile, "", "", err)
					}
				}()

				go func() {
					for newCfg := range reloader.Changes() {
						func() {
							defer func() {
								if r := recover(); r != nil {
									logger.LogError("CONFIG_RELOAD", configFile, "", "",
										fmt.Errorf("scanner construction panic: %v", r))
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
									logger.LogError("CONFIG_RELOAD", configFile, "", "",
										fmt.Errorf("rejected: security downgrade from strict mode"))
									return
								}
								// Block enabling forward proxy via reload. WriteTimeout is
								// set at server start and cannot change at runtime; tunnels
								// would be killed prematurely. Restart to enable.
								if !oldCfg.ForwardProxy.Enabled && newCfg.ForwardProxy.Enabled {
									logger.LogError("CONFIG_RELOAD", configFile, "", "",
										fmt.Errorf("rejected: forward proxy cannot be enabled via reload (requires restart)"))
									return
								}
								// Block enabling WebSocket proxy via reload for the same
								// reason: WriteTimeout must be 0 at server start.
								if !oldCfg.WebSocketProxy.Enabled && newCfg.WebSocketProxy.Enabled {
									logger.LogError("CONFIG_RELOAD", configFile, "", "",
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
							}
							newSc := scanner.New(newCfg)
							p.Reload(newCfg, newSc)
							ks.Reload(newCfg)

							// Reload emit sinks: build new sinks from config,
							// swap into emitter, close old sinks.
							newSinks, sinkErr := buildEmitSinks(newCfg)
							if sinkErr != nil {
								logger.LogError("CONFIG_RELOAD", configFile, "", "",
									fmt.Errorf("emit sink rebuild failed: %w", sinkErr))
							} else {
								oldSinks := emitter.ReloadSinks(newSinks)
								for _, s := range oldSinks {
									if closeErr := s.Close(); closeErr != nil {
										logger.LogError("CONFIG_RELOAD", configFile, "", "",
											fmt.Errorf("closing old emit sink: %w", closeErr))
									}
								}
							}

							if newCfg.ResponseScanning.Action == config.ActionAsk && !hasApprover {
								cmd.PrintErrln("WARNING: config reloaded to ask mode but HITL approver was not initialized at startup; detections will be blocked")
							}
							logger.LogConfigReload("success", fmt.Sprintf("mode=%s", newCfg.Mode))
						}()
					}
				}()
			}

			// Warn if running outside a container (reduced isolation)
			if !isContainerized() {
				cmd.PrintErrln("WARNING: running outside a container - consider using Docker/Podman for network isolation")
			}

			cmd.PrintErrf("Pipelock v%s starting\n", Version)
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
				cmd.PrintErrf("  Emit:   webhook -> %s (min_severity: %s)\n", redactEndpoint(cfg.Emit.Webhook.URL), cfg.Emit.Webhook.MinSeverity)
			}
			if cfg.Emit.Syslog.Address != "" {
				cmd.PrintErrf("  Emit:   syslog -> %s (min_severity: %s)\n", redactEndpoint(cfg.Emit.Syslog.Address), cfg.Emit.Syslog.MinSeverity)
			}
			if cfg.KillSwitch.APIToken != "" {
				if apiOnSeparatePort {
					cmd.PrintErrf("  API:    http://%s/api/v1/killswitch (kill switch remote control, separate port)\n", cfg.KillSwitch.APIListen)
				} else {
					cmd.PrintErrf("  API:    http://%s/api/v1/killswitch (kill switch remote control)\n", cfg.FetchProxy.Listen)
				}
			}
			if configFile != "" {
				cmd.PrintErrf("  Config: %s (hot-reload enabled, SIGHUP to reload)\n", configFile)
			}
			if hasMCPListen {
				cmd.PrintErrf("  MCP:    http://%s -> %s\n", mcpListen, mcpUpstream)
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
				apiMux.HandleFunc("/dashboard", ksAPI.HandleDashboard)

				apiLn, lnErr := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.KillSwitch.APIListen)
				if lnErr != nil {
					return fmt.Errorf("kill switch API bind %s: %w", cfg.KillSwitch.APIListen, lnErr)
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
					return fmt.Errorf("metrics bind %s: %w", cfg.MetricsListen, lnErr)
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
					return fmt.Errorf("MCP listener bind %s: %w", mcpListen, lnErr)
				}

				// Initialize chain matcher for MCP listener if configured.
				var mcpChainMatcher *chains.Matcher
				if cfg.ToolChainDetection.Enabled {
					mcpChainMatcher = chains.New(&cfg.ToolChainDetection).WithMetrics(m)
				}

				mcpErr = make(chan error, 1)
				go func() {
					mcpErr <- mcp.RunHTTPListenerProxy(ctx, mcpLn, mcpUpstream, cmd.ErrOrStderr(), sc, mcpApprover, inputCfg, toolCfg, policyCfg, ks, mcpChainMatcher)
				}()
			}

			// Start the fetch proxy (blocks until context cancelled or error).
			if err := p.Start(ctx); err != nil {
				return fmt.Errorf("proxy error: %w", err)
			}

			// If MCP listener was running, check for errors.
			if mcpErr != nil {
				if mErr := <-mcpErr; mErr != nil {
					cmd.PrintErrf("pipelock: MCP listener error: %v\n", mErr)
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

	return cmd
}

// buildEmitSinks creates emit sinks from the current config.
// Used at startup and during hot-reload.
func buildEmitSinks(cfg *config.Config) ([]emit.Sink, error) {
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

	return sinks, nil
}

// redactEndpoint strips userinfo, query, and fragment from an endpoint URL
// to prevent leaking tokens/secrets in startup logs.
func redactEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

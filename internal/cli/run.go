package cli

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
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

			// Set up scanner, metrics, kill switch, and proxy
			sc := scanner.New(cfg)
			defer sc.Close()
			m := metrics.New()

			ks := killswitch.New(cfg)

			var proxyOpts []proxy.Option
			hasApprover := cfg.ResponseScanning.Action == config.ActionAsk
			if hasApprover {
				approver := hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
				defer approver.Close()
				proxyOpts = append(proxyOpts, proxy.WithApprover(approver))
			}
			proxyOpts = append(proxyOpts, proxy.WithKillSwitch(ks))
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
			go func() {
				for range sigusr1Ch {
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
							}
							newSc := scanner.New(newCfg)
							p.Reload(newCfg, newSc)
							ks.Reload(newCfg)
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
			cmd.PrintErrf("  Stats:  http://%s/stats\n", cfg.FetchProxy.Listen)
			if cfg.ForwardProxy.Enabled {
				cmd.PrintErrf("  Proxy:  HTTP/HTTPS forward proxy enabled (CONNECT + absolute-URI)\n")
			}
			if cfg.WebSocketProxy.Enabled {
				cmd.PrintErrf("  WS:     http://%s/ws?url=<ws-url> (WebSocket proxy enabled)\n", cfg.FetchProxy.Listen)
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
					cfg.MCPToolPolicy.Rules = mcp.DefaultToolPolicyRules()
				}

				inputCfg := &mcp.InputScanConfig{
					Enabled:      cfg.MCPInputScanning.Enabled,
					Action:       cfg.MCPInputScanning.Action,
					OnParseError: cfg.MCPInputScanning.OnParseError,
				}
				var toolCfg *mcp.ToolScanConfig
				if cfg.MCPToolScanning.Enabled {
					toolCfg = &mcp.ToolScanConfig{
						Action:      cfg.MCPToolScanning.Action,
						DetectDrift: cfg.MCPToolScanning.DetectDrift,
					}
				}
				var policyCfg *mcp.PolicyConfig
				if cfg.MCPToolPolicy.Enabled {
					policyCfg = mcp.NewPolicyConfig(cfg.MCPToolPolicy)
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

				mcpErr = make(chan error, 1)
				go func() {
					mcpErr <- mcp.RunHTTPListenerProxy(ctx, mcpLn, mcpUpstream, cmd.ErrOrStderr(), sc, mcpApprover, inputCfg, toolCfg, policyCfg, ks)
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

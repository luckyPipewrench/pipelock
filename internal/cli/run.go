package cli

import (
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func runCmd() *cobra.Command {
	var configFile string
	var mode string
	var listen string

	cmd := &cobra.Command{
		Use:   "run [flags]",
		Short: "Start the Pipelock fetch proxy",
		Long: `Start the fetch proxy server that scans and fetches URLs on behalf of agents.

The proxy runs until interrupted (SIGINT/SIGTERM). When started with --config,
file changes and SIGHUP signals trigger a hot-reload of config and scanner.

Examples:
  pipelock run                                       # standalone proxy
  pipelock run --config pipelock.yaml                # with config file (hot-reload)
  pipelock run --mode strict --listen 0.0.0.0:9999   # override mode and listen address`,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // args used via ArgsLenAtDash
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

			// Set up scanner, metrics, and proxy
			sc := scanner.New(cfg)
			defer sc.Close()
			m := metrics.New()

			var proxyOpts []proxy.Option
			hasApprover := cfg.ResponseScanning.Action == config.ActionAsk
			if hasApprover {
				approver := hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
				defer approver.Close()
				proxyOpts = append(proxyOpts, proxy.WithApprover(approver))
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
							}
							newSc := scanner.New(newCfg)
							p.Reload(newCfg, newSc)
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
			if configFile != "" {
				cmd.PrintErrf("  Config: %s (hot-reload enabled, SIGHUP to reload)\n", configFile)
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

			// Start the proxy (blocks until context cancelled or error)
			if err := p.Start(ctx); err != nil {
				return fmt.Errorf("proxy error: %w", err)
			}

			logger.LogShutdown("signal received")
			cmd.PrintErrln("\nPipelock stopped.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().StringVarP(&mode, "mode", "m", "balanced", "operating mode: strict, balanced, audit")
	cmd.Flags().StringVarP(&listen, "listen", "l", "", "listen address (default 127.0.0.1:8888)")

	return cmd
}

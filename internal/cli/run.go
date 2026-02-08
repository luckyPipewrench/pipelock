package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func runCmd() *cobra.Command {
	var configFile string
	var mode string
	var listen string

	cmd := &cobra.Command{
		Use:   "run [flags] [-- <command> [args...]]",
		Short: "Start the Pipelock fetch proxy",
		Long: `Start the fetch proxy server that scans and fetches URLs on behalf of agents.

In standalone mode (no command after --), the proxy runs until interrupted.
When a command is provided after --, the proxy starts, then execs the command
with PIPELOCK_FETCH_URL set in the environment.

Examples:
  pipelock run                                       # standalone proxy
  pipelock run --config pipelock.yaml                # with config file
  pipelock run --mode strict -- python my_agent.py   # with agent command`,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			p := proxy.New(cfg, logger, sc, m)

			// Context with signal handling for graceful shutdown
			ctx, cancel := signal.NotifyContext(
				context.Background(),
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
							newSc := scanner.New(newCfg)
							p.Reload(newCfg, newSc)
							logger.LogConfigReload("success", fmt.Sprintf("mode=%s", newCfg.Mode))
						}()
					}
				}()
			}

			fmt.Fprintf(os.Stderr, "Pipelock v%s starting\n", Version)
			fmt.Fprintf(os.Stderr, "  Mode:   %s\n", cfg.Mode)
			fmt.Fprintf(os.Stderr, "  Listen: %s\n", cfg.FetchProxy.Listen)
			fmt.Fprintf(os.Stderr, "  Fetch:  http://%s/fetch?url=<url>\n", cfg.FetchProxy.Listen)
			fmt.Fprintf(os.Stderr, "  Health: http://%s/health\n", cfg.FetchProxy.Listen)
			fmt.Fprintf(os.Stderr, "  Stats:  http://%s/stats\n", cfg.FetchProxy.Listen)
			if configFile != "" {
				fmt.Fprintf(os.Stderr, "  Config: %s (hot-reload enabled, SIGHUP to reload)\n", configFile)
			}

			// Check for agent command after --
			dashIdx := cmd.ArgsLenAtDash()
			if dashIdx >= 0 && dashIdx < len(args) {
				agentCmd := args[dashIdx:]
				fmt.Fprintf(os.Stderr, "  Agent:  %v\n", agentCmd)
				fmt.Fprintf(os.Stderr, "\nNote: agent process launching is not yet implemented (Phase 2).\n")
				fmt.Fprintf(os.Stderr, "The fetch proxy is running — configure your agent to use:\n")
				fmt.Fprintf(os.Stderr, "  PIPELOCK_FETCH_URL=http://%s/fetch\n\n", cfg.FetchProxy.Listen)
			}

			// Start the proxy (blocks until context cancelled or error)
			if err := p.Start(ctx); err != nil {
				return fmt.Errorf("proxy error: %w", err)
			}

			logger.LogShutdown("signal received")
			fmt.Fprintln(os.Stderr, "\nPipelock stopped.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	cmd.Flags().StringVarP(&mode, "mode", "m", "balanced", "operating mode: strict, balanced, audit")
	cmd.Flags().StringVarP(&listen, "listen", "l", "", "listen address (default 127.0.0.1:8888)")

	return cmd
}

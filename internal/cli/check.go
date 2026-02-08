package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ErrURLBlocked is returned when pipelock check --url detects a blocked URL.
var ErrURLBlocked = errors.New("url blocked")

func checkCmd() *cobra.Command {
	var configFile string
	var scanURL string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate config or scan a URL",
		Long: `Validate a Pipelock config file and optionally scan a URL to test scanner behavior.

Examples:
  pipelock check --config pipelock.yaml
  pipelock check --config pipelock.yaml --url https://example.com
  pipelock check --url https://pastebin.com/raw/abc123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load and validate config
			var cfg *config.Config
			if configFile != "" {
				var err error
				cfg, err = config.Load(configFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Config validation FAILED: %v\n", err)
					return err
				}
				fmt.Println("Config validation: OK")
				fmt.Printf("  Mode:           %s\n", cfg.Mode)
				fmt.Printf("  Listen:         %s\n", cfg.FetchProxy.Listen)
				fmt.Printf("  API allowlist:  %d domains\n", len(cfg.APIAllowlist))
				fmt.Printf("  Blocklist:      %d patterns\n", len(cfg.FetchProxy.Monitoring.Blocklist))
				fmt.Printf("  DLP patterns:   %d rules\n", len(cfg.DLP.Patterns))
				fmt.Printf("  Entropy thresh: %.1f bits\n", cfg.FetchProxy.Monitoring.EntropyThreshold)
				fmt.Printf("  Max URL length: %d chars\n", cfg.FetchProxy.Monitoring.MaxURLLength)
			} else {
				cfg = config.Defaults()
				fmt.Println("Using default config (no --config specified)")
			}

			// Optionally scan a URL
			if scanURL != "" {
				fmt.Printf("\nScanning URL: %s\n", scanURL)
				sc := scanner.New(cfg)
				result := sc.Scan(scanURL)
				if result.Allowed {
					fmt.Println("  Result:  ALLOWED")
				} else {
					fmt.Println("  Result:  BLOCKED")
					fmt.Printf("  Scanner: %s\n", result.Scanner)
					fmt.Printf("  Reason:  %s\n", result.Reason)
				}
				fmt.Printf("  Score:   %.2f\n", result.Score)

				if !result.Allowed {
					return ErrURLBlocked
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path to validate")
	cmd.Flags().StringVar(&scanURL, "url", "", "URL to scan through the configured scanners")

	return cmd
}

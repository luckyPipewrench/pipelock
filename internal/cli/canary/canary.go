// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package canary

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	formatYAML = "yaml"
	formatJSON = "json"
)

// Cmd returns the "canary" subcommand.
func Cmd() *cobra.Command {
	var format string
	var name string
	var value string
	var envVar string
	var literal bool

	cmd := &cobra.Command{
		Use:   "canary",
		Short: "Print a canary_tokens config snippet",
		Long: `Print a canary_tokens configuration snippet that can be pasted into pipelock.yaml.

By default, emits a placeholder that references the env var. Use --literal
to emit the actual token value (warning: appears in stdout/logs).

Examples:
  pipelock canary
  pipelock canary --literal
  pipelock canary --format json
  pipelock canary --name db_canary --value "canary-db-credential-value" --env-var DB_CANARY`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != formatYAML && format != formatJSON {
				return fmt.Errorf("invalid format %q: must be yaml or json", format)
			}

			// Default: emit env var reference as placeholder.
			// --literal emits the actual value (with stderr warning).
			displayValue := "${" + envVar + "}"
			if literal {
				displayValue = value
				_, _ = fmt.Fprintln(os.Stderr, "warning: --literal prints the canary token value to stdout; avoid capturing in shared logs")
			}

			payload := config.CanaryTokens{
				Enabled: true,
				Tokens: []config.CanaryToken{
					{
						Name:   name,
						Value:  displayValue,
						EnvVar: envVar,
					},
				},
			}

			if format == formatJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]config.CanaryTokens{"canary_tokens": payload})
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "canary_tokens:\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  enabled: true\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  tokens:\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    - name: %q\n", name)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      value: %q\n", displayValue)
			if envVar != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      env_var: %q\n", envVar)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", formatYAML, "output format: yaml or json")
	cmd.Flags().StringVar(&name, "name", "aws_canary", "canary token name")
	cmd.Flags().StringVar(&value, "value", defaultCanaryValue(), "canary token value (used with --literal)")
	cmd.Flags().StringVar(&envVar, "env-var", "AWS_CANARY_KEY", "env var name for the canary token")
	cmd.Flags().BoolVar(&literal, "literal", false, "emit actual token value instead of env var placeholder")
	return cmd
}

func defaultCanaryValue() string {
	return "AKIA" + "IOSFODNN7" + "CANARY1"
}

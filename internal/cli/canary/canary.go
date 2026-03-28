// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package canary

import (
	"encoding/json"
	"fmt"

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

	cmd := &cobra.Command{
		Use:   "canary",
		Short: "Print a canary_tokens config snippet",
		Long: `Print a canary_tokens configuration snippet that can be pasted into pipelock.yaml.

Examples:
  pipelock canary
  pipelock canary --format json
  pipelock canary --name db_canary --value "canary-db-credential-value"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != formatYAML && format != formatJSON {
				return fmt.Errorf("invalid format %q: must be yaml or json", format)
			}

			payload := config.CanaryTokens{
				Enabled: true,
				Tokens: []config.CanaryToken{
					{
						Name:   name,
						Value:  value,
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
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      value: %q\n", value)
			if envVar != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      env_var: %q\n", envVar)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", formatYAML, "output format: yaml or json")
	cmd.Flags().StringVar(&name, "name", "aws_canary", "canary token name")
	cmd.Flags().StringVar(&value, "value", defaultCanaryValue(), "canary token value")
	cmd.Flags().StringVar(&envVar, "env-var", "AWS_CANARY_KEY", "optional env var name for the canary token")
	return cmd
}

func defaultCanaryValue() string {
	return "AKIA" + "IOSFODNN7" + "CANARY1"
}

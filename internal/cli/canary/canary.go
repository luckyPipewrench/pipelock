// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package canary

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const (
	formatYAML = "yaml"
	formatJSON = "json"
)

// JSON output uses the config loader's field names without changing shared schema types.
type jsonCanaryTokens struct {
	Enabled bool              `json:"enabled"`
	Tokens  []jsonCanaryToken `json:"tokens"`
}

type jsonCanaryToken struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	EnvVar string `json:"env_var,omitempty"`
}

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

			if format == formatJSON {
				payload := jsonCanaryTokens{
					Enabled: true,
					Tokens:  []jsonCanaryToken{{Name: name, Value: displayValue, EnvVar: envVar}},
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]jsonCanaryTokens{"canary_tokens": payload})
			}

			w := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(w, "canary_tokens:\n  enabled: true\n  tokens:\n    - name: %q\n      value: %q\n", name, displayValue); err != nil {
				return err
			}
			if envVar != "" {
				if _, err := fmt.Fprintf(w, "      env_var: %q\n", envVar); err != nil {
					return err
				}
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
	var b strings.Builder
	b.WriteString("AKIA")
	for range 16 {
		b.WriteByte('A')
	}
	return b.String()
}

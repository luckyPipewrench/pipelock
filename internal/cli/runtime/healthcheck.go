// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/proxyhealth"
)

// HealthcheckCmd returns the healthcheck cobra command.
func HealthcheckCmd() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Check if the proxy is healthy (for Docker HEALTHCHECK)",
		Long: `Sends a GET request to the proxy's /health endpoint and exits
with code 0 if healthy, 1 otherwise. Designed for use as a Docker HEALTHCHECK command.

Examples:
  pipelock healthcheck
  pipelock healthcheck --addr 0.0.0.0:8888`,
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			resp, err := proxyhealth.Get(ctx, http.DefaultClient, "http://"+addr)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unhealthy: status %d", resp.StatusCode)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8888", "proxy address to check")

	return cmd
}

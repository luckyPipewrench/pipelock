package cli

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

func healthcheckCmd() *cobra.Command {
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
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/health", addr), nil)
			if err != nil {
				return fmt.Errorf("health check failed: %w", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("health check failed: %w", err)
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

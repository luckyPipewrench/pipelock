// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func quickstartCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "quickstart",
		Short:        "Print a concrete getting-started walkthrough",
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, _ []string) {
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintln(w, "Pipelock Quickstart")
			_, _ = fmt.Fprintln(w, "===================")
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "1. Install the running binary where your runtime can find it:")
			_, _ = fmt.Fprintln(w, "   sudo pipelock install /usr/local/bin/pipelock")
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "2. Start the local proxy with a shipped balanced config:")
			_, _ = fmt.Fprintln(w, "   pipelock run --config configs/balanced.yaml")
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "3. Route HTTPS-aware tools through the proxy:")
			_, _ = fmt.Fprintln(w, "   export HTTPS_PROXY=http://127.0.0.1:8888")
			_, _ = fmt.Fprintln(w, "   export HTTP_PROXY=http://127.0.0.1:8888")
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "4. Wrap an MCP server:")
			_, _ = fmt.Fprintln(w, "   pipelock mcp proxy --config configs/balanced.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp")
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "5. Verify the local configuration and inspect a sample verdict:")
			_, _ = fmt.Fprintln(w, "   pipelock doctor --config configs/balanced.yaml")
			_, _ = fmt.Fprintln(w, "   pipelock explain --config configs/balanced.yaml https://api.vendor.example/v1/models")
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "6. Tune with the narrowest command that names the relevant knob:")
			_, _ = fmt.Fprintln(w, "   pipelock explain event req-001 --config configs/balanced.yaml --log ./audit.log")
			_, _ = fmt.Fprintln(w, "   pipelock status --config configs/balanced.yaml")
		},
	}
}

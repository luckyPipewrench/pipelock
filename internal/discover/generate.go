// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"fmt"
	"strings"
)

// GenerateWrapper returns a human-readable wrapper suggestion for an unprotected server.
func GenerateWrapper(s MCPServer) string {
	var b strings.Builder

	if s.Transport == TransportStdio && s.Command != "" {
		_, _ = fmt.Fprintf(&b, "  Replace in your %s config:\n\n", s.Client)

		// Before
		_, _ = fmt.Fprintf(&b, "  Before:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": %q,\n", s.Command)
		_, _ = fmt.Fprintf(&b, "    \"args\": %s\n\n", formatArgs(s.Args))

		// After
		_, _ = fmt.Fprintf(&b, "  After:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": \"pipelock\",\n")

		afterArgs := []string{"mcp", "proxy", "--config", "~/.config/pipelock/local.yaml", "--", s.Command}
		afterArgs = append(afterArgs, s.Args...)
		_, _ = fmt.Fprintf(&b, "    \"args\": %s\n", formatArgs(afterArgs))

		return b.String()
	}

	if s.URL != "" {
		_, _ = fmt.Fprintf(&b, "  Replace in your %s config:\n\n", s.Client)

		_, _ = fmt.Fprintf(&b, "  Before:\n")
		_, _ = fmt.Fprintf(&b, "    \"url\": %q\n\n", s.URL)

		_, _ = fmt.Fprintf(&b, "  After:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": \"pipelock\",\n")
		_, _ = fmt.Fprintf(&b, "    \"args\": [\"mcp\", \"proxy\", \"--config\", \"~/.config/pipelock/local.yaml\", \"--upstream\", %q]\n", s.URL)

		return b.String()
	}

	return "  (no suggestion available for this transport type)"
}

func formatArgs(args []string) string {
	if len(args) == 0 {
		return "[]"
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

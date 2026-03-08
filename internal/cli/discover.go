// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func discoverCmd() *cobra.Command {
	var jsonOutput bool
	var generate bool
	var homeDir string

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Scan for AI agent configs and report MCP server protection status",
		Long: `Scan the local machine for AI agent client configurations (Claude Code,
Claude Desktop, Cursor, VS Code, Cline, Continue.dev) and report which MCP
servers are configured, their protection status, and risk level.

Exit codes:
  0  All servers protected (or none found)
  1  Unprotected, unknown, or unparseable configs found
  2  Usage or runtime error

Examples:
  pipelock discover
  pipelock discover --json
  pipelock discover --generate
  pipelock discover --home /home/otheruser`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if homeDir == "" {
				h, err := os.UserHomeDir()
				if err != nil {
					return ExitCodeError(2, fmt.Errorf("determining home directory: %w", err))
				}
				homeDir = h
			}

			report, err := discover.Discover(homeDir)
			if err != nil {
				return ExitCodeError(2, fmt.Errorf("discovery failed: %w", err))
			}

			if jsonOutput {
				return printDiscoverJSON(cmd, report)
			}

			printDiscoverHuman(cmd, report)

			if generate {
				printDiscoverGenerate(cmd, report)
			}

			if report.Summary.Unprotected > 0 || report.Summary.Unknown > 0 || report.Summary.ParseErrors > 0 {
				return &ExitError{
					Err:  errors.New("unprotected MCP servers or config parse errors found"),
					Code: 1,
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output machine-readable JSON")
	cmd.Flags().BoolVar(&generate, "generate", false, "Print pipelock wrapper suggestions for unprotected servers")
	cmd.Flags().StringVar(&homeDir, "home", "", "Override home directory (default: $HOME)")

	return cmd
}

func printDiscoverJSON(cmd *cobra.Command, report *discover.Report) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return ExitCodeError(2, fmt.Errorf("encoding JSON: %w", err))
	}

	if report.Summary.Unprotected > 0 || report.Summary.Unknown > 0 || report.Summary.ParseErrors > 0 {
		return &ExitError{
			Err:  errors.New("unprotected MCP servers or config parse errors found"),
			Code: 1,
		}
	}
	return nil
}

func printDiscoverHuman(cmd *cobra.Command, report *discover.Report) {
	w := cmd.OutOrStdout()

	_, _ = fmt.Fprintln(w, "Pipelock Discovery")
	_, _ = fmt.Fprintln(w, "==================")
	_, _ = fmt.Fprintln(w)

	if len(report.Clients) == 0 {
		_, _ = fmt.Fprintln(w, "No AI agent configs found.")
		_, _ = fmt.Fprintln(w)
		return
	}

	_, _ = fmt.Fprintf(w, "Configs found: %d\n", len(report.Clients))
	for _, c := range report.Clients {
		if c.ParseError != "" {
			_, _ = fmt.Fprintf(w, "  %-16s %-50s PARSE ERROR\n", c.Client, c.ConfigPath)
		} else {
			_, _ = fmt.Fprintf(w, "  %-16s %-50s %d server(s)\n", c.Client, c.ConfigPath, c.ServerCount)
		}
	}
	_, _ = fmt.Fprintln(w)

	if report.Summary.ParseErrors > 0 {
		_, _ = fmt.Fprintf(w, "Parse errors: %d config(s) could not be read\n", report.Summary.ParseErrors)
		for _, c := range report.Clients {
			if c.ParseError != "" {
				_, _ = fmt.Fprintf(w, "  %s: %s\n", c.ConfigPath, c.ParseError)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintf(w, "MCP Servers: %d total\n", report.Summary.TotalServers)
	_, _ = fmt.Fprintf(w, "  Protected (pipelock):  %d\n", report.Summary.ProtectedPipelock)
	_, _ = fmt.Fprintf(w, "  Protected (other):     %d\n", report.Summary.ProtectedOther)
	_, _ = fmt.Fprintf(w, "  Unprotected:           %d\n", report.Summary.Unprotected)
	_, _ = fmt.Fprintf(w, "  Unknown:               %d\n", report.Summary.Unknown)
	_, _ = fmt.Fprintln(w)

	// List unprotected servers sorted by risk
	unprotected := false
	for _, s := range report.Servers {
		if s.Protection == discover.Unprotected || s.Protection == discover.Unknown {
			if !unprotected {
				_, _ = fmt.Fprintln(w, "Unprotected servers:")
				unprotected = true
			}
			risk := strings.ToUpper(string(s.Risk))
			desc := serverDescription(s)
			if s.ProjectPath != "" {
				desc += fmt.Sprintf(" (project: %s)", s.ProjectPath)
			}
			_, _ = fmt.Fprintf(w, "  [%-6s] [%-16s] %-20s %s\n",
				risk, s.Client, s.ServerName, desc)
			for _, warn := range s.ParseWarnings {
				_, _ = fmt.Fprintf(w, "           WARNING: %s\n", warn)
			}
		}
	}

	if unprotected {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Use --generate to print pipelock wrapper suggestions.")
	} else if report.Summary.TotalServers > 0 {
		_, _ = fmt.Fprintln(w, "All servers are protected.")
	}
	_, _ = fmt.Fprintln(w, "Use --json for machine-readable output.")
}

func printDiscoverGenerate(cmd *cobra.Command, report *discover.Report) {
	w := cmd.OutOrStdout()
	printed := false

	for _, s := range report.Servers {
		if s.Protection != discover.Unprotected {
			continue
		}
		if !printed {
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "Wrapper suggestions:")
			_, _ = fmt.Fprintln(w, "====================")
			printed = true
		}
		_, _ = fmt.Fprintln(w)
		if s.ProjectPath != "" {
			_, _ = fmt.Fprintf(w, "Server: %s (%s, project: %s)\n", s.ServerName, s.Client, s.ProjectPath)
		} else {
			_, _ = fmt.Fprintf(w, "Server: %s (%s)\n", s.ServerName, s.Client)
		}
		suggestion := discover.GenerateWrapper(s)
		_, _ = fmt.Fprintln(w, suggestion)
	}
}

func serverDescription(s discover.MCPServer) string {
	if s.Command != "" {
		parts := []string{s.Command}
		parts = append(parts, s.Args...)
		return strings.Join(parts, " ")
	}
	if s.URL != "" {
		return s.URL
	}
	return "(unknown)"
}

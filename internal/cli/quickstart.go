// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"
)

// quickstartCmd prints the getting-started walkthrough.
//
// Two things this has to get right, because it is the first command a new user
// runs and both were wrong before.
//
// It must not name a file the reader does not have. It previously said
// `--config configs/balanced.yaml` in five of six steps. That path exists only
// in a source clone, so anyone who installed from Homebrew, a container, or a
// release binary followed step two and got "no such file or directory". The
// walkthrough now creates a config in step one and refers to that.
//
// It must not print instructions for an operating system the reader is not on.
// It previously printed sudo, /usr/local/bin, and shell export lines
// unconditionally, none of which mean anything on Windows, which is a platform
// this project publishes binaries for.
func quickstartCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "quickstart",
		Short:        "Print a concrete getting-started walkthrough",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, _ []string) {
			writeQuickstart(cmd.OutOrStdout(), runtime.GOOS)
		},
	}
}

const (
	quickstartConfig    = "pipelock.yaml"
	quickstartWorkspace = "agent-workspace"
)

func writeQuickstart(w io.Writer, goos string) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }

	p("Pipelock Quickstart")
	p("===================")
	p("")
	p("1. Create a config. This writes %s in the current directory and", quickstartConfig)
	p("   checks that it loads:")
	p("   pipelock init --output ./%s", quickstartConfig)
	p("")
	p("2. Start the local proxy with that config:")
	p("   pipelock run --config ./%s", quickstartConfig)
	p("")
	p("3. Route HTTPS-aware tools through the proxy:")
	for _, line := range proxyEnvLines(goos) {
		p("   %s", line)
	}
	p("")
	p("4. Wrap an MCP server. Point it at one directory you make for the agent")
	p("   rather than at your whole disk:")
	p("   pipelock mcp proxy --config ./%s -- npx -y @modelcontextprotocol/server-filesystem ./%s",
		quickstartConfig, quickstartWorkspace)
	p("")
	p("5. Verify the configuration and inspect a sample verdict:")
	p("   pipelock doctor --config ./%s", quickstartConfig)
	p("   pipelock explain --config ./%s https://api.vendor.example/v1/models", quickstartConfig)
	p("")
	p("6. Tune with the narrowest command that names the relevant knob:")
	p("   pipelock explain event req-001 --config ./%s --log ./audit.log", quickstartConfig)
	p("   pipelock status --config ./%s", quickstartConfig)

	if line := systemInstallLine(goos); line != "" {
		p("")
		p("To install the binary system-wide so other runtimes find it:")
		p("   %s", line)
	}
}

// proxyEnvLines returns the shell lines that point a tool at the proxy, in the
// syntax of the platform the reader is actually on. A bash export line is not a
// suggestion on Windows, it is a syntax error.
func proxyEnvLines(goos string) []string {
	const addr = "http://127.0.0.1:8888"
	if goos == "windows" {
		// Each label sits on its own line. Appending one to a command is not a
		// note, it is part of the command: cmd assigns everything after the
		// equals sign, so the variable would hold the URL, the padding, and the
		// label, and the proxy address would never resolve.
		return []string{
			"cmd.exe:",
			`  set HTTPS_PROXY=` + addr,
			`  set HTTP_PROXY=` + addr,
			"PowerShell:",
			`  $env:HTTPS_PROXY = "` + addr + `"`,
			`  $env:HTTP_PROXY = "` + addr + `"`,
		}
	}
	return []string{
		"export HTTPS_PROXY=" + addr,
		"export HTTP_PROXY=" + addr,
	}
}

// systemInstallLine returns the system-wide install command, or empty when the
// platform has no single conventional location to name. Printing a Unix path
// and sudo to a Windows reader sends them somewhere that does not exist.
func systemInstallLine(goos string) string {
	if goos == "windows" {
		return ""
	}
	return "sudo pipelock install /usr/local/bin/pipelock"
}

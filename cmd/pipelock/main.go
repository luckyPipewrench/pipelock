// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for the Pipelock CLI.
package main

import (
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/cli"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

func main() {
	// Sandbox re-exec entry points. These run before any CLI initialization.
	// MCP mode: applies containment then execs the command (does not return).
	// Standalone mode: applies containment, runs bridge proxy + agent subprocess.
	if sandbox.IsInitMode() {
		sandbox.RunInit()
		return
	}
	if sandbox.IsStandaloneInitMode() {
		sandbox.RunStandaloneInit()
		return
	}

	if err := cli.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cliutil.ExitCodeOf(err))
	}
}

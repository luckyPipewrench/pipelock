// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/capabilitymanifest"
)

// run holds the whole generator so its failure paths are reachable from a test.
// main stays flag parsing and an exit code, which is the part a test cannot
// exercise without spawning a process.
func run(manifestPath, agentsPath string, stderr io.Writer) int {
	if manifestPath == "" || agentsPath == "" {
		_, _ = fmt.Fprintln(stderr, "usage: generate -manifest PATH -agents PATH")
		return 2
	}

	manifest, err := capabilitymanifest.Load(manifestPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load manifest: %v\n", err)
		return 1
	}
	agents, err := os.ReadFile(filepath.Clean(agentsPath))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "read AGENTS.md: %v\n", err)
		return 1
	}
	updated, err := capabilitymanifest.ReplaceAgentsSection(string(agents), capabilitymanifest.RenderAgentsSection(manifest))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "render AGENTS.md: %v\n", err)
		return 1
	}
	if err := os.WriteFile(filepath.Clean(agentsPath), []byte(updated), 0o600); err != nil {
		_, _ = fmt.Fprintf(stderr, "write AGENTS.md: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	manifestPath := flag.String("manifest", "", "path to capability manifest")
	agentsPath := flag.String("agents", "", "path to AGENTS.md")
	flag.Parse()
	os.Exit(run(*manifestPath, *agentsPath, os.Stderr))
}

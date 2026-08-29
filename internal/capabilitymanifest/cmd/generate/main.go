// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/capabilitymanifest"
)

func main() {
	manifestPath := flag.String("manifest", "", "path to capability manifest")
	agentsPath := flag.String("agents", "", "path to AGENTS.md")
	flag.Parse()
	if *manifestPath == "" || *agentsPath == "" {
		fmt.Fprintln(os.Stderr, "usage: generate -manifest PATH -agents PATH")
		os.Exit(2)
	}

	manifest, err := capabilitymanifest.Load(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load manifest: %v\n", err)
		os.Exit(1)
	}
	agents, err := os.ReadFile(filepath.Clean(*agentsPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read AGENTS.md: %v\n", err)
		os.Exit(1)
	}
	updated, err := capabilitymanifest.ReplaceAgentsSection(string(agents), capabilitymanifest.RenderAgentsSection(manifest))
	if err != nil {
		fmt.Fprintf(os.Stderr, "render AGENTS.md: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Clean(*agentsPath), []byte(updated), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write AGENTS.md: %v\n", err)
		os.Exit(1)
	}
}

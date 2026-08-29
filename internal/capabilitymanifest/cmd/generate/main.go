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
	if err := writeAtomically(filepath.Clean(agentsPath), []byte(updated)); err != nil {
		_, _ = fmt.Fprintf(stderr, "write AGENTS.md: %v\n", err)
		return 1
	}
	return 0
}

// writeAtomically replaces a file through a temporary file in the same
// directory followed by a rename, so an interrupted run cannot leave the
// contributor guidance truncated or empty. A direct write truncates first,
// which means a crash between truncate and write destroys the file.
func writeAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp, err := os.CreateTemp(dir, ".agents-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func main() {
	manifestPath := flag.String("manifest", "", "path to capability manifest")
	agentsPath := flag.String("agents", "", "path to AGENTS.md")
	flag.Parse()
	os.Exit(run(*manifestPath, *agentsPath, os.Stderr))
}

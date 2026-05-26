// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Finding describes a DLP match detected in a file written to a watched directory.
type Finding struct {
	Path        string `json:"path"`
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
	IsAgent     bool   `json:"is_agent"`          // true if writer is in the agent process tree
	Encoded     string `json:"encoded,omitempty"` // encoding layer where match was found
}

// DLPScanner is the subset of scanner.Scanner needed by the file watcher.
// Using an interface allows test doubles without spinning up a full scanner.
type DLPScanner interface {
	ScanTextForDLP(ctx context.Context, text string) scanner.TextDLPResult
}

// Watcher monitors directories for file writes and scans content for secrets.
type Watcher interface {
	// Arm installs watches on all configured directories synchronously.
	// Must be called before launching the child process. Returns an error
	// only if a required:true entry cannot be installed; non-required
	// failures are recorded via DegradedPaths and the onError callback.
	Arm() error
	// Start processes filesystem events. Blocks until ctx is cancelled.
	// Call Arm() first to install watches.
	Start(ctx context.Context) error
	// Findings returns a channel that receives DLP findings as they are detected.
	Findings() <-chan Finding
	// DegradedPaths returns the configured watch_paths entries whose Arm()
	// install failed and whose entry was not marked required:true. Empty
	// when the watcher is fully armed. Safe to call concurrently.
	DegradedPaths() []DegradedPath
	// Close stops the watcher and releases resources.
	Close() error
}

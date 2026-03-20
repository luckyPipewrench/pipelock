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
	PID         int    `json:"pid,omitempty"` // 0 if attribution unavailable
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
	IsAgent     bool   `json:"is_agent"`          // true if PID is in the agent process tree
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
	// Must be called before launching the child process.
	Arm() error
	// Start processes filesystem events. Blocks until ctx is cancelled.
	// Call Arm() first to install watches.
	Start(ctx context.Context) error
	// Findings returns a channel that receives DLP findings as they are detected.
	Findings() <-chan Finding
	// Close stops the watcher and releases resources.
	Close() error
}

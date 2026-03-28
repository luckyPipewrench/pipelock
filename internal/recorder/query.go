// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// QueryFilter specifies criteria for filtering evidence entries.
type QueryFilter struct {
	SessionID string
	Type      string // "request", "response", "scan", "tool_call", "hitl", "checkpoint"
	Transport string // "fetch", "forward", "connect", "websocket", "mcp-stdio", "mcp-http"
	After     time.Time
	Before    time.Time
	MinSeq    uint64
	MaxSeq    uint64
	HasMaxSeq bool // Distinguishes MaxSeq=0 from unset
}

// QueryResult holds the results of an evidence query.
type QueryResult struct {
	Entries    []Entry
	TotalFiles int
	FilesRead  int
}

// QuerySession reads evidence files for a session and applies filters.
func QuerySession(dir, sessionID string, filter *QueryFilter) (*QueryResult, error) {
	dir = filepath.Clean(dir)
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading evidence directory: %w", err)
	}

	prefix := "evidence-" + sessionID + "-"
	var files []string
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".jsonl") {
			files = append(files, filepath.Join(dir, name))
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return extractSeqStart(files[i]) < extractSeqStart(files[j])
	})

	result := &QueryResult{
		TotalFiles: len(files),
	}

	for _, f := range files {
		entries, err := ReadEntries(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		result.FilesRead++

		for _, e := range entries {
			if matchesFilter(e, filter) {
				result.Entries = append(result.Entries, e)
			}
		}
	}

	return result, nil
}

// ListSessions returns the unique session IDs found in evidence files.
func ListSessions(dir string) ([]string, error) {
	dir = filepath.Clean(dir)
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading evidence directory: %w", err)
	}

	seen := make(map[string]struct{})
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !strings.HasPrefix(name, "evidence-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		// Parse session ID: evidence-<session_id>-<seq>.jsonl
		rest := strings.TrimPrefix(name, "evidence-")
		rest = strings.TrimSuffix(rest, ".jsonl")
		// Find the last dash to separate session ID from seq number
		lastDash := strings.LastIndex(rest, "-")
		if lastDash < 0 {
			continue
		}
		sessionID := rest[:lastDash]
		if sessionID != "" {
			seen[sessionID] = struct{}{}
		}
	}

	sessions := make([]string, 0, len(seen))
	for s := range seen {
		sessions = append(sessions, s)
	}
	sort.Strings(sessions)
	return sessions, nil
}

// extractSeqStart parses the numeric seqStart from an evidence filename.
// Returns 0 if the filename cannot be parsed.
func extractSeqStart(path string) int {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, ".jsonl")
	lastDash := strings.LastIndex(name, "-")
	if lastDash < 0 {
		return 0
	}
	n, err := strconv.Atoi(name[lastDash+1:])
	if err != nil {
		return 0
	}
	return n
}

// matchesFilter checks if an entry matches the given filter criteria.
func matchesFilter(e Entry, f *QueryFilter) bool {
	if f == nil {
		return true
	}
	if f.SessionID != "" && e.SessionID != f.SessionID {
		return false
	}
	if f.Type != "" && e.Type != f.Type {
		return false
	}
	if f.Transport != "" && e.Transport != f.Transport {
		return false
	}
	if !f.After.IsZero() && e.Timestamp.Before(f.After) {
		return false
	}
	if !f.Before.IsZero() && e.Timestamp.After(f.Before) {
		return false
	}
	if e.Sequence < f.MinSeq {
		return false
	}
	if f.HasMaxSeq && e.Sequence > f.MaxSeq {
		return false
	}
	return true
}

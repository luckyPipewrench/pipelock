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

	// MaxEntriesRead is a hard ceiling on parsed recorder entries for callers
	// that render evidence in an online UI. Zero means unbounded.
	MaxEntriesRead int
}

// QueryResult holds the results of an evidence query.
type QueryResult struct {
	Entries     []Entry
	TotalFiles  int
	FilesRead   int
	EntriesRead int
	Truncated   bool
}

// QuerySession reads evidence files for a session and applies filters.
func QuerySession(dir, sessionID string, filter *QueryFilter) (*QueryResult, error) {
	dir = filepath.Clean(dir)
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading evidence directory: %w", err)
	}

	var files []string
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		fileSessionID, ok := evidenceFileSessionID(name)
		if ok && fileSessionID == sessionID {
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
		maxEntries := 0
		if filter != nil && filter.MaxEntriesRead > 0 {
			remaining := filter.MaxEntriesRead - result.EntriesRead
			if remaining <= 0 {
				result.Truncated = true
				break
			}
			maxEntries = remaining
		}

		entries, truncated, err := readEntries(f, maxEntries)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		result.FilesRead++
		result.EntriesRead += len(entries)
		if truncated {
			result.Truncated = true
		}

		for _, e := range entries {
			if e.SessionID != sessionID {
				return nil, fmt.Errorf("reading %s: entry seq %d session_id %q does not match requested session %q", filepath.Base(f), e.Sequence, e.SessionID, sessionID)
			}
			if matchesFilter(e, filter) {
				result.Entries = append(result.Entries, e)
			}
		}

		if result.Truncated {
			break
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
		sessionID, ok := evidenceFileSessionID(name)
		if !ok {
			continue
		}
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

func evidenceFileSessionID(name string) (string, bool) {
	sessionID, _, ok := parseEvidenceFilename(name)
	return sessionID, ok
}

func parseEvidenceFilename(name string) (sessionID string, seqStart int, ok bool) {
	name = filepath.Base(name)
	if !strings.HasPrefix(name, "evidence-") || !strings.HasSuffix(name, ".jsonl") {
		return "", 0, false
	}
	rest := strings.TrimPrefix(name, "evidence-")
	rest = strings.TrimSuffix(rest, ".jsonl")
	lastDash := strings.LastIndex(rest, "-")
	if lastDash < 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(rest[lastDash+1:])
	if err != nil {
		n = 0
	}
	return rest[:lastDash], n, true
}

// extractSeqStart parses the numeric seqStart from an evidence filename.
// Returns 0 if the filename cannot be parsed.
func extractSeqStart(path string) int {
	_, seqStart, ok := parseEvidenceFilename(path)
	if !ok {
		return 0
	}
	return seqStart
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

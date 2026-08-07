// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
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
	// that render evidence in an online UI. Zero uses the default per-file
	// evidence ceiling.
	MaxEntriesRead int
	// MaxDirectoryEntries is a hard ceiling on evidence directory entries read
	// before filtering to one session. Zero uses the default ceiling.
	MaxDirectoryEntries int
	// MaxBytesRead is a hard ceiling on recorder bytes scanned before filtering.
	// Zero uses the default per-file evidence ceiling.
	MaxBytesRead int64
}

// QueryResult holds the results of an evidence query.
type QueryResult struct {
	Entries     []Entry
	TotalFiles  int
	FilesRead   int
	EntriesRead int
	BytesRead   int64
	Truncated   bool
}

// QuerySession reads evidence files for a session and applies filters.
func QuerySession(dir, sessionID string, filter *QueryFilter) (*QueryResult, error) {
	location, err := ResolveEvidenceLocation(dir, "")
	if err != nil {
		return nil, fmt.Errorf("resolve evidence location: %w", err)
	}
	return QuerySessionResolved(location, sessionID, filter)
}

// QuerySessionResolved reads one already-resolved evidence location.
func QuerySessionResolved(location EvidenceLocation, sessionID string, filter *QueryFilter) (*QueryResult, error) {
	dirEntries, dirTruncated, err := readEvidenceLocationDirectoryEntries(location, maxDirectoryEntries(filter))
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
			files = append(files, name)
		}
	}

	// Total order. sort.Slice is unstable and an unparseable trailing
	// segment yields sequence 0, so ties must not fall to directory order.
	sort.Slice(files, func(i, j int) bool {
		si, sj := extractSeqStart(files[i]), extractSeqStart(files[j])
		if si != sj {
			return si < sj
		}
		return filepath.Base(files[i]) < filepath.Base(files[j])
	})

	result := &QueryResult{
		TotalFiles: len(files),
		Truncated:  dirTruncated,
	}

	for _, f := range files {
		maxEntries := MaxEvidenceReadEntries
		if filter != nil && filter.MaxEntriesRead > 0 {
			remaining := filter.MaxEntriesRead - result.EntriesRead
			if remaining <= 0 {
				result.Truncated = true
				break
			}
			maxEntries = remaining
		}
		maxBytes := MaxEvidenceReadFileBytes
		if filter != nil && filter.MaxBytesRead > 0 {
			remaining := filter.MaxBytesRead - result.BytesRead
			if remaining <= 0 {
				result.Truncated = true
				break
			}
			maxBytes = remaining
		}

		entries, truncated, bytesRead, err := readEntriesAtEvidenceLocation(location, f, entryReadLimits{MaxEntries: maxEntries, MaxBytes: maxBytes})
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		result.FilesRead++
		result.EntriesRead += len(entries)
		result.BytesRead += bytesRead
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
	return ListSessionsBounded(dir, MaxEvidenceReadDirectoryEntries)
}

type SessionListResult struct {
	Sessions  []string
	Truncated bool
}

// ListSessionsBounded returns unique session IDs while enforcing a hard ceiling
// on directory entries read. Zero means unbounded.
func ListSessionsBounded(dir string, maxEntries int) ([]string, error) {
	result, err := ListSessionsBoundedResult(dir, maxEntries)
	if err != nil {
		return nil, err
	}
	if result.Truncated {
		return nil, fmt.Errorf("%w: evidence directory exceeds %d entries", ErrEvidenceReadLimitExceeded, maxEntries)
	}
	return result.Sessions, nil
}

// ListSessionsBoundedResult returns unique session IDs and an explicit
// truncation signal when the directory-entry ceiling is reached. Zero means
// unbounded.
func ListSessionsBoundedResult(dir string, maxEntries int) (SessionListResult, error) {
	location, err := ResolveEvidenceLocation(dir, "")
	if err != nil {
		return SessionListResult{}, fmt.Errorf("resolve evidence location: %w", err)
	}
	return ListSessionsBoundedResultResolved(location, maxEntries)
}

// ListSessionsBoundedResultResolved lists sessions in one already-resolved evidence location.
func ListSessionsBoundedResultResolved(location EvidenceLocation, maxEntries int) (SessionListResult, error) {
	dirEntries, truncated, err := readEvidenceLocationDirectoryEntries(location, maxEntries)
	if err != nil {
		return SessionListResult{}, fmt.Errorf("reading evidence directory: %w", err)
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
	return SessionListResult{Sessions: sessions, Truncated: truncated}, nil
}

func maxDirectoryEntries(filter *QueryFilter) int {
	if filter != nil && filter.MaxDirectoryEntries > 0 {
		return filter.MaxDirectoryEntries
	}
	return MaxEvidenceReadDirectoryEntries
}

func readDirectoryEntries(dir string, maxEntries int) ([]os.DirEntry, bool, error) {
	if maxEntries <= 0 {
		entries, err := os.ReadDir(dir)
		return entries, false, err
	}
	directory, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = directory.Close() }()
	// maxEntries+1 would overflow to a negative value at math.MaxInt, and a
	// non-positive count makes ReadDir read the whole directory unbounded.
	readLimit := maxEntries
	if readLimit < math.MaxInt {
		readLimit++
	}
	entries, err := directory.ReadDir(readLimit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if len(entries) > maxEntries {
		return entries[:maxEntries], true, nil
	}
	return entries, false, nil
}

func evidenceFileSessionID(name string) (string, bool) {
	sessionID, _, ok := ParseEvidenceFilename(name)
	return sessionID, ok
}

// ParseEvidenceFilename splits an evidence shard filename into its session ID
// and starting sequence.
//
// It delegates to evidencename.Parse, which is the single definition shared
// with the contract verifier. Callers MUST compare the returned sessionID for
// equality rather than prefix-testing the filename; see that package for why.
func ParseEvidenceFilename(name string) (sessionID string, seqStart uint64, ok bool) {
	return evidencename.Parse(name)
}

// extractSeqStart parses the numeric seqStart from an evidence filename.
// Returns 0 if the filename cannot be parsed.
func extractSeqStart(path string) uint64 {
	_, seqStart, ok := ParseEvidenceFilename(path)
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

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

		if err := CheckEntrySessions(entries, sessionID); err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		for _, e := range entries {
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

// WalkSessionEntries securely reads one session's evidence shards in the same
// order as QuerySessionResolved and calls consume once per parsed entry. It
// keeps the bounded directory listing and one entry line in memory; callers
// must treat any returned error as invalidating the entire walk, since an
// error can occur after earlier entries were delivered.
func WalkSessionEntries(dir, sessionID string, consume func(Entry) error) error {
	if consume == nil {
		return errors.New("session entry consumer is required")
	}
	location, err := ResolveEvidenceLocation(dir, "")
	if err != nil {
		return fmt.Errorf("resolve evidence location: %w", err)
	}
	dirEntries, truncated, err := readEvidenceLocationDirectoryEntries(location, MaxEvidenceReadDirectoryEntries)
	if err != nil {
		return fmt.Errorf("reading evidence directory: %w", err)
	}
	if truncated {
		return fmt.Errorf("%w: evidence directory exceeds %d entries", ErrEvidenceReadLimitExceeded, MaxEvidenceReadDirectoryEntries)
	}

	files := make([]string, 0, len(dirEntries))
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
	sort.Slice(files, func(i, j int) bool {
		si, sj := extractSeqStart(files[i]), extractSeqStart(files[j])
		if si != sj {
			return si < sj
		}
		return filepath.Base(files[i]) < filepath.Base(files[j])
	})

	for _, name := range files {
		if err := walkEntriesAtEvidenceLocation(location, name, sessionID, consume); err != nil {
			return fmt.Errorf("reading %s: %w", filepath.Base(name), err)
		}
	}
	return nil
}

func walkEntriesAtEvidenceLocation(location EvidenceLocation, name, sessionID string, consume func(Entry) error) error {
	file, before, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = file.Close() }()
	if before.Size() > MaxEvidenceReadFileBytes {
		return fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(name), MaxEvidenceReadFileBytes)
	}
	if err := walkEntryReader(io.NewSectionReader(file, 0, before.Size()), filepath.Join(location.Dir, name), sessionID, consume); err != nil {
		return fmt.Errorf("reading evidence file: %w", err)
	}
	if err := ensureEvidenceFileUnchanged(file, before); err != nil {
		return err
	}
	return nil
}

func walkEntryReader(input io.Reader, path, sessionID string, consume func(Entry) error) error {
	reader := bufio.NewReader(input)
	line := make([]byte, 0, 4096)
	var bytesRead int64
	entriesRead := 0
	for {
		fragment, readErr := reader.ReadSlice('\n')
		bytesRead += int64(len(fragment))
		if bytesRead > MaxEvidenceReadFileBytes {
			return fmt.Errorf("%w: evidence file %s exceeds %d bytes", ErrEvidenceReadLimitExceeded, filepath.Base(path), MaxEvidenceReadFileBytes)
		}
		if len(line)+len(fragment) > maxEntryWireLineBytes {
			return fmt.Errorf("line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
		}
		line = append(line, fragment...)
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("scanning evidence entries: %w", readErr)
		}
		complete := len(line) > 0 && line[len(line)-1] == '\n'
		if !complete && len(line) > 0 {
			// Match file-backed QuerySession semantics: an unterminated final
			// JSONL record is a torn write, even if it contains valid JSON.
			return InspectEvidenceTailBytes(path, line, nil)
		}
		if len(line) > 0 {
			payload := bytes.TrimSuffix(line, []byte{'\n'})
			payload = bytes.TrimSuffix(payload, []byte{'\r'})
			if len(payload) > MaxEntryLineBytes {
				return fmt.Errorf("line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
			}
			if len(bytes.TrimSpace(payload)) > 0 {
				if entriesRead >= MaxEvidenceReadEntries {
					return fmt.Errorf("%w: evidence file %s exceeds %d entries", ErrEvidenceReadLimitExceeded, filepath.Base(path), MaxEvidenceReadEntries)
				}
				entry, err := ParseEntryLine(payload)
				if err != nil {
					return fmt.Errorf("parsing entry: %w", err)
				}
				if !acceptedEntryVersions[entry.Version] {
					return fmt.Errorf("unsupported entry version %d (accepted: 1, 2, 3)", entry.Version)
				}
				if err := ValidateEntrySchema(entry); err != nil {
					return err
				}
				if entry.SessionID != sessionID {
					return fmt.Errorf("%w: entry seq %d session_id %q does not match requested session %q", ErrEvidenceRefused, entry.Sequence, entry.SessionID, sessionID)
				}
				if err := consume(entry); err != nil {
					return err
				}
				entriesRead++
			}
		}
		line = line[:0]
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
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

// Names of the files the recorder and the receipt chain keep inside an
// evidence directory besides the JSONL shards themselves. The chain-link and
// anchor-state names are owned by the receipt and anchor packages, which this
// package cannot import; parity tests in those packages fail if their names
// stop being recognized here.
const (
	// RunWriterLockPrefix and RunWriterLockSuffix frame a run's lifetime lock.
	RunWriterLockPrefix = "writer-"
	RunWriterLockSuffix = ".lock"

	chainLinkPrefix     = "chain-link-"
	chainLinkSuffix     = ".json"
	anchorStateMarker   = "anchor-state.json"
	rawEscrowSuffix     = ".raw.enc"
	rawEscrowNamePrefix = "evidence-"
	rawEscrowNameMarker = "-raw-"
)

// IsRecorderOwnedFile reports whether name is a file the recorder or the
// receipt chain writes into an evidence directory: a JSONL shard, a raw-escrow
// sidecar, a restart continuity link, a run's lifetime writer lock, or the
// anchor-state marker.
//
// A command that writes its own output into or beside an evidence directory
// must refuse every one of these, because an atomic replace destroys evidence
// another process wrote. It exists as ONE definition so the next file the
// recorder learns to write is protected by adding it here, rather than by
// finding every guard that listed the old names.
func IsRecorderOwnedFile(name string) bool {
	if _, _, ok := ParseEvidenceFilename(name); ok {
		return true
	}
	switch {
	case strings.HasPrefix(name, rawEscrowNamePrefix) && strings.Contains(name, rawEscrowNameMarker) && strings.HasSuffix(name, rawEscrowSuffix):
		return true
	case strings.HasPrefix(name, chainLinkPrefix) && strings.HasSuffix(name, chainLinkSuffix):
		return true
	case strings.HasPrefix(name, RunWriterLockPrefix) && strings.HasSuffix(name, RunWriterLockSuffix):
		return true
	case name == anchorStateMarker:
		return true
	}
	return false
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

// CheckEntrySessions refuses entries that are not all of session. A file
// named for one session that holds another session's entries is not that
// session's evidence, whatever its hash chain says.
func CheckEntrySessions(entries []Entry, session string) error {
	for _, e := range entries {
		if e.SessionID != session {
			return fmt.Errorf("%w: entry seq %d session_id %q does not match requested session %q", ErrEvidenceRefused, e.Sequence, e.SessionID, session)
		}
	}
	return nil
}

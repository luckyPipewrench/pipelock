// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bufio"
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

// Authoritative session history.
//
// The readers in this file are the ONLY directory readers that write,
// lifecycle, verification and anchoring code may use. They differ from the
// bounded display readers in query.go (QuerySession, ListSessions and their
// variants) in one way that matters: they apply no presentation budget. There
// is no directory entry ceiling, no whole-file byte ceiling and no per-file
// entry ceiling, because a budget that refuses complete valid evidence turns a
// display limit into a lifecycle outage: a receipt group that cannot close, a
// closed group that stops verifying, a successor that cannot be created.
//
// What they keep is every check that decides whether evidence is genuine:
// shard selection by parsed session equality (never a filename prefix), a
// refusal of two shards that start the same sequence, no-follow opens through
// the pinned evidence location, refusal of non-regular files, the recorder's
// 1 MiB single-entry line limit, entry version and schema validation, session
// membership of every entry, torn-tail classification, and detection of a
// shard that changed while it was read.
//
// Memory stays bounded however long the session is. Unrelated files are
// skipped as they are listed and never retained or counted. The session's own
// shard names are ordered in windows: each directory pass keeps only the
// sessionHistoryWindow smallest shard keys after the last one already
// delivered, so a session with more shards than that is walked in several
// passes rather than by holding every name at once. Entries stream one line at
// a time.
//
// A boundary test (session_history_boundary_test.go) fails if anything this
// file reaches calls a bounded display reader or names a display budget, and
// if a write, lifecycle, verification or anchoring package calls one.

// sessionHistoryWindow is how many shard names one directory pass retains. A
// session with at most this many shards is walked in a single pass.
const sessionHistoryWindow = 1024

// sessionHistoryDirBatch is how many directory entries are read per call.
const sessionHistoryDirBatch = 128

// SessionHistoryShard identifies one shard of an authoritative walk.
type SessionHistoryShard struct {
	// Name is the shard's base name inside the evidence location.
	Name string
	// SeqStart is the starting sequence parsed from Name.
	SeqStart uint64
	// Final reports that no later shard of the session was listed when this
	// shard was delivered.
	Final bool
}

// WalkSessionHistory resolves dir and walks one session's complete history.
// See WalkSessionHistoryResolved.
func WalkSessionHistory(dir, sessionID string, consume func(Entry) error) error {
	location, err := ResolveEvidenceLocation(dir, "")
	if err != nil {
		return fmt.Errorf("resolve evidence location: %w", err)
	}
	return WalkSessionHistoryResolved(location, sessionID, consume)
}

// WalkSessionHistoryResolved delivers every entry of sessionID, in chain order
// across all of its shards, to consume. It is the authoritative counterpart
// of the bounded display readers: it never truncates and never refuses
// evidence for its size, and unrelated files in the directory do not affect
// it. Any returned error invalidates the whole walk, because consume may
// already have seen entries before the failure.
//
// A torn final write in the last shard returns an error wrapping
// ErrTornTail after every complete entry before it was delivered. A torn
// shard followed by a later shard is refused outright, because the later
// shard may hold authenticated entries a caller must not treat as missing.
func WalkSessionHistoryResolved(location EvidenceLocation, sessionID string, consume func(Entry) error) error {
	if consume == nil {
		return errors.New("session entry consumer is required")
	}
	return walkSessionHistoryEntries(location, sessionID, sessionHistoryWindow, consume)
}

func walkSessionHistoryEntries(location EvidenceLocation, sessionID string, window int, consume func(Entry) error) error {
	return walkSessionHistoryShards(location, sessionID, window, func(shard SessionHistoryShard) error {
		err := walkHistoryShardEntries(location, shard.Name, sessionID, consume)
		if err == nil {
			return nil
		}
		if !shard.Final && errors.Is(err, ErrTornTail) {
			// A later segment may contain authenticated entries. Never let a
			// caller treat this stopped walk as a recoverable final write.
			return fmt.Errorf("receipt group session has a torn segment: %s", shard.Name)
		}
		return fmt.Errorf("reading %s: %w", shard.Name, err)
	})
}

// WalkSessionHistoryFiles delivers each of sessionID's shards, in chain
// order, as a reader over exactly the bytes present when the shard was
// opened. It is for verifiers that parse recorder lines themselves; they get
// the same shard selection, ordering, secure opens and change detection as
// WalkSessionHistoryResolved, and no size budget. The shard is refused after
// consume returns if it changed while it was read. Any returned error
// invalidates the whole walk.
func WalkSessionHistoryFiles(location EvidenceLocation, sessionID string, consume func(SessionHistoryShard, io.Reader) error) error {
	if consume == nil {
		return errors.New("session shard consumer is required")
	}
	return walkSessionHistoryShards(location, sessionID, sessionHistoryWindow, func(shard SessionHistoryShard) error {
		if err := readHistoryShard(location, shard, consume); err != nil {
			return fmt.Errorf("reading %s: %w", shard.Name, err)
		}
		return nil
	})
}

func readHistoryShard(location EvidenceLocation, shard SessionHistoryShard, consume func(SessionHistoryShard, io.Reader) error) error {
	file, before, err := openEvidenceLocationFile(location, shard.Name)
	if err != nil {
		return fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := consume(shard, io.NewSectionReader(file, 0, before.Size())); err != nil {
		return err
	}
	return ensureEvidenceFileUnchanged(file, before)
}

// walkHistoryShardEntries streams one shard's entries through the pinned
// location and refuses the shard if it changed while it was read.
func walkHistoryShardEntries(location EvidenceLocation, name, sessionID string, consume func(Entry) error) error {
	file, before, err := openEvidenceLocationFile(location, name)
	if err != nil {
		return fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := walkHistoryEntries(io.NewSectionReader(file, 0, before.Size()), filepath.Join(location.Dir, name), sessionID, consume); err != nil {
		return fmt.Errorf("reading evidence file: %w", err)
	}
	return ensureEvidenceFileUnchanged(file, before)
}

// walkHistoryEntries parses one shard line by line. Its only size limit is
// the recorder's per-entry line limit, which is a format rule, not a budget.
func walkHistoryEntries(input io.Reader, path, sessionID string, consume func(Entry) error) error {
	reader := bufio.NewReader(input)
	line := make([]byte, 0, 4096)
	var bytesRead int64
	for {
		fragment, readErr := reader.ReadSlice('\n')
		bytesRead += int64(len(fragment))
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
			// Reader verdicts never authenticate an unterminated record. Writer
			// recovery separately validates complete JSON before classifying it.
			boundary := bytesRead - int64(len(line))
			return &TornTailError{Path: path, Offset: boundary, LastGoodOffset: boundary}
		}
		if len(line) > 0 {
			payload := bytes.TrimSuffix(line, []byte{'\n'})
			payload = bytes.TrimSuffix(payload, []byte{'\r'})
			if len(payload) > MaxEntryLineBytes {
				return fmt.Errorf("line exceeds %d-byte recorder entry limit", MaxEntryLineBytes)
			}
			if TrimEntryLine(string(payload)) != "" {
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
					return entrySessionError(entry, sessionID)
				}
				if err := consume(entry); err != nil {
					return err
				}
			}
		}
		line = line[:0]
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

// WalkHistoryEntriesFromReader parses every recorder entry in r and delivers
// it to consume. It applies the recorder's per-entry line limit and the same
// parsing, version and schema checks as every reader, and no aggregate byte or
// entry budget. When r is an *os.File, an unterminated final record is refused
// as ErrTornTail before any entry is delivered.
func WalkHistoryEntriesFromReader(r io.Reader, consume func(Entry) error) error {
	if consume == nil {
		return errors.New("entry consumer is required")
	}
	_, _, err := walkEntriesFromReader(r, entryReadLimits{}, consume)
	return err
}

// ReadHistoryEntries reads every entry of one recorder file with no aggregate
// budget, for callers that need the whole file at once. Memory is the
// caller's to bound: prefer WalkHistoryEntriesFromReader or WalkEvidenceFile.
func ReadHistoryEntries(path string) ([]Entry, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = f.Close() }()
	entries, err := ReadHistoryEntriesFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("reading evidence file: %w", err)
	}
	return entries, nil
}

// ReadHistoryEntriesFromReader is ReadHistoryEntries over r, for evidence a
// caller already holds. The caller bounds what r can supply.
func ReadHistoryEntriesFromReader(r io.Reader) ([]Entry, error) {
	var entries []Entry
	if err := WalkHistoryEntriesFromReader(r, func(e Entry) error {
		entries = append(entries, e)
		return nil
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

// WalkEvidenceFile walks one recorder file through the evidence readers'
// secured open: it refuses a symlinked or non-regular file, refuses a torn
// final write, reads only the bytes present when the file was opened, and
// fails if the file changed during the walk. It applies the per-entry line
// limit and no aggregate budget. When raw is non-nil, every byte the walk
// reads is written to it, so a caller can bind a later read of the same file
// to the exact bytes this one verified. It returns the file identity observed
// at open.
func WalkEvidenceFile(path string, raw io.Writer, consume func(Entry) error) (os.FileInfo, error) {
	file, info, err := openRegularEvidenceFile(path, validateEvidenceFileAccess())
	if err != nil {
		return nil, fmt.Errorf("opening evidence file: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := inspectJSONLTail(file, info, file.Name(), evidenceTailValidator(nil)); err != nil {
		return nil, fmt.Errorf("reading evidence file: %w", err)
	}
	var src io.Reader = io.NewSectionReader(file, 0, info.Size())
	if raw != nil {
		src = io.TeeReader(src, raw)
	}
	_, bytesRead, err := walkEntriesFromReader(src, entryReadLimits{}, consume)
	if err != nil {
		return nil, fmt.Errorf("reading evidence file: %w", err)
	}
	if bytesRead != info.Size() {
		return nil, fmt.Errorf("reading evidence file: read %d of %d bytes", bytesRead, info.Size())
	}
	if err := ensureEvidenceFileUnchanged(file, info); err != nil {
		return nil, err
	}
	return info, nil
}

// validateHistorySessionID refuses a session ID that cannot name a shard.
// Selection compares the parsed name for equality, so a path separator would
// never match; refusing it names the mistake instead of returning nothing.
func validateHistorySessionID(sessionID string) error {
	switch {
	case sessionID == "", sessionID == ".", sessionID == "..":
		return fmt.Errorf("invalid evidence session id %q", sessionID)
	case strings.ContainsAny(sessionID, `/\`):
		return fmt.Errorf("evidence session id %q contains a path separator", sessionID)
	case !utf8.ValidString(sessionID):
		return errors.New("evidence session id is not valid UTF-8")
	}
	return nil
}

// walkSessionHistoryShards visits sessionID's shards in (sequence start,
// name) order. It holds at most window+1 shard names at a time.
func walkSessionHistoryShards(location EvidenceLocation, sessionID string, window int, visit func(SessionHistoryShard) error) error {
	if err := validateHistorySessionID(sessionID); err != nil {
		return err
	}
	if window <= 0 {
		return errors.New("session history window must be positive")
	}
	c := historyCursor{location: location, sessionID: sessionID, window: window}
	for {
		shard, ok, err := c.next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if err := visit(shard); err != nil {
			return err
		}
	}
}

// historyKey orders shards the way every evidence reader does: by parsed
// sequence start, then by name, so ties never fall to directory order.
type historyKey struct {
	name string
	seq  uint64
}

func (k historyKey) less(o historyKey) bool {
	if k.seq != o.seq {
		return k.seq < o.seq
	}
	return k.name < o.name
}

// historyCursor yields shards in order, one directory pass per window.
type historyCursor struct {
	location  EvidenceLocation
	sessionID string
	window    int

	queue   []historyKey
	more    bool
	after   *historyKey // greatest key fetched so far
	started bool
}

func (c *historyCursor) next() (SessionHistoryShard, bool, error) {
	if !c.started {
		c.started = true
		if err := c.fill(); err != nil {
			return SessionHistoryShard{}, false, err
		}
	}
	if len(c.queue) == 0 {
		return SessionHistoryShard{}, false, nil
	}
	// Look ahead before delivering the last queued shard so its Final flag is
	// known: a torn shard is recoverable only when nothing follows it.
	if len(c.queue) == 1 && c.more {
		if err := c.fill(); err != nil {
			return SessionHistoryShard{}, false, err
		}
	}
	k := c.queue[0]
	c.queue = c.queue[1:]
	return SessionHistoryShard{Name: k.name, SeqStart: k.seq, Final: len(c.queue) == 0 && !c.more}, true, nil
}

// fill lists the directory once and appends the window smallest shard keys
// after c.after. Duplicate sequence starts are refused before any shard of
// the new window is delivered, including a duplicate of the previous window's
// last shard.
func (c *historyCursor) fill() error {
	keys, more, err := scanHistoryWindow(c.location, c.sessionID, c.after, c.window)
	if err != nil {
		return fmt.Errorf("reading evidence directory: %w", err)
	}
	names := make([]string, 0, len(keys)+1)
	if c.after != nil {
		names = append(names, c.after.name)
	}
	for _, k := range keys {
		names = append(names, k.name)
	}
	if err := evidencename.CheckNoDuplicateSeqStart(names); err != nil {
		return err
	}
	c.queue = append(c.queue, keys...)
	c.more = more
	if len(keys) > 0 {
		last := keys[len(keys)-1]
		c.after = &last
	}
	return nil
}

// scanHistoryWindow returns, in order, the window smallest shard keys of
// sessionID strictly greater than after, and whether more such shards exist.
// Entries of other sessions, sidecars and unrelated files are skipped as they
// are read and never retained.
func scanHistoryWindow(location EvidenceLocation, sessionID string, after *historyKey, window int) ([]historyKey, bool, error) {
	directory, err := openEvidenceLocationDirectory(location)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = directory.Close() }()
	h := make(historyMaxHeap, 0, min(window, sessionHistoryDirBatch))
	more := false
	for {
		batch, readErr := directory.ReadDir(sessionHistoryDirBatch)
		for _, de := range batch {
			name := de.Name()
			parsed, seq, ok := evidencename.Parse(name)
			if !ok || parsed != sessionID || name != filepath.Base(name) {
				continue
			}
			k := historyKey{name: name, seq: seq}
			if after != nil && !after.less(k) {
				continue
			}
			switch {
			case len(h) < window:
				heap.Push(&h, k)
			case k.less(h[0]):
				h[0] = k
				heap.Fix(&h, 0)
				more = true
			default:
				more = true
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, false, readErr
		}
	}
	keys := []historyKey(h)
	slices.SortFunc(keys, func(a, b historyKey) int {
		switch {
		case a.less(b):
			return -1
		case b.less(a):
			return 1
		default:
			return 0
		}
	})
	return keys, more, nil
}

// historyMaxHeap keeps the greatest retained key at the root, so a smaller
// key can replace it in O(log window).
type historyMaxHeap []historyKey

func (h historyMaxHeap) Len() int           { return len(h) }
func (h historyMaxHeap) Less(i, j int) bool { return h[j].less(h[i]) }
func (h historyMaxHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *historyMaxHeap) Push(x any)        { *h = append(*h, x.(historyKey)) }
func (h *historyMaxHeap) Pop() any {
	old := *h
	k := old[len(old)-1]
	*h = old[:len(old)-1]
	return k
}

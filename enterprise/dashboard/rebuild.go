//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	ReadModelIndexFile = "read-model-index.json"
	rebuildVersion     = 1
)

type RebuildOptions struct {
	SourceDir string
	Output    string
	Now       func() time.Time
}

type ReadModelIndex struct {
	RebuildVersion int             `json:"rebuild_version"`
	RebuiltAt      time.Time       `json:"rebuilt_at"`
	Sources        []IndexSource   `json:"sources"`
	SourceRange    IndexRange      `json:"source_range"`
	EntryCount     int             `json:"entry_count"`
	Staleness      StalenessMarker `json:"staleness"`
}

type IndexSource struct {
	File       string    `json:"file"`
	SHA256     string    `json:"sha256"`
	FirstSeq   uint64    `json:"first_seq"`
	LastSeq    uint64    `json:"last_seq"`
	FirstTime  time.Time `json:"first_time"`
	LastTime   time.Time `json:"last_time"`
	EntryCount int       `json:"entry_count"`
	SessionID  string    `json:"session_id"`
}

type IndexRange struct {
	FirstTime time.Time `json:"first_time"`
	LastTime  time.Time `json:"last_time"`
	FirstSeq  uint64    `json:"first_seq"`
	LastSeq   uint64    `json:"last_seq"`
}

type StalenessMarker struct {
	CheckedAt  time.Time `json:"checked_at"`
	SourceHash string    `json:"source_hash"`
	Status     string    `json:"status"`
}

func RebuildReadModel(opts RebuildOptions) error {
	paths, err := evidencePaths(opts.SourceDir)
	if err != nil {
		return fmt.Errorf("NO SOURCE EVIDENCE: read recorder directory: %w", err)
	}
	if len(paths) == 0 {
		return errors.New("NO SOURCE EVIDENCE: recorder directory contains no evidence JSONL files; no index was written")
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	index, err := buildReadModelIndex(paths, now().UTC())
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal read-model index: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(opts.Output)), 0o750); err != nil {
		return fmt.Errorf("create read-model directory: %w", err)
	}
	if err := atomicfile.Write(opts.Output, data, 0o600); err != nil {
		return fmt.Errorf("write read-model index: %w", err)
	}
	return nil
}

func evidencePaths(sourceDir string) ([]string, error) {
	canonicalDir, err := filepath.EvalSymlinks(filepath.Clean(sourceDir))
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(canonicalDir)
	if err != nil {
		return nil, err
	}
	return filterEvidenceEntries(canonicalDir, entries)
}

func boundedEvidencePaths(sourceDir string) ([]string, error) {
	canonicalDir, err := filepath.EvalSymlinks(filepath.Clean(sourceDir))
	if err != nil {
		return nil, err
	}
	directory, err := os.Open(canonicalDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	entries, err := directory.ReadDir(maxEvidenceVerificationFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxEvidenceVerificationFiles {
		return nil, errEvidenceVerificationTooLarge
	}
	return filterEvidenceEntries(canonicalDir, entries)
}

func filterEvidenceEntries(canonicalDir string, entries []os.DirEntry) ([]string, error) {
	var paths []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "evidence-") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("source evidence %s is non-regular", entry.Name())
		}
		paths = append(paths, filepath.Join(canonicalDir, entry.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

func buildReadModelIndex(paths []string, rebuiltAt time.Time) (ReadModelIndex, error) {
	if rebuiltAt.IsZero() {
		return ReadModelIndex{}, errors.New("read-model rebuild time must not be zero")
	}
	index := ReadModelIndex{RebuildVersion: rebuildVersion, RebuiltAt: rebuiltAt}
	combined := sha256.New()
	for _, path := range paths {
		file, _, err := openRegularEvidence(path)
		if err != nil {
			return ReadModelIndex{}, fmt.Errorf("read source evidence %s: %w", filepath.Base(path), err)
		}
		data, readErr := io.ReadAll(file)
		closeErr := file.Close()
		if readErr != nil {
			return ReadModelIndex{}, fmt.Errorf("read source evidence %s: %w", filepath.Base(path), readErr)
		}
		if closeErr != nil {
			return ReadModelIndex{}, fmt.Errorf("close source evidence %s: %w", filepath.Base(path), closeErr)
		}
		parsed, err := recorder.ReadEntriesFromReader(bytes.NewReader(data))
		if err != nil {
			return ReadModelIndex{}, fmt.Errorf("parse source evidence %s: %w", filepath.Base(path), err)
		}
		if len(parsed) == 0 {
			return ReadModelIndex{}, fmt.Errorf("source evidence %s contains no entries; no index was written", filepath.Base(path))
		}
		sum := sha256.Sum256(data)
		_, _ = combined.Write([]byte(filepath.Base(path)))
		_, _ = combined.Write(sum[:])
		source := IndexSource{File: filepath.Base(path), SHA256: hex.EncodeToString(sum[:]), EntryCount: len(parsed), FirstSeq: parsed[0].Sequence, LastSeq: parsed[len(parsed)-1].Sequence, FirstTime: parsed[0].Timestamp, LastTime: parsed[len(parsed)-1].Timestamp, SessionID: parsed[0].SessionID}
		for _, entry := range parsed {
			if entry.SessionID != source.SessionID {
				return ReadModelIndex{}, fmt.Errorf("source evidence %s mixes session IDs; no index was written", source.File)
			}
			if entry.Sequence < source.FirstSeq {
				source.FirstSeq = entry.Sequence
			}
			if entry.Sequence > source.LastSeq {
				source.LastSeq = entry.Sequence
			}
			if entry.Timestamp.Before(source.FirstTime) {
				source.FirstTime = entry.Timestamp
			}
			if entry.Timestamp.After(source.LastTime) {
				source.LastTime = entry.Timestamp
			}
		}
		index.Sources = append(index.Sources, source)
		index.EntryCount += len(parsed)
	}
	first := index.Sources[0]
	index.SourceRange = IndexRange{FirstTime: first.FirstTime, LastTime: first.LastTime, FirstSeq: first.FirstSeq, LastSeq: first.LastSeq}
	for _, source := range index.Sources[1:] {
		if source.FirstTime.Before(index.SourceRange.FirstTime) {
			index.SourceRange.FirstTime = source.FirstTime
		}
		if source.LastTime.After(index.SourceRange.LastTime) {
			index.SourceRange.LastTime = source.LastTime
		}
		if source.FirstSeq < index.SourceRange.FirstSeq {
			index.SourceRange.FirstSeq = source.FirstSeq
		}
		if source.LastSeq > index.SourceRange.LastSeq {
			index.SourceRange.LastSeq = source.LastSeq
		}
	}
	index.Staleness = StalenessMarker{CheckedAt: index.RebuiltAt, SourceHash: hex.EncodeToString(combined.Sum(nil)), Status: "fresh_at_rebuild"}
	return index, nil
}

func openRegularEvidence(path string) (*os.File, os.FileInfo, error) {
	cleanPath := filepath.Clean(path)
	canonicalDir, err := filepath.EvalSymlinks(filepath.Dir(cleanPath))
	if err != nil || canonicalDir != filepath.Dir(cleanPath) {
		return nil, nil, errors.New("source evidence is outside its canonical source directory")
	}
	before, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, errors.New("source evidence is non-regular")
	}
	file, err := os.OpenFile(cleanPath, os.O_RDONLY|evidenceNoFollowFlag, 0)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, nil, errors.New("source evidence changed or is non-regular")
	}
	return file, after, nil
}

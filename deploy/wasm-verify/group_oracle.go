// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Read Go-produced receipt-group fixtures and emit direct Go verifier verdicts
// for the WASM parity suite.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type trustFixture struct {
	TrustedKeys []string `json:"trusted_keys"`
}

type groupCase struct {
	Scenario string                      `json:"scenario"`
	GroupID  string                      `json:"groupId"`
	Keys     []string                    `json:"keys"`
	Verdict  receipt.ReceiptGroupVerdict `json:"verdict"`
	Error    string                      `json:"error,omitempty"`
}

const (
	maxFixtureEntries    = 4096
	maxFixtureEntryBytes = 32 << 20
	maxFixtureTotalBytes = 128 << 20
)

func main() {
	if err := run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run owns the temporary root so every failure path removes it. Exiting from
// the middle of main would skip the deferred cleanup.
func run(args []string) error {
	if len(args) != 2 {
		return errors.New("fixture ZIP path required")
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("read fixture ZIP: %w", err)
	}
	root, err := os.MkdirTemp("", "pipelock-group-oracle-")
	if err != nil {
		return fmt.Errorf("create fixture root: %w", err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := unpackFixture(data, root); err != nil {
		return fmt.Errorf("unpack fixture: %w", err)
	}
	cases, err := verifyFixtureDirectories(root)
	if err != nil {
		return fmt.Errorf("verify fixture: %w", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(cases); err != nil {
		return fmt.Errorf("encode oracle output: %w", err)
	}
	return nil
}

// safeArchiveName accepts only a relative, slash-separated path whose every
// segment is a plain name. A ".." segment passes path.Clean when it leads the
// path, and filepath.Join would then resolve it outside the root.
func safeArchiveName(name string) bool {
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || filepath.VolumeName(name) != "" {
		return false
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return path.Clean(trimmed) == trimmed
}

func unpackFixture(data []byte, root string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if len(r.File) > maxFixtureEntries {
		return fmt.Errorf("archive has %d entries, limit %d", len(r.File), maxFixtureEntries)
	}
	cleanRoot := filepath.Clean(root)
	seen := make(map[string]struct{}, len(r.File))
	var total int64
	for _, file := range r.File {
		name := file.Name
		if !safeArchiveName(name) {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate archive path %q", name)
		}
		seen[name] = struct{}{}
		target := filepath.Join(cleanRoot, filepath.FromSlash(name))
		if rel, err := filepath.Rel(cleanRoot, target); err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("archive path %q escapes the fixture root", name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if !file.Mode().IsRegular() {
			return fmt.Errorf("non-regular archive path %q", name)
		}
		if file.UncompressedSize64 > maxFixtureEntryBytes {
			return fmt.Errorf("archive path %q is larger than %d bytes", name, maxFixtureEntryBytes)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		reader, err := file.Open()
		if err != nil {
			return err
		}
		// The declared size is attacker-controlled; bound the real read too.
		contents, readErr := io.ReadAll(io.LimitReader(reader, maxFixtureEntryBytes+1))
		closeErr := reader.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if int64(len(contents)) > maxFixtureEntryBytes {
			return fmt.Errorf("archive path %q is larger than %d bytes", name, maxFixtureEntryBytes)
		}
		total += int64(len(contents))
		if total > maxFixtureTotalBytes {
			return fmt.Errorf("archive contents exceed %d bytes", maxFixtureTotalBytes)
		}
		if err := os.WriteFile(target, contents, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func verifyFixtureDirectories(root string) ([]groupCase, error) {
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var results []groupCase
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		scenario := filepath.Join(root, dir.Name())
		trustBytes, err := os.ReadFile(filepath.Join(scenario, "trust.json"))
		if err != nil {
			return nil, err
		}
		var trust trustFixture
		if err := json.Unmarshal(trustBytes, &trust); err != nil {
			return nil, err
		}
		files, err := os.ReadDir(scenario)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if !strings.HasPrefix(file.Name(), "receipt-group-") || !strings.HasSuffix(file.Name(), "-open.json") {
				continue
			}
			groupID := strings.TrimSuffix(strings.TrimPrefix(file.Name(), "receipt-group-"), "-open.json")
			if _, err := receipt.UnmarshalReceiptGroupOpen(readFile(filepath.Join(scenario, file.Name())), trust.TrustedKeys); err != nil {
				return nil, fmt.Errorf("read group opening: %w", err)
			}
			result := receipt.VerifyReceiptGroup(scenario, groupID, trust.TrustedKeys)
			results = append(results, groupCase{Scenario: dir.Name(), GroupID: groupID, Keys: trust.TrustedKeys, Verdict: result.Verdict, Error: result.Error})
		}
	}
	return results, nil
}

func readFile(name string) []byte {
	data, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return data
}

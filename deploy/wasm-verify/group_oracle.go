// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Read Go-produced receipt-group fixtures and emit direct Go verifier verdicts
// for the WASM parity suite.
package main

import (
	"archive/zip"
	"encoding/json"
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

func main() {
	if len(os.Args) != 2 {
		fatalf("fixture ZIP path required")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatalf("read fixture ZIP: %v", err)
	}
	root, err := os.MkdirTemp("", "pipelock-group-oracle-")
	if err != nil {
		fatalf("create fixture root: %v", err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := unpackFixture(data, root); err != nil {
		fatalf("unpack fixture: %v", err)
	}
	cases, err := verifyFixtureDirectories(root)
	if err != nil {
		fatalf("verify fixture: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(cases); err != nil {
		fatalf("encode oracle output: %v", err)
	}
}

func unpackFixture(data []byte, root string) error {
	r, err := zip.NewReader(strings.NewReader(string(data)), int64(len(data)))
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(r.File))
	for _, file := range r.File {
		name := file.Name
		if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || path.Clean(strings.TrimSuffix(name, "/")) != strings.TrimSuffix(name, "/") {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate archive path %q", name)
		}
		seen[name] = struct{}{}
		target := filepath.Join(root, filepath.FromSlash(name))
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if !file.Mode().IsRegular() {
			return fmt.Errorf("non-regular archive path %q", name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		reader, err := file.Open()
		if err != nil {
			return err
		}
		contents, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
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

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

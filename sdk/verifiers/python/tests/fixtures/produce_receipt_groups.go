// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Generate actual Go-producer receipt groups used by the Python verifier tests.
// Run from the repository root:
// go run sdk/verifiers/python/tests/fixtures/produce_receipt_groups.go /path/to/empty/output
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type trustFixture struct {
	GroupID     string   `json:"group_id"`
	TrustedKeys []string `json:"trusted_keys"`
}

func generateKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, key
}

func closeGroup(dir string, key ed25519.PrivateKey, previous string) string {
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		panic(err)
	}
	template := receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: "fixture",
		Principal: "local", Actor: "pipelock",
	}
	var set *receipt.ReceiptShardSet
	if previous == "" {
		set, err = receipt.OpenInitialReceiptShardSet(template, "proxy", 2, 0)
	} else {
		set, err = receipt.OpenSuccessorReceiptShardSet(template, "proxy", 2, 0, previous)
	}
	if err != nil {
		panic(err)
	}
	opening, _ := set.Opening()
	for _, emitter := range set.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			panic(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			panic(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		panic(err)
	}
	if err := rec.Close(); err != nil {
		panic(err)
	}
	return opening.GroupID
}

func writeTrust(dir, groupID string, keys []string) {
	raw, err := json.Marshal(trustFixture{GroupID: groupID, TrustedKeys: keys})
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), raw, 0o600); err != nil {
		panic(err)
	}
}

func mustEmptyDir(path string) {
	if err := os.MkdirAll(path, 0o750); err != nil {
		panic(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		panic(err)
	}
	if len(entries) != 0 {
		panic(fmt.Sprintf("fixture output directory %q must be empty", path))
	}
}

func copyFixtureTree(source, target string, onlyMissing bool) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(target, rel)
		if info.IsDir() {
			return os.MkdirAll(dest, 0o750)
		}
		if onlyMissing {
			if _, err := os.Lstat(dest); err == nil {
				return nil
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		data, err := os.ReadFile(path) // #nosec G304 -- generated fixture path under the supplied output directory.
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o600)
	})
}

func main() {
	if len(os.Args) != 2 {
		panic("output directory required")
	}
	root := os.Args[1]
	validDir := filepath.Join(root, "group-valid")
	successorDir := filepath.Join(root, "group-successor")
	mustEmptyDir(root)
	if err := os.Mkdir(validDir, 0o750); err != nil {
		panic(err)
	}
	if err := os.Mkdir(successorDir, 0o750); err != nil {
		panic(err)
	}

	validPub, validKey := generateKey()
	validID := closeGroup(validDir, validKey, "")
	writeTrust(validDir, validID, []string{hex.EncodeToString(validPub)})

	previousPub, previousKey := generateKey()
	previousID := closeGroup(successorDir, previousKey, "")
	successorPub, successorKey := generateKey()
	successorID := closeGroup(successorDir, successorKey, previousID)
	writeTrust(successorDir, successorID, []string{
		hex.EncodeToString(previousPub), hex.EncodeToString(successorPub),
	})

	// Produce two independently valid successors of the same closed head by
	// publishing each in a copy, then combining their signed artifacts.
	duplicateDir := filepath.Join(root, "duplicate-successor")
	if err := os.Mkdir(duplicateDir, 0o750); err != nil {
		panic(err)
	}
	duplicatePub, duplicateKey := generateKey()
	duplicateID := closeGroup(duplicateDir, duplicateKey, "")
	secondCopy := filepath.Join(root, "duplicate-second-copy")
	if err := copyFixtureTree(duplicateDir, secondCopy, false); err != nil {
		panic(err)
	}
	firstPub, firstKey := generateKey()
	firstID := closeGroup(duplicateDir, firstKey, duplicateID)
	secondPub, secondKey := generateKey()
	secondID := closeGroup(secondCopy, secondKey, duplicateID)
	if err := copyFixtureTree(secondCopy, duplicateDir, true); err != nil {
		panic(err)
	}
	writeTrust(duplicateDir, firstID, []string{
		hex.EncodeToString(duplicatePub), hex.EncodeToString(firstPub), hex.EncodeToString(secondPub),
	})
	fmt.Printf("group-valid: %s\ngroup-successor: %s (after %s)\n", validID, successorID, previousID)
	fmt.Printf("duplicate-successor: %s and %s after %s\n", firstID, secondID, duplicateID)
}

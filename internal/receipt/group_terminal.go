// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// FindTerminalReceiptGroup finds the unique group of base that has no signed
// successor opening. It verifies every opening against pinned signer keys,
// then checks predecessor links and terminal candidates in memory.
func FindTerminalReceiptGroup(dir, base string, trusted []string) (string, bool, error) {
	if len(trusted) == 0 {
		return "", false, errors.New("receipt group terminal discovery requires a trusted signer key")
	}
	type openingEntry struct {
		name string
		open ReceiptGroupOpen
		hash string
	}
	// Read and verify every opening once; the successor checks below run in
	// memory so startup cost stays linear in the number of openings.
	var openings []openingEntry
	if err := walkInventoryNames(dir, func(name string) error {
		if !strings.HasPrefix(name, "receipt-group-") || !strings.HasSuffix(name, "-open.json") {
			return nil
		}
		open, hash, err := readTopologicalGroupOpen(dir, name, trusted)
		if err != nil {
			return err
		}
		openings = append(openings, openingEntry{name: name, open: open, hash: hash})
		return nil
	}); err != nil {
		return "", false, err
	}
	successorsOf := make(map[string][]openingEntry, len(openings))
	for _, entry := range openings {
		if entry.open.PreviousGroupID != "" {
			successorsOf[entry.open.PreviousGroupID] = append(successorsOf[entry.open.PreviousGroupID], entry)
		}
	}
	terminal := ""
	found := false
	multipleTerminals := false
	for _, entry := range openings {
		if entry.open.BaseSession != base {
			continue
		}
		successors := 0
		for _, other := range successorsOf[entry.open.GroupID] {
			if other.name == entry.name {
				continue
			}
			if other.open.BaseSession != base || other.open.PreviousOpenManifestSHA256 != entry.hash {
				return "", false, errors.New("receipt group successor refers to a mismatched predecessor")
			}
			successors++
			if successors > 1 {
				return "", false, errors.New("receipt group predecessor has multiple successor openings")
			}
		}
		if successors == 0 {
			if found {
				multipleTerminals = true
				continue
			}
			terminal, found = entry.open.GroupID, true
		}
	}
	if multipleTerminals {
		return "", false, errors.New("receipt group history has more than one terminal group")
	}
	return terminal, found, nil
}

func readTopologicalGroupOpen(dir, name string, trusted []string) (ReceiptGroupOpen, string, error) {
	if err := validateGroupArtifactFileName(name); err != nil || !strings.HasSuffix(name, "-open.json") {
		return ReceiptGroupOpen{}, "", fmt.Errorf("invalid receipt group opening name %q", name)
	}
	raw, err := readBoundedGroupFile(dir, name)
	if err != nil {
		return ReceiptGroupOpen{}, "", err
	}
	open, err := UnmarshalReceiptGroupOpen(raw, trusted)
	if err != nil || name != "receipt-group-"+open.GroupID+"-open.json" {
		return ReceiptGroupOpen{}, "", errors.New("receipt group opening identity or signature is invalid")
	}
	sum := sha256.Sum256(raw)
	return open, hex.EncodeToString(sum[:]), nil
}

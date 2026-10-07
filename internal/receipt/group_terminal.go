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
// successor opening. It streams names and uses repeated passes rather than
// retaining every historical group in memory. Startup happens once, so this
// bounded-memory O(groups²) search is preferable to an unbounded index.
func FindTerminalReceiptGroup(dir, base string, trusted []string) (string, bool, error) {
	if len(trusted) == 0 {
		return "", false, errors.New("receipt group terminal discovery requires a trusted signer key")
	}
	terminal := ""
	found := false
	err := walkInventoryNames(dir, func(name string) error {
		if !strings.HasPrefix(name, "receipt-group-") || !strings.HasSuffix(name, "-open.json") {
			return nil
		}
		open, hash, err := readTopologicalGroupOpen(dir, name, trusted)
		if err != nil {
			return err
		}
		if open.BaseSession != base {
			return nil
		}
		successors := 0
		if err := walkInventoryNames(dir, func(otherName string) error {
			if !strings.HasPrefix(otherName, "receipt-group-") || !strings.HasSuffix(otherName, "-open.json") || otherName == name {
				return nil
			}
			other, _, err := readTopologicalGroupOpen(dir, otherName, trusted)
			if err != nil {
				return err
			}
			if other.PreviousGroupID != open.GroupID {
				return nil
			}
			if other.BaseSession != base || other.PreviousOpenManifestSHA256 != hash {
				return errors.New("receipt group successor refers to a mismatched predecessor")
			}
			successors++
			if successors > 1 {
				return errors.New("receipt group predecessor has multiple successor openings")
			}
			return nil
		}); err != nil {
			return err
		}
		if successors == 0 {
			if found {
				return errors.New("receipt group history has more than one terminal group")
			}
			terminal, found = open.GroupID, true
		}
		return nil
	})
	return terminal, found, err
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

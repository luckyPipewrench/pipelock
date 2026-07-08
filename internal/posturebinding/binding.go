// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package posturebinding derives receipt session_open binding fields from a
// signed posture proof artifact.
package posturebinding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	// RuntimeProofEnv overrides the posture proof path used for receipt
	// session_open binding.
	RuntimeProofEnv = "PIPELOCK_POSTURE_PROOF"
	// DefaultContainRunProofPath is where `pipelock contain run` writes the
	// signed runtime posture capsule by default.
	DefaultContainRunProofPath = "/var/lib/pipelock/contain/posture/proof.json"
)

// LoadRuntime returns the posture binding for the configured runtime proof
// path. Missing proof files mean no attested containment is available and return
// the zero binding; malformed present proof files return an error so callers do
// not sign a misleading empty binding by accident.
func LoadRuntime() (receipt.PostureBinding, error) {
	path := strings.TrimSpace(os.Getenv(RuntimeProofEnv))
	if path == "" {
		path = DefaultContainRunProofPath
	}
	return LoadFile(path)
}

// LoadFile derives a receipt posture binding from a signed posture proof file.
func LoadFile(path string) (receipt.PostureBinding, error) {
	if strings.TrimSpace(path) == "" {
		return receipt.PostureBinding{}, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return receipt.PostureBinding{}, nil
		}
		return receipt.PostureBinding{}, fmt.Errorf("read posture proof: %w", err)
	}
	var capsule posture.Capsule
	if err := json.Unmarshal(data, &capsule); err != nil {
		return receipt.PostureBinding{}, fmt.Errorf("parse posture proof: %w", err)
	}
	if capsule.Evidence.Containment == nil {
		return receipt.PostureBinding{}, nil
	}
	canonical, err := json.Marshal(&capsule)
	if err != nil {
		return receipt.PostureBinding{}, fmt.Errorf("marshal posture proof: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return receipt.PostureBinding{
		CapsuleSHA256:    hex.EncodeToString(sum[:]),
		SignerKeyID:      capsule.SignerKeyID,
		ContainmentNonce: capsule.Signature,
		ContainedUID:     capsule.Evidence.Containment.TargetUID,
	}, nil
}

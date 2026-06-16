// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/secperm"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// PublishedOrchestratorPubKeyHex is the published public half of the stable
// "Pipelock Playground" demo orchestrator key.
//
// The demo signs each run's launch manifest and host-containment witness with
// the matching private key; an offline verifier checks a run against THIS key —
// looked up ahead of time from here (or the published docs), never taken from
// the bundle itself. That is what makes "verify with our published key"
// meaningful: a VERIFY OK means "signed by the key you already trust", not
// "internally consistent with a key the download handed you".
//
// It is a FIXED demo identity with no security stakes — the demo proves the
// Pipelock mechanism; the key only needs to be stable and published. It is
// generated once and never rotated, and is deliberately NOT any production
// signing key (not the license signer, not a customer key). Empty until the
// stable keypair is generated and published (see `keygen-orchestrator`).
const PublishedOrchestratorPubKeyHex = "539bda06995b228e55af68c05c41cee14b060041ff4d0c13fcf13544e922abcb"

// orchestratorKeyConfigDir/File locate the stable orchestrator PRIVATE key on
// disk. The private key is never committed (the demo key has no security stakes
// but committing any private key is still wrong); it is generated locally with
// `keygen-orchestrator` and read at run time.
const (
	orchestratorKeyConfigDir = "pipelock"
	orchestratorKeyFileName  = "playground-demo-signing.key"
)

type orchestratorKeyFile interface {
	Write([]byte) (int, error)
	Close() error
}

var openOrchestratorKeyFile = func(path string, flag int, perm os.FileMode) (orchestratorKeyFile, error) {
	return os.OpenFile(filepath.Clean(path), flag, perm) // #nosec G304 -- operator-supplied key path is cleaned and opened O_EXCL by caller.
}

// DefaultOrchestratorKeyPath returns the standard on-disk location of the stable
// orchestrator private key (e.g. ~/.config/pipelock/playground-demo-signing.key
// on Linux). It returns "" when the user config dir cannot be determined.
func DefaultOrchestratorKeyPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, orchestratorKeyConfigDir, orchestratorKeyFileName)
}

// LoadOrchestratorSigningKey reads a hex-encoded ed25519 private key from path.
// It fails closed on a missing file, unsafe Unix permissions, malformed hex, or
// wrong key length.
func LoadOrchestratorSigningKey(path string) (ed25519.PrivateKey, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read orchestrator key: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("read orchestrator key: %w", err)
	}
	if secperm.TooPermissive(info.Mode().Perm(), 0o037) {
		return nil, fmt.Errorf("orchestrator key %s has permissions %04o, want 0600 or 0640", resolved, info.Mode().Perm())
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read orchestrator key: %w", err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode orchestrator key hex: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("orchestrator key wrong size: got %d bytes, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

// OrchestratorKeyMatchesPublished reports whether priv derives the compiled
// published demo public key.
func OrchestratorKeyMatchesPublished(priv ed25519.PrivateKey) bool {
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey)) == PublishedOrchestratorPubKeyHex
}

// GenerateOrchestratorKey generates a fresh ed25519 keypair and writes the
// hex-encoded private key to path (0600), creating the parent directory (0750)
// if needed. It refuses to overwrite an existing key unless force is true, so a
// stable demo key is not accidentally rotated. It returns the hex-encoded public
// key for publishing as PublishedOrchestratorPubKeyHex.
func GenerateOrchestratorKey(path string, force bool) (pubHex string, err error) {
	if path == "" {
		return "", fmt.Errorf("orchestrator key path is empty")
	}
	if !force {
		if _, statErr := os.Stat(path); statErr == nil {
			return "", fmt.Errorf("orchestrator key already exists at %s (use --force to overwrite and rotate)", path)
		}
	}
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		return "", fmt.Errorf("generate keypair: %w", err)
	}
	cleanPath := filepath.Clean(path)
	if mkErr := os.MkdirAll(filepath.Dir(cleanPath), 0o750); mkErr != nil {
		return "", fmt.Errorf("create key dir: %w", mkErr)
	}
	data := []byte(hex.EncodeToString(priv) + "\n")
	if force {
		if wErr := atomicfile.Write(cleanPath, data, 0o600); wErr != nil {
			return "", fmt.Errorf("write orchestrator key: %w", wErr)
		}
		return hex.EncodeToString(pub), nil
	}

	f, openErr := openOrchestratorKeyFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		return "", fmt.Errorf("write orchestrator key: %w", openErr)
	}
	if _, wErr := f.Write(data); wErr != nil {
		_ = f.Close()
		_ = os.Remove(cleanPath)
		return "", fmt.Errorf("write orchestrator key: %w", wErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(cleanPath)
		return "", fmt.Errorf("write orchestrator key: %w", closeErr)
	}
	return hex.EncodeToString(pub), nil
}

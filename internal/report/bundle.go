// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Manifest describes a signed evidence bundle.
type Manifest struct {
	Files     map[string]string `json:"files"` // filename -> SHA256 hex
	Generated time.Time         `json:"generated"`
	Version   string            `json:"version"`
}

// Bundle output filenames.
const (
	fileReportHTML  = "report.html"
	fileReportJSON  = "report.json"
	fileManifest    = "manifest.json"
	dirPermissions  = 0o750
	filePermissions = 0o600
)

// WriteBundle writes report.html, report.json, and manifest.json to dir.
// If privKey is non-nil, also writes manifest.json.sig.
func WriteBundle(dir string, r *Report, privKey ed25519.PrivateKey) error {
	if err := os.MkdirAll(filepath.Clean(dir), dirPermissions); err != nil {
		return fmt.Errorf("creating bundle directory: %w", err)
	}

	// Render HTML.
	var htmlBuf bytes.Buffer
	if err := RenderHTML(&htmlBuf, r); err != nil {
		return fmt.Errorf("rendering HTML: %w", err)
	}
	htmlPath := filepath.Join(dir, fileReportHTML)
	if err := os.WriteFile(htmlPath, htmlBuf.Bytes(), filePermissions); err != nil {
		return fmt.Errorf("writing %s: %w", fileReportHTML, err)
	}

	// Render JSON.
	var jsonBuf bytes.Buffer
	if err := RenderJSON(&jsonBuf, r); err != nil {
		return fmt.Errorf("rendering JSON: %w", err)
	}
	jsonPath := filepath.Join(dir, fileReportJSON)
	if err := os.WriteFile(jsonPath, jsonBuf.Bytes(), filePermissions); err != nil {
		return fmt.Errorf("writing %s: %w", fileReportJSON, err)
	}

	// Compute SHA256 hashes.
	htmlHash := sha256.Sum256(htmlBuf.Bytes())
	jsonHash := sha256.Sum256(jsonBuf.Bytes())

	manifest := Manifest{
		Files: map[string]string{
			fileReportHTML: hex.EncodeToString(htmlHash[:]),
			fileReportJSON: hex.EncodeToString(jsonHash[:]),
		},
		Generated: r.Generated,
		Version:   r.Version,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}
	// Append newline for clean file ending.
	manifestBytes = append(manifestBytes, '\n')

	manifestPath := filepath.Join(dir, fileManifest)
	if err := os.WriteFile(manifestPath, manifestBytes, filePermissions); err != nil {
		return fmt.Errorf("writing %s: %w", fileManifest, err)
	}

	// Sign manifest if key provided; otherwise clean up stale signatures
	// from a previous signed run in the same directory.
	sigPath := manifestPath + signing.SigExtension
	if privKey != nil {
		sig, err := signing.SignFile(manifestPath, privKey)
		if err != nil {
			return fmt.Errorf("signing manifest: %w", err)
		}
		if err := signing.SaveSignature(sig, sigPath); err != nil {
			return fmt.Errorf("saving signature: %w", err)
		}
	} else {
		_ = os.Remove(sigPath) // best-effort cleanup of stale signature
	}

	return nil
}

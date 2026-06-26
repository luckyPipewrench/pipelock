// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package replaycapture

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	artifactGalleryIndexName = "gallery.json"
	artifactSignerKeyName    = "signing-key.pub"
	gallerySchemaVersion     = "pipelock.replay_gallery.v0"
)

// GalleryIndex is the top-level index the playback UI loads to enumerate
// recordings. It pins the single lab signer key for the whole gallery.
type GalleryIndex struct {
	SchemaVersion    string         `json:"schema_version"`
	GeneratedAt      string         `json:"generated_at"`
	PipelockVersion  string         `json:"pipelock_version"`
	SignerKey        string         `json:"signer_key"`
	CompletenessNote string         `json:"completeness_note"`
	Scenarios        []GalleryEntry `json:"scenarios"`
}

// GalleryEntry is one recording's index row.
type GalleryEntry struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Category        string `json:"category"`
	BenchCaseID     string `json:"bench_case_id"`
	Transport       string `json:"transport"`
	DecisiveVerdict string `json:"decisive_verdict"`
	ReceiptCount    int    `json:"receipt_count"`
	PacketDir       string `json:"packet_dir"`
	ManifestPath    string `json:"manifest_path"`
}

// GenerateResult summarizes a gallery generation run.
type GenerateResult struct {
	OutDir       string
	SignerKeyHex string
	Packets      []AssembleResult
}

// Generate runs the full publish pipeline for every scenario — capture →
// allowlist gate → assemble → manifest → verify — then writes the gallery index
// and the published public key, and finally lints the entire gallery
// fail-closed. Any failure aborts before anything is considered publishable.
func (e *Engine) Generate(scenarios []Scenario, outDir, pipelockVersion string, generatedAt time.Time) (*GenerateResult, error) {
	if err := os.MkdirAll(filepath.Clean(outDir), dirPerm); err != nil {
		return nil, fmt.Errorf("gallery dir: %w", err)
	}

	var (
		results []AssembleResult
		entries []GalleryEntry
	)

	for _, s := range scenarios {
		cs, err := e.Capture(s)
		if err != nil {
			return nil, err
		}
		res, err := AssemblePacket(cs, outDir, generatedAt)
		if err != nil {
			return nil, err
		}

		packetBytes, err := os.ReadFile(filepath.Join(res.PacketDir, artifactPacketName))
		if err != nil {
			return nil, fmt.Errorf("scenario %s: read packet: %w", s.ID, err)
		}
		manifest := BuildManifest(cs, res, packetBytes, pipelockVersion)
		if err := WriteManifest(res.PacketDir, manifest); err != nil {
			return nil, fmt.Errorf("scenario %s: %w", s.ID, err)
		}

		// Verify each packet exactly as the shipped verifier would.
		if err := VerifyPacketDir(res.PacketDir, e.pubKeyHex); err != nil {
			return nil, fmt.Errorf("scenario %s: verify: %w", s.ID, err)
		}

		results = append(results, *res)
		entries = append(entries, GalleryEntry{
			ID:              s.ID,
			Title:           s.Title,
			Category:        s.Category,
			BenchCaseID:     s.BenchCaseID,
			Transport:       s.Transport,
			DecisiveVerdict: decisiveVerdict(cs),
			ReceiptCount:    cs.ReceiptCount,
			PacketDir:       s.ID,
			ManifestPath:    filepath.Join(s.ID, artifactManifestName),
		})
	}

	if err := e.writeGalleryFiles(outDir, entries, pipelockVersion, generatedAt); err != nil {
		return nil, err
	}

	// Final fail-closed sweep over every published byte (generic markers plus
	// any operator-supplied private markers).
	if err := LintGalleryFailClosed(outDir, e.opsecMarkers); err != nil {
		return nil, err
	}

	return &GenerateResult{OutDir: outDir, SignerKeyHex: e.pubKeyHex, Packets: results}, nil
}

// writeGalleryFiles writes gallery.json and the published signer public key.
func (e *Engine) writeGalleryFiles(outDir string, entries []GalleryEntry, pipelockVersion string, generatedAt time.Time) error {
	index := GalleryIndex{
		SchemaVersion:    gallerySchemaVersion,
		GeneratedAt:      generatedAt.UTC().Format(rfc3339),
		PipelockVersion:  pipelockVersion,
		SignerKey:        e.pubKeyHex,
		CompletenessNote: completenessNote,
		Scenarios:        entries,
	}
	data, err := marshalIndentNoEscape(index)
	if err != nil {
		return fmt.Errorf("marshaling gallery index: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, artifactGalleryIndexName), data, filePerm); err != nil {
		return fmt.Errorf("writing gallery index: %w", err)
	}
	keyContent := e.pubKeyHex + "\n"
	if err := os.WriteFile(filepath.Join(outDir, artifactSignerKeyName), []byte(keyContent), filePerm); err != nil {
		return fmt.Errorf("writing signer key: %w", err)
	}
	return nil
}

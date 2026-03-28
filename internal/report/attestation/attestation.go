// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package attestation builds signed evidence objects for assess output.
package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/report/compliance"
)

// Schema version for attestation payloads.
const SchemaVersion = "1"

// DefaultTTL is the default attestation validity period.
const DefaultTTL = 30 * 24 * time.Hour // 30 days

// Input carries the minimal values needed to build an attestation.
type Input struct {
	Tool                  string
	Version               string
	BuildSHA              string
	RunID                 string
	GeneratedAt           time.Time
	TTL                   time.Duration // 0 = DefaultTTL
	LicenseTier           string
	OverallGrade          string
	OverallScore          int
	PrimaryArtifact       string
	PrimaryArtifactSHA256 string
	Compliance            []compliance.CoverageSummary
	SignerAgent           string // agent name that signed this attestation
	SignerKeyFingerprint  string // SHA-256 fingerprint of the signing public key
	BadgeSHA256           string // SHA-256 of badge.svg (empty if no badge)
}

// Attestation is the signed evidence payload emitted by assess finalize.
type Attestation struct {
	SchemaVersion         string                       `json:"schema_version"`
	Tool                  string                       `json:"tool"`
	Version               string                       `json:"version"`
	BuildSHA              string                       `json:"build_sha,omitempty"`
	RunID                 string                       `json:"run_id"`
	GeneratedAt           time.Time                    `json:"generated_at"`
	ExpiresAt             time.Time                    `json:"expires_at"`
	SignerAgent           string                       `json:"signer_agent,omitempty"`
	SignerKeyFingerprint  string                       `json:"signer_key_fingerprint,omitempty"`
	LicenseTier           string                       `json:"license_tier"`
	OverallGrade          string                       `json:"overall_grade"`
	OverallScore          int                          `json:"overall_score"`
	PrimaryArtifact       string                       `json:"primary_artifact"`
	PrimaryArtifactSHA256 string                       `json:"primary_artifact_sha256"`
	BadgeSHA256           string                       `json:"badge_sha256,omitempty"`
	Compliance            []compliance.CoverageSummary `json:"compliance,omitempty"`
	BadgeText             string                       `json:"badge_text"`
}

// KeyFingerprint computes the SHA-256 fingerprint of an Ed25519 public key.
func KeyFingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// Expired reports whether the attestation TTL has elapsed.
func (a Attestation) Expired() bool {
	return !a.ExpiresAt.IsZero() && time.Now().After(a.ExpiresAt)
}

// New builds an attestation payload from the supplied input.
func New(in Input) Attestation {
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	generated := in.GeneratedAt.UTC()
	return Attestation{
		SchemaVersion:         SchemaVersion,
		Tool:                  in.Tool,
		Version:               in.Version,
		BuildSHA:              in.BuildSHA,
		RunID:                 in.RunID,
		GeneratedAt:           generated,
		ExpiresAt:             generated.Add(ttl),
		SignerAgent:           in.SignerAgent,
		SignerKeyFingerprint:  in.SignerKeyFingerprint,
		LicenseTier:           in.LicenseTier,
		OverallGrade:          in.OverallGrade,
		OverallScore:          in.OverallScore,
		PrimaryArtifact:       in.PrimaryArtifact,
		PrimaryArtifactSHA256: in.PrimaryArtifactSHA256,
		BadgeSHA256:           in.BadgeSHA256,
		Compliance:            in.Compliance,
		BadgeText:             "Pipelock Verified",
	}
}

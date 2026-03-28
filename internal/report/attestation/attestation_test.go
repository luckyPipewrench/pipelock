// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/report/compliance"
)

func TestNewAttestation(t *testing.T) {
	now := time.Date(2026, 3, 27, 15, 0, 0, 0, time.UTC)
	a := New(Input{
		Tool:                  "pipelock",
		Version:               "2.0.0",
		BuildSHA:              "deadbeef",
		RunID:                 "run-123",
		GeneratedAt:           now,
		LicenseTier:           "assess",
		OverallGrade:          "A",
		OverallScore:          94,
		PrimaryArtifact:       "assessment.json",
		PrimaryArtifactSHA256: "abc123",
		Compliance:            []compliance.CoverageSummary{{FrameworkID: "owasp_mcp_top_10", FrameworkName: "OWASP MCP Top 10", Total: 10, Covered: 8}},
	})

	if a.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", a.SchemaVersion, SchemaVersion)
	}
	if a.BadgeText != "Pipelock Verified" {
		t.Fatalf("BadgeText = %q, want Pipelock Verified", a.BadgeText)
	}
	if a.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt must be set")
	}
	expectedExpiry := now.Add(DefaultTTL)
	if !a.ExpiresAt.Equal(expectedExpiry) {
		t.Fatalf("ExpiresAt = %v, want %v", a.ExpiresAt, expectedExpiry)
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"assessment.json"`) {
		t.Fatalf("expected primary artifact in JSON, got %s", string(data))
	}
	if !strings.Contains(string(data), `"expires_at"`) {
		t.Fatal("expected expires_at in JSON output")
	}
}

func TestNewAttestation_CustomTTL(t *testing.T) {
	now := time.Now().UTC()
	ttl := 7 * 24 * time.Hour // 7 days
	a := New(Input{
		GeneratedAt: now,
		TTL:         ttl,
	})
	if !a.ExpiresAt.Equal(now.Add(ttl)) {
		t.Fatalf("custom TTL: ExpiresAt = %v, want %v", a.ExpiresAt, now.Add(ttl))
	}
}

func TestAttestation_Expired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		a := New(Input{GeneratedAt: time.Now()})
		if a.Expired() {
			t.Fatal("fresh attestation should not be expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		a := Attestation{
			GeneratedAt: time.Now().Add(-60 * 24 * time.Hour),
			ExpiresAt:   time.Now().Add(-30 * 24 * time.Hour),
		}
		if !a.Expired() {
			t.Fatal("past-expiry attestation should be expired")
		}
	})

	t.Run("zero expiry never expires", func(t *testing.T) {
		a := Attestation{GeneratedAt: time.Now().Add(-365 * 24 * time.Hour)}
		if a.Expired() {
			t.Fatal("zero ExpiresAt should never expire")
		}
	})
}

func TestSVG(t *testing.T) {
	a := New(Input{
		GeneratedAt:     time.Now(),
		OverallGrade:    "A",
		OverallScore:    94,
		PrimaryArtifact: "assessment.json",
	})

	svg := SVG(a)
	if !strings.Contains(svg, "<svg") {
		t.Error("expected SVG element")
	}
	if !strings.Contains(svg, "Pipelock Verified") {
		t.Error("expected badge text")
	}
	if !strings.Contains(svg, "Score: 94/100") {
		t.Error("expected score in badge")
	}
}

func TestSVG_AllGrades(t *testing.T) {
	grades := []struct {
		score int
		color string
	}{
		{95, "#16a34a"}, // green
		{85, "#2563eb"}, // blue
		{75, "#ca8a04"}, // yellow
		{65, "#ea580c"}, // orange
		{50, "#dc2626"}, // red
	}

	for _, g := range grades {
		t.Run(fmt.Sprintf("score_%d", g.score), func(t *testing.T) {
			a := New(Input{
				GeneratedAt:  time.Now(),
				OverallScore: g.score,
			})
			svg := SVG(a)
			if !strings.Contains(svg, g.color) {
				t.Errorf("score %d: expected color %s in SVG", g.score, g.color)
			}
		})
	}
}

func TestSVG_EscapesHTML(t *testing.T) {
	a := Attestation{
		BadgeText:       `<script>alert("xss")</script>`,
		OverallGrade:    `"injected"`,
		PrimaryArtifact: `file&name`,
	}
	svg := SVG(a)
	if strings.Contains(svg, "<script>") {
		t.Error("SVG must escape HTML in badge text")
	}
	if strings.Contains(svg, `"injected"`) {
		t.Error("SVG must escape HTML in grade")
	}
}

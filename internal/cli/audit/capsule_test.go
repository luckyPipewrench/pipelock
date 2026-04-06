// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testConfigContent = "mode: balanced\nenforce: true\n"

func TestCapsuleCmd_DefaultsJSON(t *testing.T) {
	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var capsule PostureCapsule
	if err := json.Unmarshal([]byte(buf.String()), &capsule); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if capsule.Version != capsuleVersion {
		t.Errorf("version = %q, want %q", capsule.Version, capsuleVersion)
	}
	if capsule.Score == nil {
		t.Fatal("score should not be nil")
	}
	if capsule.ConfigHash != configHashDefaults {
		t.Errorf("config_hash = %q, want %q", capsule.ConfigHash, configHashDefaults)
	}
	if capsule.GeneratedAt.IsZero() {
		t.Error("generated_at should not be zero")
	}
	if !capsule.ExpiresAt.After(capsule.GeneratedAt) {
		t.Error("expires_at should be after generated_at")
	}
}

func TestCapsuleCmd_WriteFiles(t *testing.T) {
	dir := t.TempDir()

	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "-o", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, name := range []string{capsuleFileJSON, capsuleFileMD, capsuleFileSVG} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s should not be empty", name)
		}
	}

	output := buf.String()
	if !strings.Contains(output, capsuleFileJSON) {
		t.Error("output should mention proof.json")
	}
	if !strings.Contains(output, capsuleFileMD) {
		t.Error("output should mention proof.md")
	}
	if !strings.Contains(output, capsuleFileSVG) {
		t.Error("output should mention proof.svg")
	}
}

func TestCapsuleCmd_FormatSelection(t *testing.T) {
	dir := t.TempDir()

	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "-o", dir, "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, capsuleFileJSON)); err != nil {
		t.Errorf("proof.json should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, capsuleFileMD)); err == nil {
		t.Error("proof.md should not exist when --format json")
	}
	if _, err := os.Stat(filepath.Join(dir, capsuleFileSVG)); err == nil {
		t.Error("proof.svg should not exist when --format json")
	}
}

func TestCapsuleCmd_CIGatePass(t *testing.T) {
	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// Defaults score is modest but > 0, use threshold 1.
	cmd.SetArgs([]string{"audit", "capsule", "--json", "--ci-gate", "1"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ci-gate=1 should pass for defaults: %v", err)
	}
}

func TestCapsuleCmd_CIGateFail(t *testing.T) {
	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// Threshold of 100 should fail for defaults.
	cmd.SetArgs([]string{"audit", "capsule", "--json", "--ci-gate", "100"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("ci-gate=100 should fail for defaults")
	}
	if !strings.Contains(err.Error(), "below CI gate threshold") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCapsuleCmd_CustomExpiration(t *testing.T) {
	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "--json", "--expires", "24h"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var capsule PostureCapsule
	if err := json.Unmarshal([]byte(buf.String()), &capsule); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	diff := capsule.ExpiresAt.Sub(capsule.GeneratedAt)
	// Allow 1 second tolerance for test execution time.
	if diff < 23*time.Hour || diff > 25*time.Hour {
		t.Errorf("expected ~24h expiry, got %v", diff)
	}
}

func TestCapsuleCmd_NegativeExpires(t *testing.T) {
	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "--json", "--expires", "-1h"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("negative --expires should fail")
	}
	if !strings.Contains(err.Error(), "--expires must be > 0") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCapsuleCmd_ConfigHash(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte(testConfigContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "--json", "-c", cfgPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var capsule PostureCapsule
	if err := json.Unmarshal([]byte(buf.String()), &capsule); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	h := sha256.Sum256([]byte(testConfigContent))
	want := fmt.Sprintf("sha256:%x", h)
	if capsule.ConfigHash != want {
		t.Errorf("config_hash = %q, want %q", capsule.ConfigHash, want)
	}
}

func TestCapsuleCmd_JSONRoundTrip(t *testing.T) {
	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var first PostureCapsule
	if err := json.Unmarshal([]byte(buf.String()), &first); err != nil {
		t.Fatalf("first unmarshal failed: %v", err)
	}

	reMarshaled, err := json.MarshalIndent(first, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}

	var second PostureCapsule
	if err := json.Unmarshal(reMarshaled, &second); err != nil {
		t.Fatalf("second unmarshal failed: %v", err)
	}

	if first.Version != second.Version {
		t.Errorf("version mismatch: %q vs %q", first.Version, second.Version)
	}
	if first.Score.Percentage != second.Score.Percentage {
		t.Errorf("percentage mismatch: %d vs %d", first.Score.Percentage, second.Score.Percentage)
	}
	if first.ConfigHash != second.ConfigHash {
		t.Errorf("config_hash mismatch: %q vs %q", first.ConfigHash, second.ConfigHash)
	}
}

func TestCapsuleCmd_OutputDirCreation(t *testing.T) {
	parent := t.TempDir()
	nested := filepath.Join(parent, "sub", "dir")

	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "-o", nested, "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(nested, capsuleFileJSON)); err != nil {
		t.Errorf("proof.json should exist in nested dir: %v", err)
	}
}

func TestBadgeColor(t *testing.T) {
	tests := []struct {
		grade string
		want  string
	}{
		{testGradeA, badgeColorGreen},
		{"B", badgeColorYellowGreen},
		{"C", badgeColorYellow},
		{"D", badgeColorOrange},
		{testGradeF, badgeColorRed},
	}
	for _, tt := range tests {
		t.Run(tt.grade, func(t *testing.T) {
			got := badgeColor(tt.grade)
			if got != tt.want {
				t.Errorf("badgeColor(%q) = %q, want %q", tt.grade, got, tt.want)
			}
		})
	}
}

func TestBadgeSVGContent(t *testing.T) {
	capsule := &PostureCapsule{
		Score: &ScoreResult{
			Grade:      testGradeA,
			Percentage: 95,
		},
	}
	svg := renderCapsuleSVG(capsule)
	svgStr := string(svg)

	if !strings.Contains(svgStr, "pipelock") {
		t.Error("SVG should contain 'pipelock' label")
	}
	if !strings.Contains(svgStr, badgeColorGreen) {
		t.Error("SVG should use green color for grade A")
	}
	if !strings.Contains(svgStr, "A 95%") {
		t.Error("SVG should contain grade and percentage")
	}
}

func TestCapsuleMDContent(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	capsule := &PostureCapsule{
		Version:     capsuleVersion,
		GeneratedAt: now,
		ExpiresAt:   now.Add(defaultExpiry),
		Score: &ScoreResult{
			TotalScore: 85,
			MaxScore:   100,
			Grade:      "B",
			Percentage: 85,
			Categories: []ScoreCategory{
				{Name: "DLP", Score: 15, MaxScore: 15},
			},
			Findings: []ScoreFinding{
				{Severity: scoreSevWarning, Category: "Test", Message: "test finding"},
			},
		},
		ConfigHash:  "sha256:abc123",
		PipelockVer: "v2.1.2",
	}

	md := string(renderCapsuleMD(capsule))

	if !strings.Contains(md, "# Pipelock Security Posture") {
		t.Error("MD should have title")
	}
	if !strings.Contains(md, "85/100") {
		t.Error("MD should contain score")
	}
	if !strings.Contains(md, "sha256:abc123") {
		t.Error("MD should contain config hash")
	}
	if !strings.Contains(md, "v2.1.2") {
		t.Error("MD should contain pipelock version")
	}
	if !strings.Contains(md, "| DLP | 15 | 15 |") {
		t.Error("MD should contain category table row")
	}
	if !strings.Contains(md, "test finding") {
		t.Error("MD should contain finding message")
	}
	if !strings.Contains(md, "[warning]") {
		t.Error("MD should contain finding severity")
	}
}

func TestHashConfigFile_Defaults(t *testing.T) {
	h, err := hashConfigFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != configHashDefaults {
		t.Errorf("empty path should return %q, got %q", configHashDefaults, h)
	}
}

func TestHashConfigFile_Real(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := []byte("mode: strict\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := hashConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := sha256.Sum256(content)
	wantStr := fmt.Sprintf("sha256:%x", want)
	if h != wantStr {
		t.Errorf("hash = %q, want %q", h, wantStr)
	}
}

func TestHashConfigFile_Missing(t *testing.T) {
	_, err := hashConfigFile("/nonexistent/path/to/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseFormats(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"all", "json,md,svg", 3},
		{"json only", "json", 1},
		{"with spaces", " json , md ", 2},
		{"unknown filtered", "json,xml,md", 2},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFormats(tt.input)
			if len(got) != tt.want {
				t.Errorf("parseFormats(%q) = %d formats, want %d", tt.input, len(got), tt.want)
			}
		})
	}
}

func TestFindingIcon(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{scoreSevCritical, "\u274c"},
		{scoreSevWarning, "\u26a0\ufe0f"},
		{scoreSevInfo, "\u2139\ufe0f"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := findingIcon(tt.severity)
			if got != tt.want {
				t.Errorf("findingIcon(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestCheckCIGate(t *testing.T) {
	tests := []struct {
		name    string
		pct     int
		gate    int
		wantErr bool
	}{
		{"no gate", 50, 0, false},
		{"above threshold", 80, 70, false},
		{"at threshold", 70, 70, false},
		{"below threshold", 50, 70, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ScoreResult{Percentage: tt.pct}
			err := checkCIGate(result, tt.gate)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkCIGate(pct=%d, gate=%d) error = %v, wantErr %v",
					tt.pct, tt.gate, err, tt.wantErr)
			}
		})
	}
}

func TestCapsuleCmd_InvalidConfig(t *testing.T) {
	cmd := testRoot()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"audit", "capsule", "--json", "-c", "/nonexistent/config.yaml"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid config path")
	}
}

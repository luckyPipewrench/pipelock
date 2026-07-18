// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestEmitOverridesPreloadedContainmentWithoutAliasing(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	preloaded := testEvidenceBundle()
	preloaded.ContainLaunch = &ContainLaunchEvidence{Launcher: "old"}
	preloaded.Containment = &ContainmentEvidence{Mode: ContainmentModeBestEffortProxyEnv}
	launch := &ContainLaunchEvidence{
		Launcher:     "new",
		TargetGroups: []string{"100", "200"},
		EnvVars:      []string{"HTTP_PROXY"},
	}
	containment := &ContainmentEvidence{
		Mode:             ContainmentModeKernelNFTOwnerMatch,
		BoundaryVerified: true,
	}

	capsule, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: &preloaded,
		ContainLaunch:  launch,
		Containment:    containment,
	})
	if err != nil {
		t.Fatalf("Emit(): %v", err)
	}

	launch.TargetGroups[0] = "changed"
	launch.EnvVars[0] = "CHANGED"
	containment.Mode = "changed"
	if got := capsule.Evidence.ContainLaunch.TargetGroups[0]; got != "100" {
		t.Fatalf("capsule target group = %q, want cloned value", got)
	}
	if got := capsule.Evidence.ContainLaunch.EnvVars[0]; got != "HTTP_PROXY" {
		t.Fatalf("capsule env var = %q, want cloned value", got)
	}
	if got := capsule.Evidence.Containment.Mode; got != ContainmentModeKernelNFTOwnerMatch {
		t.Fatalf("capsule containment mode = %q, want cloned value", got)
	}
}

func TestVerifyAtZeroClockUsesWallClockAndRejectsExpiredCapsule(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule, err := Emit(config.Defaults(), Options{
		SigningKey:     priv,
		EvidenceBundle: bundlePtr(testEvidenceBundle()),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	capsule.GeneratedAt = now.Add(-2 * time.Hour)
	capsule.ExpiresAt = now.Add(-time.Hour)
	capsule.Signature = resignCapsule(t, capsule, priv)

	err = VerifyAt(capsule, priv.Public().(ed25519.PublicKey), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("VerifyAt() error = %v, want expiration rejection", err)
	}
}

func TestProofWritersRejectUnusableOutputPath(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(outputPath, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	capsule := &Capsule{}

	if _, err := WriteProofJSON(outputPath, capsule); err == nil || !strings.Contains(err.Error(), "create output directory") {
		t.Fatalf("WriteProofJSON() error = %v, want directory failure", err)
	}
	if _, err := WriteProofMarkdown(outputPath, capsule); err == nil || !strings.Contains(err.Error(), "create output directory") {
		t.Fatalf("WriteProofMarkdown() error = %v, want directory failure", err)
	}
}

func TestWriteProofMarkdownRejectsDirectoryAtDestination(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ProofMarkdownFilename), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteProofMarkdown(dir, &Capsule{}); err == nil || !strings.Contains(err.Error(), "write proof.md") {
		t.Fatalf("WriteProofMarkdown() error = %v, want atomic write failure", err)
	}
}

func TestRenderProofMarkdownIncludesContainLaunchAuditFields(t *testing.T) {
	capsule := &Capsule{
		Evidence: EvidenceBundle{
			ContainLaunch: &ContainLaunchEvidence{
				Launcher:     "contain",
				AgentUser:    "agent",
				TargetUID:    "1001",
				TargetGID:    "1002",
				TargetGroups: []string{"1002", "1003"},
				Tool:         "runner",
				Argc:         3,
				ArgvSHA256:   "argv-digest",
				CWD:          "/workspace",
				ProxyPort:    8080,
				EnvSHA256:    "env-digest",
				EnvVars:      []string{"HTTP_PROXY", "HTTPS_PROXY"},
			},
		},
	}

	got := RenderProofMarkdown(capsule)
	for _, want := range []string{
		"## Contain launch",
		"Launcher: `contain`",
		"uid `1001`",
		"Argv SHA-256: `argv-digest`",
		"Proxy port: 8080",
		"Env vars: `HTTP_PROXY`, `HTTPS_PROXY`",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("markdown missing %q:\n%s", want, got)
		}
	}
}

func TestCapsuleUnmarshalRejectsMalformedTrailingData(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{} {}`),
		[]byte(`{} {`),
	} {
		var capsule Capsule
		if err := json.Unmarshal(data, &capsule); err == nil {
			t.Fatalf("json.Unmarshal(%q) accepted trailing data", data)
		}
	}
}

func TestCollectFlightRecorderEvidenceRejectsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recorder")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.Dir = path

	_, err := collectFlightRecorderEvidence(cfg)
	if err == nil || !strings.Contains(err.Error(), "read flight recorder dir") {
		t.Fatalf("collectFlightRecorderEvidence() error = %v, want filesystem rejection", err)
	}
}

func TestCloneEvidenceBundleHandlesNilAndIndependentNestedState(t *testing.T) {
	now := time.Now().UTC()
	wantTimestamp := now
	original := EvidenceBundle{
		FlightRecorder: FlightRecorderCounts{
			LastReceiptAt:  &now,
			ScannerVerdict: map[string]VerdictCount{"dlp": {Block: 1}},
		},
		ContainLaunch: &ContainLaunchEvidence{
			TargetGroups: []string{"10"},
			EnvVars:      []string{"HTTP_PROXY"},
		},
		Containment: &ContainmentEvidence{Mode: ContainmentModeKernelNFTOwnerMatch},
	}
	cloned := cloneEvidenceBundle(original)
	original.FlightRecorder.ScannerVerdict["dlp"] = VerdictCount{Allow: 1}
	original.ContainLaunch.TargetGroups[0] = "changed"
	original.ContainLaunch.EnvVars[0] = "changed"
	original.Containment.Mode = "changed"
	*original.FlightRecorder.LastReceiptAt = now.Add(time.Hour)

	if cloned.FlightRecorder.ScannerVerdict["dlp"].Block != 1 {
		t.Fatal("scanner verdict map was aliased")
	}
	if cloned.ContainLaunch.TargetGroups[0] != "10" || cloned.ContainLaunch.EnvVars[0] != "HTTP_PROXY" {
		t.Fatal("contain launch slices were aliased")
	}
	if cloned.Containment.Mode != ContainmentModeKernelNFTOwnerMatch {
		t.Fatal("containment evidence was aliased")
	}
	if !cloned.FlightRecorder.LastReceiptAt.Equal(wantTimestamp) {
		t.Fatal("receipt timestamp was aliased")
	}
	if cloneContainLaunchEvidence(nil) != nil || cloneContainmentEvidence(nil) != nil {
		t.Fatal("nil optional evidence must remain nil")
	}
}

func TestCanonicalEncodingPropagatesNestedMarshalFailure(t *testing.T) {
	original := jsonMarshal
	defer func() { jsonMarshal = original }()
	sentinel := errors.New("encode denied")
	jsonMarshal = func(v any) ([]byte, error) {
		if s, ok := v.(string); ok && s == "blocked" {
			return nil, sentinel
		}
		return json.Marshal(v)
	}

	for _, value := range []any{
		"blocked",
		map[string]any{"blocked": true},
		map[string]any{"key": "blocked"},
		[]any{"blocked"},
	} {
		var buf bytes.Buffer
		if err := appendCanonical(&buf, value); !errors.Is(err, sentinel) {
			t.Fatalf("appendCanonical(%#v) error = %v, want sentinel", value, err)
		}
	}
}

func TestAppendCanonicalFallbackAndFloat(t *testing.T) {
	var buf bytes.Buffer
	if err := appendCanonical(&buf, 1.25); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "1.25" {
		t.Fatalf("float encoding = %q", got)
	}

	buf.Reset()
	if err := appendCanonical(&buf, struct {
		State string `json:"state"`
	}{State: "closed"}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != `{"state":"closed"}` {
		t.Fatalf("fallback encoding = %q", got)
	}
}

func TestCanonicalJSONRejectsMalformedMarshallerOutput(t *testing.T) {
	original := jsonMarshal
	defer func() { jsonMarshal = original }()
	jsonMarshal = func(any) ([]byte, error) {
		return []byte("{"), nil
	}
	if _, err := canonicalJSON("value"); err == nil {
		t.Fatal("canonicalJSON() accepted malformed encoder output")
	}
}

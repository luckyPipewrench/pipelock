// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
)

// Trust-gap regression tests for the schema-v2 evidence-integrity contract.
//
// Each test exercises one boundary condition where a finalize run could
// previously trust evidence it should not have:
//
//   - Evidence file modified between run and finalize.
//   - Evidence file deleted between run and finalize.
//   - Evidence file truncated to zero bytes.
//   - Manifest written by an older binary (schema v1, no EvidenceHashes).
//   - v2 manifest with an empty EvidenceHashes map.
//   - SkippedPrimitives claim that contradicts on-disk evidence.
//   - Extra evidence files referenced by a future schema.
//   - Empty VerifyReport awarding a perfect 100 score.
//   - Compliance frameworks attached to a partial assessment.

// completeRun runs init and run and returns the run directory.
func completeRun(t *testing.T) string {
	t.Helper()
	runDir, _ := initTestRun(t)
	if err := runAssessRun(runDir, false, nil); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}
	return runDir
}

// finalizeAndExpectError calls runAssessFinalize and asserts the error
// message contains the given substring (case-insensitive).
func finalizeAndExpectError(t *testing.T, runDir, want string) {
	t.Helper()
	err := runAssessFinalize(runDir, assessFinalizeOpts{Unsigned: true})
	if err == nil {
		t.Fatalf("expected finalize to fail; got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Errorf("error %q does not contain %q", err.Error(), want)
	}
}

func TestFinalize_RejectsModifiedEvidence(t *testing.T) {
	runDir := completeRun(t)

	// An attacker (or clumsy hand) mutates simulate.jsonl after run.
	// The recorded hash will no longer match — finalize must refuse.
	evPath := filepath.Join(runDir, "evidence", "simulate.jsonl")
	tampered := []byte(`{"name":"injected","detected":true,"category":"DLP"}` + "\n")
	if err := os.WriteFile(evPath, tampered, 0o600); err != nil {
		t.Fatalf("tampering with evidence: %v", err)
	}

	finalizeAndExpectError(t, runDir, "modified since run")
}

func TestFinalize_RejectsDeletedEvidence(t *testing.T) {
	runDir := completeRun(t)

	// Manifest still claims all four primitives ran; finalize must not
	// silently drop a section just because the file vanished.
	if err := os.Remove(filepath.Join(runDir, "evidence", "verify-install.jsonl")); err != nil {
		t.Fatalf("removing evidence: %v", err)
	}

	finalizeAndExpectError(t, runDir, "no such file")
}

func TestFinalize_RejectsTruncatedEvidence(t *testing.T) {
	runDir := completeRun(t)

	// Empty evidence file is structurally indistinguishable from a missing
	// primitive — finalize must catch both.
	evPath := filepath.Join(runDir, "evidence", "discover.jsonl")
	if err := os.WriteFile(evPath, []byte{}, 0o600); err != nil {
		t.Fatalf("truncating evidence: %v", err)
	}

	// Could hit "is empty" or "modified since run" depending on
	// statfs ordering; the integrity prefix is the stable signal.
	finalizeAndExpectError(t, runDir, "evidence integrity")
}

func TestFinalize_RejectsV1Manifest(t *testing.T) {
	runDir := completeRun(t)

	// Downgrade the manifest in-place to look like it was produced by a
	// pre-v2 binary. v2 finalize must refuse with a clear error pointing
	// at re-init, not a confusing tampering message.
	manifestPath := filepath.Join(runDir, "manifest.json")
	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m AssessManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	m.SchemaVersion = assessSchemaVersionV1
	m.EvidenceHashes = nil
	out, _ := json.MarshalIndent(&m, "", "  ")
	if err := os.WriteFile(manifestPath, out, 0o600); err != nil {
		t.Fatalf("rewriting manifest: %v", err)
	}

	finalizeAndExpectError(t, runDir, "schema_version")
}

func TestFinalize_RejectsUnsupportedManifestSchema(t *testing.T) {
	runDir := completeRun(t)

	// Future schemas may add primitives or semantics this binary cannot
	// interpret. Do not treat "has evidence_hashes" as enough to finalize.
	manifestPath := filepath.Join(runDir, "manifest.json")
	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m AssessManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	m.SchemaVersion = "99"
	out, _ := json.MarshalIndent(&m, "", "  ")
	if err := os.WriteFile(manifestPath, out, 0o600); err != nil {
		t.Fatalf("rewriting manifest: %v", err)
	}

	finalizeAndExpectError(t, runDir, "unsupported manifest schema_version")
}

func TestFinalize_RejectsManifestWithoutEvidenceHashes(t *testing.T) {
	runDir := completeRun(t)

	manifestPath := filepath.Join(runDir, "manifest.json")
	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m AssessManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	m.EvidenceHashes = nil
	out, _ := json.MarshalIndent(&m, "", "  ")
	if err := os.WriteFile(manifestPath, out, 0o600); err != nil {
		t.Fatalf("rewriting manifest: %v", err)
	}

	finalizeAndExpectError(t, runDir, "missing evidence_hashes")
}

func TestFinalize_RejectsSkippedClaimContradictingDisk(t *testing.T) {
	runDir := completeRun(t)

	// Lie about what was skipped: claim verify-install was skipped while
	// its evidence file (and hash) are still present on disk.
	manifestPath := filepath.Join(runDir, "manifest.json")
	data, _ := os.ReadFile(filepath.Clean(manifestPath))
	var m AssessManifest
	_ = json.Unmarshal(data, &m)
	m.SkippedPrimitives = []string{primitiveVerifyInstall}
	out, _ := json.MarshalIndent(&m, "", "  ")
	if err := os.WriteFile(manifestPath, out, 0o600); err != nil {
		t.Fatalf("rewriting manifest: %v", err)
	}

	// --allow-partial avoids the "skipped without partial" gate so we
	// reach the integrity check.
	err := runAssessFinalize(runDir, assessFinalizeOpts{Unsigned: true, AllowPartial: true})
	if err == nil {
		t.Fatal("expected finalize to fail; got nil")
	}
	if !strings.Contains(err.Error(), "listed as skipped") {
		t.Errorf("error %q does not flag skipped/hash contradiction", err.Error())
	}
}

func TestFinalize_RejectsUnknownEvidenceFile(t *testing.T) {
	runDir := completeRun(t)

	// A future schema might add a new primitive. Today's binary refuses
	// to finalize a manifest that references an evidence file name it
	// does not know — prevents accidental "I trust whatever the manifest
	// says" behavior.
	manifestPath := filepath.Join(runDir, "manifest.json")
	data, _ := os.ReadFile(filepath.Clean(manifestPath))
	var m AssessManifest
	_ = json.Unmarshal(data, &m)
	if m.EvidenceHashes == nil {
		m.EvidenceHashes = map[string]string{}
	}
	m.EvidenceHashes["future-primitive.jsonl"] = "deadbeef"
	out, _ := json.MarshalIndent(&m, "", "  ")
	if err := os.WriteFile(manifestPath, out, 0o600); err != nil {
		t.Fatalf("rewriting manifest: %v", err)
	}

	finalizeAndExpectError(t, runDir, "unknown evidence file")
}

func TestFinalize_AcceptsValidV2Run(t *testing.T) {
	// Sanity check — the integrity gate must not break the happy path.
	runDir := completeRun(t)
	if err := runAssessFinalize(runDir, assessFinalizeOpts{Unsigned: true}); err != nil {
		t.Fatalf("happy-path finalize failed: %v", err)
	}

	// EvidenceHashes recorded for all four primitives (none skipped).
	m := readTestManifest(t, runDir)
	want := []string{
		"simulate.jsonl",
		"audit-score.jsonl",
		"verify-install.jsonl",
		"discover.jsonl",
	}
	for _, name := range want {
		if _, ok := m.EvidenceHashes[name]; !ok {
			t.Errorf("EvidenceHashes missing %s", name)
		}
	}
	if m.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", m.SchemaVersion, assessSchemaVersion)
	}
}

func TestScoreDeploymentVerification_EmptyChecksDoesNotAward100(t *testing.T) {
	// Before v2, an empty VerifyReport with zero checks was scored 100/100
	// (all checks N/A). Combined with the old fail-open evidence path,
	// a corrupt verify-install.jsonl could become a perfect 30% section.
	// Empty Checks now produces MaxScore=0, excluding the section from
	// the weighted denominator instead.
	section := scoreDeploymentVerification(&diag.VerifyReport{})
	if section.MaxScore != 0 {
		t.Errorf("MaxScore = %d, want 0 for empty-checks report", section.MaxScore)
	}
	if section.Score != 0 {
		t.Errorf("Score = %d, want 0", section.Score)
	}
	if section.Grade != assessGradeF {
		t.Errorf("Grade = %q, want %q", section.Grade, assessGradeF)
	}
}

func TestSynthesizeAssessment_RedactsConfigFilePath(t *testing.T) {
	// manifest.json on disk keeps the absolute config path so run and
	// re-finalize can re-read and hash the file. The Assessment embedded
	// into assessment.json (and signed via attestation) is the shared
	// artifact and must basename the path so customers reading a signed
	// bundle cannot infer where the assessment was run.
	cases := []struct {
		name, input, want string
	}{
		{"absolute path", "/home/operator/configs/pipelock.yaml", "pipelock.yaml"},
		{"defaults sentinel preserved", configLabelDefaults, configLabelDefaults},
		{"empty preserved", "", ""},
		{"relative path basenamed", "configs/balanced.yaml", "balanced.yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := AssessManifest{
				SchemaVersion: assessSchemaVersion,
				ConfigFile:    c.input,
			}
			a := synthesizeAssessment(m, AssessSources{})
			if a.Manifest.ConfigFile != c.want {
				t.Errorf("Manifest.ConfigFile = %q, want %q", a.Manifest.ConfigFile, c.want)
			}
		})
	}
}

func TestSynthesizeAssessment_PartialOmitsCompliance(t *testing.T) {
	// AllowPartial assessments cannot honestly claim framework coverage.
	// shouldAttachCompliance must report a reason and synthesize must
	// leave the Compliance slice empty while recording the why in the
	// manifest carried by the Assessment output.
	m := AssessManifest{
		SchemaVersion: assessSchemaVersion,
		AllowPartial:  true,
	}
	a := synthesizeAssessment(m, AssessSources{})
	if len(a.Compliance) != 0 {
		t.Errorf("partial assessment attached %d frameworks, want 0", len(a.Compliance))
	}
	if a.Manifest.ComplianceOmittedReason == "" {
		t.Error("ComplianceOmittedReason must be set on partial assessments")
	}
}

func TestShortHash(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"abcdef012345", "abcdef012345"}, // exactly 12 — boundary
		{"abcdef0123456789", "abcdef012345"},
		{"deadbeef" + strings.Repeat("0", 56), "deadbeef0000"},
	}
	for _, c := range cases {
		if got := shortHash(c.in); got != c.want {
			t.Errorf("shortHash(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoadSigningIdentity_AgentResolutionError(t *testing.T) {
	// Exercise the error wrapping path: an empty agent name with no
	// PIPELOCK_AGENT env and no fallback yields a ResolveAgentName error,
	// which loadSigningIdentity must wrap with the "resolving agent"
	// prefix so the operator can tell which step failed.
	t.Setenv("PIPELOCK_AGENT", "")
	id, err := loadSigningIdentity(assessFinalizeOpts{Agent: ""})
	if err == nil {
		t.Fatalf("expected error from missing agent name; got id=%+v", id)
	}
	if !strings.Contains(err.Error(), "resolving agent") {
		t.Errorf("error %q lacks 'resolving agent' wrapper", err.Error())
	}
}

func TestSynthesizeAssessment_SkippedOmitsCompliance(t *testing.T) {
	m := AssessManifest{
		SchemaVersion:     assessSchemaVersion,
		SkippedPrimitives: []string{primitiveDiscover},
	}
	a := synthesizeAssessment(m, AssessSources{})
	if len(a.Compliance) != 0 {
		t.Errorf("skipped-primitive assessment attached %d frameworks, want 0", len(a.Compliance))
	}
	if !strings.Contains(a.Manifest.ComplianceOmittedReason, "skipped primitives") {
		t.Errorf("ComplianceOmittedReason = %q, want substring %q", a.Manifest.ComplianceOmittedReason, "skipped primitives")
	}
}

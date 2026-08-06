// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeProvenanceFixtureFile marshals a fixture to a temp file and returns its path.
func writeProvenanceFixtureFile(t *testing.T, fixture provenanceFixture) string {
	t.Helper()
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunProvenanceRequiresExplicitIncompleteOptIn(t *testing.T) {
	path := writeProvenanceFixtureFile(t, validProvenanceFixture(t, "A💩B", 1, 5))

	var out bytes.Buffer
	if err := runProvenance(&out, path, false); err == nil {
		t.Fatal("runProvenance returned success for an incomplete report")
	}

	var report provenanceStageReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("stdout was not a provenance report: %v (%q)", err, out.String())
	}
	if report.Signature != "verified" || report.Overall == "invalid" {
		t.Fatalf("report = %+v", report)
	}

	out.Reset()
	if err := runProvenance(&out, path, true); err != nil {
		t.Fatalf("runProvenance with --allow-incomplete returned %v", err)
	}
}

func TestRunProvenanceRejectsUnreadableFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")

	var out bytes.Buffer
	err := runProvenance(&out, missing, false)
	if err == nil {
		t.Fatal("runProvenance accepted a missing fixture path")
	}
	if !strings.Contains(err.Error(), "read provenance fixture") {
		t.Fatalf("error = %v, want a read failure", err)
	}
	if out.Len() != 0 {
		t.Fatalf("wrote %q to stdout for an unreadable fixture", out.String())
	}
}

func TestRunProvenanceRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := runProvenance(&out, path, false)
	if err == nil {
		t.Fatal("runProvenance accepted malformed JSON")
	}
	if !strings.Contains(err.Error(), "decode provenance fixture") {
		t.Fatalf("error = %v, want a decode failure", err)
	}
	var report provenanceStageReport
	if decodeErr := json.Unmarshal(out.Bytes(), &report); decodeErr != nil {
		t.Fatalf("stdout was not a staged rejection: %v (%q)", decodeErr, out.String())
	}
	if report.FailureStage != "proof_structure" || report.Overall != "invalid" {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunProvenanceRejectsDuplicateEnvelopeKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "duplicate.json")
	data, err := json.Marshal(validProvenanceFixture(t, "view", 0, 4))
	if err != nil {
		t.Fatal(err)
	}
	format := []byte(`"format":"` + provenanceFixtureFormat + `"`)
	replacement := append([]byte{}, format...)
	replacement = append(replacement, ',')
	replacement = append(replacement, format...)
	data = bytes.Replace(data, format, replacement, 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runProvenance(&out, path, false); err == nil {
		t.Fatal("runProvenance accepted a duplicate fixture key")
	}
	var report provenanceStageReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FailureStage != "proof_structure" {
		t.Fatalf("report = %+v", report)
	}
}

// A structurally rejected fixture must still PRINT its staged report before the
// command fails. An operator needs to see which stage rejected the proof, not
// just a non-zero exit.
func TestRunProvenanceReportsStageThenFailsForInvalidFixture(t *testing.T) {
	fixture := validProvenanceFixture(t, "view", 0, 4)
	fixture.Format = "pipelock-evidence-provenance-verification-fixture/v-wrong"
	path := writeProvenanceFixtureFile(t, fixture)

	var out bytes.Buffer
	err := runProvenance(&out, path, false)
	if err == nil {
		t.Fatal("runProvenance accepted a fixture with an unknown format")
	}
	if !strings.Contains(err.Error(), "proof_structure") {
		t.Fatalf("error = %v, want the failing stage named", err)
	}

	var report provenanceStageReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("no staged report printed before failure: %v (%q)", err, out.String())
	}
	if report.Overall != "invalid" {
		t.Fatalf("report.Overall = %q, want invalid", report.Overall)
	}
}

func TestVerifyProvenanceFixtureRejectsEmptyEntries(t *testing.T) {
	fixture := validProvenanceFixture(t, "view", 0, 4)
	fixture.Entries = nil

	report := verifyProvenanceFixture(fixture)
	if report.Overall != "invalid" || report.FailureStage != "proof_structure" {
		t.Fatalf("report = %+v, want invalid at proof_structure", report)
	}
}

func TestVerifyProvenanceFixtureRejectsMalformedPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"not hex", "zzzz"},
		{"wrong length", "aabbcc"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := validProvenanceFixture(t, "view", 0, 4)
			fixture.Verification.SignerPublicKeyHex = tc.key

			report := verifyProvenanceFixture(fixture)
			if report.Signature != "invalid" || report.FailureStage != "signature" {
				t.Fatalf("report = %+v, want signature invalid", report)
			}
		})
	}
}

func TestProvenanceCmdWiring(t *testing.T) {
	path := writeProvenanceFixtureFile(t, validProvenanceFixture(t, "A💩B", 1, 5))

	cmd := newProvenanceCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--allow-incomplete", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("command returned %v, want nil", err)
	}
	if !strings.Contains(out.String(), `"signature":"verified"`) &&
		!strings.Contains(out.String(), `"signature": "verified"`) {
		t.Fatalf("command output did not carry the staged report: %q", out.String())
	}
}

func TestAllowIncompleteDoesNotAcceptInvalidFixture(t *testing.T) {
	fixture := validProvenanceFixture(t, "view", 0, 4)
	fixture.Format = "unsupported"
	path := writeProvenanceFixtureFile(t, fixture)

	var out bytes.Buffer
	if err := runProvenance(&out, path, true); err == nil {
		t.Fatal("--allow-incomplete accepted an invalid fixture")
	}
}

func TestProvenanceCmdRequiresExactlyOneArgument(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		cmd := newProvenanceCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)

		if err := cmd.Execute(); err == nil {
			t.Fatalf("command accepted %d arguments", len(args))
		}
	}
}

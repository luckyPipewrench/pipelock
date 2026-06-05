// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLintGallery_RealGalleryIsClean generates the full gallery and proves the
// linter finds nothing to redact — the strongest evidence the artifacts are
// public-safe by construction.
func TestLintGallery_RealGalleryIsClean(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	outDir := t.TempDir()

	if _, err := eng.Generate(DefaultScenarios(), outDir, "v2.7.0-test", fixedStamp()); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	findings, err := LintGallery(outDir, nil)
	if err != nil {
		t.Fatalf("LintGallery: %v", err)
	}
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("unexpected finding: %s", f)
		}
	}
}

func TestScanBytes_CatchesViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		rule string
	}{
		{"private ip 10/8", `"host": "10.0.0.5"`, "private-ip"},
		{"private ip 192.168", `192.168.1.5`, "private-ip"}, // OPSEC-OK generic RFC1918 fixture, not real infra
		{"private ipv6 ula", `"host": "fd00::1"`, "private-ipv6"},
		{"private ipv6 link local", `"host": "fe80::1"`, "private-ipv6"},
		{"loopback ip 127", `"target": "http://127.0.0.1:44919/v1/records/42"`, "loopback-ip"},
		{"loopback ip v6", `"target": "http://[::1]:44919/v1/records/42"`, "loopback-ip"},
		{"home path", `/home/operator/dev/project`, "private-infra"},
		{"config path", `loaded .config/pipelock/local.yaml`, "private-infra"},
		{"raw aws key", `token=` + SyntheticAWSKey(), "raw-secret-shape"},
		{"overclaim unbreakable", `Pipelock makes agents unbreakable`, "overclaim"},
		{"overclaim hipaa", `HIPAA compliant proof`, "overclaim"},
		{"overclaim real attack", `watch a real attack live`, "overclaim"},
		{"overclaim completeness", `this is complete session truth`, "overclaim"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := scanBytes("test.txt", []byte(tc.in), nil)
			if !hasRule(findings, tc.rule) {
				t.Fatalf("expected rule %q in findings for %q, got %v", tc.rule, tc.in, findings)
			}
		})
	}
}

func TestScanBytes_FailsClosedOnOversizedLine(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("a", 1024*1024+1)
	findings := scanBytes("packet.json", []byte(oversized), nil)
	if !hasRule(findings, "scan-error") {
		t.Fatalf("expected scan-error for oversized line, got %v", findings)
	}
}

// TestScanBytes_AllowsSafeAddresses proves reserved fixture hosts, the exact
// metadata target, and RFC 5737 documentation addresses are NOT flagged — they
// are intentional, public-safe lab targets.
func TestScanBytes_AllowsSafeAddresses(t *testing.T) {
	t.Parallel()

	safe := []string{
		`"target": "http://records.fixture.test:44919/v1/records/42"`,
		`"target": "http://169.254.169.254/latest/meta-data/"`,
		`"target": "https://203.0.113.10/x"`,
		`"destination_class": "read-only lab documentation endpoint"`,
	}
	for _, line := range safe {
		findings := scanBytes("test.txt", []byte(line), nil)
		if len(findings) != 0 {
			t.Errorf("expected %q clean, got %v", line, findings)
		}
	}
}

// TestSupplementalMarkers proves operator-private markers (loaded from an
// external file, never the repo) are enforced in addition to the generic set.
func TestSupplementalMarkers(t *testing.T) {
	t.Parallel()

	// No private name is hardcoded in the source: a host that is only a marker
	// via the supplemental file is clean without it.
	const privateHost = "internal-host.example-corp.test"
	if findings := scanBytes("test.txt", []byte("reach "+privateHost), nil); len(findings) != 0 {
		t.Fatalf("expected clean without supplemental markers, got %v", findings)
	}

	markerFile := filepath.Join(t.TempDir(), "opsec.txt")
	if err := os.WriteFile(markerFile, []byte("# private\n"+privateHost+"\n\n"), filePerm); err != nil {
		t.Fatal(err)
	}
	markers, err := LoadSupplementalMarkers(markerFile)
	if err != nil {
		t.Fatalf("LoadSupplementalMarkers: %v", err)
	}
	findings := scanBytes("test.txt", []byte("reach "+privateHost), markers)
	if !hasRule(findings, "opsec-supplemental") {
		t.Errorf("expected supplemental marker to flag %q, got %v", privateHost, findings)
	}

	// Empty path and missing file both yield no markers, no error.
	if m, err := LoadSupplementalMarkers(""); err != nil || m != nil {
		t.Errorf("empty path: m=%v err=%v", m, err)
	}
	if m, err := LoadSupplementalMarkers(filepath.Join(t.TempDir(), "absent")); err != nil || m != nil {
		t.Errorf("missing file: m=%v err=%v", m, err)
	}
}

func TestLoadSupplementalMarkers_RejectsOversizedLine(t *testing.T) {
	t.Parallel()

	markerFile := filepath.Join(t.TempDir(), "opsec.txt")
	if err := os.WriteFile(markerFile, []byte(strings.Repeat("a", 1024*1024+1)), filePerm); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSupplementalMarkers(markerFile); err == nil {
		t.Fatalf("expected oversized marker file to fail closed")
	}
}

func hasRule(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The artifact linter is the mechanical pre-publish gate (launch gate #10). It
// sweeps every rendered byte of every artifact — packet.json, evidence.jsonl,
// manifest.json, summary.md, verifier.txt — for private paths, real
// infrastructure hosts/IPs, raw secret shapes, and overclaim phrases, and blocks
// publication on any hit. It is the dry-run artifact audit made automatic, and a
// backstop behind the allowlist and envelope gates (defense-in-depth: different
// failure surface).

// privateIPRE matches RFC 1918 private ranges (real infrastructure). It
// deliberately does NOT match link-local (169.254/16, which includes the
// intentional cloud-metadata SSRF target) or the RFC 5737 documentation ranges,
// all of which are safe to publish.
var privateIPRE = regexp.MustCompile(
	`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}` +
		`|192\.168\.\d{1,3}\.\d{1,3}` +
		`|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`,
)

// privateIPv6RE catches local IPv6 ranges that should never appear in a public
// gallery artifact. There is no IPv6 metadata scenario in the launch gallery.
var privateIPv6RE = regexp.MustCompile(`(?i)\b(?:f[cd][0-9a-f]{2}:|fe80:)`)

// loopbackIPRE catches local fixture literals. The rig may use loopback behind
// dns.host_overrides, but published artifacts should carry reserved hostnames,
// not local listener addresses.
var loopbackIPRE = regexp.MustCompile(`\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\[?::1\]?`)

// privateInfraMarkers are GENERIC, case-insensitive substrings that betray a
// leaked local filesystem path or the internal agent header. They are
// deliberately generic: this is a PUBLIC repo, so operator-specific host,
// domain, or account names must NOT be hardcoded here (a committed banlist of
// private names is itself a disclosure). Operator-specific markers load at
// runtime from an external file via LoadSupplementalMarkers — kept out of the
// repo. Private IPs are matched by privateIPRE, not by name.
var privateInfraMarkers = []string{
	"/home/",
	"/users/",
	".config/pipelock",
	"x-pipelock-agent", // the internal header name should not surface in artifacts
}

// LoadSupplementalMarkers reads operator-specific OPSEC markers (one per line,
// blank lines and # comments ignored) from path. These never live in the repo;
// the path typically points at a private 0600 file. A missing path returns nil
// markers and no error, so the gate degrades to generic-only.
func LoadSupplementalMarkers(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading opsec markers: %w", err)
	}
	var markers []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		markers = append(markers, strings.ToLower(line))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning opsec markers: %w", err)
	}
	return markers, nil
}

// overclaimMarkers are banned marketing phrases. The gallery must claim
// "verified mediated decisions", never certification, unbreakability, or
// "real/live attack" (the recordings are curated synthetic lab scenarios).
var overclaimMarkers = []string{
	"unbreakable",
	"hipaa",
	"compliance",
	"compliant",
	"certified",
	"certification",
	"100% secure",
	"safe ai",
	"real attack",
	"live attack",
	"complete session truth",
	"transcript is signed",
	"guaranteed",
}

// Finding is one linter hit.
type Finding struct {
	File  string
	Line  int
	Rule  string
	Match string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d [%s] %q", f.File, f.Line, f.Rule, f.Match)
}

// LintArtifacts scans every regular file directly inside dir and returns all
// findings. extraMarkers are operator-specific OPSEC substrings checked in
// addition to the generic set. An empty slice means the directory is clean.
func LintArtifacts(dir string, extraMarkers []string) ([]Finding, error) {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return nil, fmt.Errorf("reading artifact dir: %w", err)
	}
	var findings []Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), readErr)
		}
		findings = append(findings, scanBytes(e.Name(), data, extraMarkers)...)
	}
	return findings, nil
}

// LintGallery scans the top-level gallery files and every packet subdirectory
// under root, returning all findings across the gallery.
func LintGallery(root string, extraMarkers []string) ([]Finding, error) {
	topLevel, err := LintArtifacts(root, extraMarkers)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("reading gallery root: %w", err)
	}
	findings := topLevel
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, subErr := LintArtifacts(filepath.Join(root, e.Name()), extraMarkers)
		if subErr != nil {
			return nil, subErr
		}
		findings = append(findings, sub...)
	}
	return findings, nil
}

// LintGalleryFailClosed scans the gallery and returns a non-nil error listing
// every finding when anything is found. This is the publish gate.
func LintGalleryFailClosed(root string, extraMarkers []string) error {
	findings, err := LintGallery(root, extraMarkers)
	if err != nil {
		return err
	}
	return findingsError(findings)
}

func findingsError(findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.String())
	}
	return fmt.Errorf("artifact linter blocked publish (%d findings):\n%s", len(findings), strings.Join(lines, "\n"))
}

// scanBytes applies every rule to one file's contents, line by line.
func scanBytes(file string, data []byte, extraMarkers []string) []Finding {
	var findings []Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		lower := strings.ToLower(line)

		if m := secretShapeRE.FindString(line); m != "" {
			findings = append(findings, Finding{file, lineNo, "raw-secret-shape", m})
		}
		if m := privateIPRE.FindString(line); m != "" {
			findings = append(findings, Finding{file, lineNo, "private-ip", m})
		}
		if m := privateIPv6RE.FindString(line); m != "" {
			findings = append(findings, Finding{file, lineNo, "private-ipv6", m})
		}
		if m := loopbackIPRE.FindString(line); m != "" {
			findings = append(findings, Finding{file, lineNo, "loopback-ip", m})
		}
		for _, marker := range privateInfraMarkers {
			if strings.Contains(lower, marker) {
				findings = append(findings, Finding{file, lineNo, "private-infra", marker})
			}
		}
		for _, marker := range extraMarkers {
			if strings.Contains(lower, marker) {
				findings = append(findings, Finding{file, lineNo, "opsec-supplemental", marker})
			}
		}
		for _, marker := range overclaimMarkers {
			if strings.Contains(lower, marker) {
				findings = append(findings, Finding{file, lineNo, "overclaim", marker})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		findings = append(findings, Finding{file, lineNo + 1, "scan-error", err.Error()})
	}
	return findings
}

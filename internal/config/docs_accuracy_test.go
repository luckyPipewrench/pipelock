// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

var markdownLinkPattern = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

func TestDocsDeclareLiveStatsAndDefaults(t *testing.T) {
	t.Parallel()

	root := repoRootForDocsAccuracy(t)

	t.Run("configuration.md", func(t *testing.T) {
		configDoc := readDocAccuracyFile(t, root, "docs/configuration.md")
		mustContain(t, configDoc, "request_body_scanning:\n  enabled: true")
		mustContain(t, configDoc, "| `enabled` | `true` | Enable request body/header DLP scanning")
		mustContain(t, configDoc, "Omitting `request_body_scanning.enabled` or `request_body_scanning.scan_headers` defaults both to `true`")
		mustNotContain(t, configDoc, "omitting the field from your YAML file gives `false`")
	})

	t.Run("SECURITY.md", func(t *testing.T) {
		securityPolicy := readDocAccuracyFile(t, root, "SECURITY.md")
		mustContain(t, securityPolicy, "| 3.x | Yes |")
		mustNotContain(t, securityPolicy, "| 2.x | Yes |")
	})

	t.Run("AGENTS.md", func(t *testing.T) {
		agentDoc := readDocAccuracyFile(t, root, "AGENTS.md")
		// Derive the DLP count from the live canonical source (same as make stats /
		// TestCanonicalStats) so the doc must agree with reality, not a frozen
		// literal. Hardcoding "65" here would let the doc rot when patterns are
		// added (the count ratchets up) and would fail a *correct* doc update.
		dlpCount := len(Defaults().DLP.Patterns)
		mustContain(t, agentDoc, fmt.Sprintf("DLP (%d built-in credential patterns", dlpCount))
		mustContain(t, agentDoc, "Path entropy analysis")
		mustContain(t, agentDoc, "Subdomain entropy analysis")
		mustContain(t, agentDoc, "Run `make stats` before citing the current direct-dependency count")
		mustNotContain(t, agentDoc, "48 regex patterns")
		mustNotContain(t, agentDoc, "20 direct dependencies")
	})

	t.Run("docs/guides/block-reason-header.md", func(t *testing.T) {
		blockReasonGuide := readDocAccuracyFile(t, root, "docs/guides/block-reason-header.md")
		mustContain(t, blockReasonGuide, "canonical 36-character hyphenated UUIDv7")
		mustContain(t, blockReasonGuide, "live receipt `action_id` values use the UUIDv7 form")
		mustNotContain(t, blockReasonGuide, "reserved for a 26-character Crockford-base32 ULID")
	})

	t.Run("docs/specs/block-reason-header.md", func(t *testing.T) {
		blockReasonSpec := readDocAccuracyFile(t, root, "docs/specs/block-reason-header.md")
		mustContain(t, blockReasonSpec, "production emit sites are shipped")
		mustContain(t, blockReasonSpec, "production-path matrix test")
		mustNotContain(t, blockReasonSpec, "it is not currently emitted on production blocks")
		mustNotContain(t, blockReasonSpec, "The follow-up transport PR wires the header")
	})

	t.Run("docs/specs/receipt-prior-art-mapping.md", func(t *testing.T) {
		priorArt := readDocAccuracyFile(t, root, "docs/specs/receipt-prior-art-mapping.md")
		mustContain(t, priorArt, "response header (opaque receipt ID)")
		mustContain(t, priorArt, "may carry a receipt ID")
		mustNotContain(t, priorArt, "response header (opaque ULID receipt ID)")
	})
}

func TestDocsLocalLinksResolve(t *testing.T) {
	t.Parallel()

	root := repoRootForDocsAccuracy(t)
	var docs []string
	for _, top := range []string{"README.md", "CONTRIBUTING.md", "GOVERNANCE.md", "SECURITY.md"} {
		docs = append(docs, filepath.Join(root, top))
	}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".md") {
			docs = append(docs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk documentation: %v", err)
	}
	slices.Sort(docs)

	anchorCache := make(map[string]map[string]struct{}, len(docs))
	for _, doc := range docs {
		body, readErr := os.ReadFile(filepath.Clean(doc))
		if readErr != nil {
			t.Fatalf("read %s: %v", doc, readErr)
		}
		for _, match := range markdownLinkPattern.FindAllStringSubmatch(string(body), -1) {
			target := strings.Trim(match[1], "<>")
			if target == "" || strings.HasPrefix(target, "http://") ||
				strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") ||
				strings.HasPrefix(target, "data:") {
				continue
			}

			pathPart, fragment, _ := strings.Cut(target, "#")
			targetPath := doc
			if pathPart != "" {
				if strings.HasPrefix(pathPart, "/") {
					// Root-relative website routes are not repository files.
					continue
				}
				targetPath = filepath.Clean(filepath.Join(filepath.Dir(doc), pathPart))
				withinRoot, relErr := filepath.Rel(root, targetPath)
				if relErr != nil || withinRoot == ".." || strings.HasPrefix(withinRoot, ".."+string(filepath.Separator)) {
					t.Errorf("%s: local link escapes repository: %s", relativeDocPath(root, doc), target)
					continue
				}
				if _, statErr := os.Stat(targetPath); statErr != nil {
					t.Errorf("%s: local link target does not exist: %s", relativeDocPath(root, doc), target)
					continue
				}
			}

			if fragment == "" || !strings.EqualFold(filepath.Ext(targetPath), ".md") {
				continue
			}
			anchors, ok := anchorCache[targetPath]
			if !ok {
				anchors = markdownHeadingAnchors(t, targetPath)
				anchorCache[targetPath] = anchors
			}
			if _, ok := anchors[strings.ToLower(fragment)]; !ok {
				t.Errorf("%s: Markdown anchor does not exist: %s", relativeDocPath(root, doc), target)
			}
		}
	}
}

func markdownHeadingAnchors(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read anchor target %s: %v", path, err)
	}

	anchors := make(map[string]struct{})
	counts := make(map[string]int)
	inFence := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || !strings.HasPrefix(line, "#") {
			continue
		}
		level := 0
		for level < len(line) && line[level] == '#' {
			level++
		}
		if level == 0 || level > 6 || level >= len(line) || line[level] != ' ' {
			continue
		}
		slug := githubHeadingSlug(strings.TrimSpace(strings.TrimRight(line[level+1:], "# ")))
		if slug == "" {
			continue
		}
		n := counts[slug]
		counts[slug]++
		if n > 0 {
			slug = fmt.Sprintf("%s-%d", slug, n)
		}
		anchors[slug] = struct{}{}
	}
	return anchors
}

func githubHeadingSlug(heading string) string {
	heading = strings.ToLower(heading)
	var out strings.Builder
	for _, r := range heading {
		switch {
		case r == ' ' || r == '-':
			out.WriteRune(r)
		case r == '_':
			out.WriteRune(r)
		case r >= 'a' && r <= 'z':
			out.WriteRune(r)
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		}
	}
	return strings.ReplaceAll(out.String(), " ", "-")
}

func relativeDocPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

func repoRootForDocsAccuracy(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve docs accuracy test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func readDocAccuracyFile(t *testing.T, root, rel string) string {
	t.Helper()
	path := filepath.Clean(filepath.Join(root, rel))
	withinRoot, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("resolve %s under repo root: %v", rel, err)
	}
	if withinRoot == ".." || strings.HasPrefix(withinRoot, ".."+string(filepath.Separator)) {
		t.Fatalf("doc path %s escapes repo root", rel)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- fixed repository docs checked above stay under repo root.
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func mustContain(t *testing.T, doc, want string) {
	t.Helper()
	if !strings.Contains(doc, want) {
		t.Fatalf("doc missing %q", want)
	}
}

func mustNotContain(t *testing.T, doc, stale string) {
	t.Helper()
	if strings.Contains(doc, stale) {
		t.Fatalf("doc contains stale text %q", stale)
	}
}

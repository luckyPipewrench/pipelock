package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

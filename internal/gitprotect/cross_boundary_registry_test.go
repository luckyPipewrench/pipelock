// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// Cross-boundary value registry.
//
// The recurring defect this guards is NOT a discipline failure. It is a
// discovery failure: one policy value expressed in two execution contexts that
// no compiler, linker or type system can see at once, so the copies agree only
// because someone remembered. Nothing surfaces the divergence until a reviewer
// happens to notice.
//
// Real instances on this codebase:
//   - a 50 MiB limit in a shell script against a 100 MiB Go constant, where a
//     diff between the two failed generation on input the scanner would accept
//   - an alternative-IP parser in internal/config and another in
//     internal/scanner, which drifted and made a forwarder allowlist entry
//     canonicalize one way at validation and another at runtime
//   - a required status check named in a GitHub ruleset against the workflow
//     meant to produce it
//
// In-language duplication usually gets caught by ordinary tests. CROSS-boundary
// duplication goes silent, which is why only that class is registered here.
//
// This registry does not DISCOVER new pairs; nothing cheap can, and a heuristic
// that flagged every shared literal would be too noisy to survive. What it does
// is make the known set knowable in one place instead of scattered across
// unrelated test files, and fail closed when a registered pair diverges.
//
// When you add a value to a shell script, workflow, or another repository that
// also exists in Go, add it here.
type crossBoundaryPair struct {
	// name identifies the policy value in review output.
	name string
	// authority is where the value is defined for the product.
	authority string
	// copyPath is the non-Go artifact holding the second copy.
	copyPath string
	// copyPattern extracts the copy's value; submatch 1 is the value.
	copyPattern *regexp.Regexp
	// want is the authoritative value, referenced from Go so a change to the
	// constant breaks compilation here rather than drifting quietly.
	want string
	// why states the failure if the two disagree, so a future reader can judge
	// which side to correct rather than blindly syncing.
	why string
}

func crossBoundaryRegistry() []crossBoundaryPair {
	return []crossBoundaryPair{
		{
			name:        "trusted diff generator size limit",
			authority:   "gitprotect.MaxDiffBytes",
			copyPath:    filepath.Join("..", "..", "scripts", "generate-trusted-diff.sh"),
			copyPattern: regexp.MustCompile(`(?m)^max_bytes=\$\{4:-(\d+)\}\s*$`),
			want:        strconv.Itoa(MaxDiffBytes),
			why:         "a generator limit below the scanner's refuses diffs the scanner would accept, turning a large but ordinary pull request into a failed gate; one above it produces input the scanner then rejects, which reads to the author as a scanner fault rather than a size limit",
		},
	}
}

func TestCrossBoundaryValuesAgree(t *testing.T) {
	t.Parallel()

	registry := crossBoundaryRegistry()
	if len(registry) == 0 {
		t.Fatal("registry is empty; if every pair was genuinely eliminated, delete this test deliberately rather than leaving it vacuous")
	}

	for _, pair := range registry {
		t.Run(pair.name, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Clean(pair.copyPath))
			if err != nil {
				t.Fatalf("read %s: %v", pair.copyPath, err)
			}

			// Require exactly one live assignment. Zero means the registry
			// entry has gone stale and is silently checking nothing; more than
			// one means the artifact itself now holds competing values and
			// which one wins depends on parse order.
			matches := pair.copyPattern.FindAllSubmatch(data, -1)
			switch len(matches) {
			case 1:
			case 0:
				t.Fatalf("no live %s assignment found in %s; if that file changed shape, update the registry entry rather than leaving a check that verifies nothing", pair.name, pair.copyPath)
			default:
				t.Fatalf("%s is assigned %d times in %s; a single authoritative assignment is required or the effective value depends on ordering", pair.name, len(matches), pair.copyPath)
			}

			if got := string(matches[0][1]); got != pair.want {
				t.Fatalf("%s disagrees: %s has %s, %s has %s.\n%s", pair.name, pair.copyPath, got, pair.authority, pair.want, pair.why)
			}
		})
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// diagnose reports what the runtime would actually do. The runtime refuses a
// bundle whose min_pipelock cannot be checked, so `pipelock check` must report
// that as a failure rather than quietly passing, and it must name the override.
func TestCheckRules_UnverifiableVersionReportsFailure(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cfg := config.Defaults()
	cfg.Rules.RulesDir = rulesDir
	// Deliberately NOT setting AllowUnversionedBundleLoad: a test binary reports
	// no released version, which is the condition under test.

	result := checkRules("", "", cfg)
	if result.Status == statusPass {
		t.Fatalf("unverifiable version reported as pass: %s", result.Detail)
	}
	if !strings.Contains(result.Detail, "min_pipelock") {
		t.Errorf("failure detail does not name the requirement: %s", result.Detail)
	}
	if !strings.Contains(result.Detail, "allow_unversioned_bundle_load") {
		t.Errorf("failure detail does not name the override an operator would use: %s", result.Detail)
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// diagnose reports what the runtime would actually do. The runtime loads a
// bundle whose min_pipelock cannot be checked, so this remains a passing check.
func TestCheckRules_UnverifiableVersionLoads(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cfg := config.Defaults()
	cfg.Rules.RulesDir = rulesDir
	// A test binary reports no released version, which is the condition under test.

	result := checkRules("", "", cfg)
	if result.Status != statusPass {
		t.Fatalf("unverifiable version reported as %s: %s", result.Status, result.Detail)
	}
}

//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"

	_ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
)

// TestRedactionConfigKey_StableAcrossMergeAgentProfile exercises the real
// production trigger for the fail-closed bug: the per-agent config path
// (config.MergeAgentProfileFunc -> enterprise.deepCopyConfig). The startup
// redaction runtime is keyed from the pristine config; every forward-proxy
// request keys from the merged (deep-copied) config. If the two keys disagree
// the request body is blocked with "redaction runtime unavailable". This also
// covers the nil/default profile case, which still deep-copies the base.
func TestRedactionConfigKey_StableAcrossMergeAgentProfile(t *testing.T) {
	if config.MergeAgentProfileFunc == nil {
		t.Fatal("config.MergeAgentProfileFunc not wired; enterprise testinit missing")
	}
	base := config.Defaults()
	applyRedactionTestProfile(base)
	baseKey := mustRedactionKey(t, base)
	if baseKey == "" {
		t.Fatal("base redaction key is empty; test setup did not enable redaction")
	}

	for _, tc := range []struct {
		name    string
		profile *config.AgentProfile
	}{
		{name: "nil profile (default agent)", profile: nil},
		{name: "empty profile", profile: &config.AgentProfile{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := config.MergeAgentProfileFunc(base, tc.profile)
			if err != nil {
				t.Fatalf("MergeAgentProfileFunc: %v", err)
			}
			if got := mustRedactionKey(t, merged); got != baseKey {
				t.Fatalf("redactionConfigKey differs across MergeAgentProfile:\n  pristine = %s\n  merged   = %s", baseKey, got)
			}
		})
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDaybreak_StrictReloadRejectsListenerStateTokenDowngrade(t *testing.T) {
	oldCfg := config.Defaults()
	oldCfg.Mode = config.ModeStrict
	required := true
	oldCfg.MCPSessionBinding.Enabled = true
	oldCfg.MCPSessionBinding.ListenerRequireStateToken = &required

	newCfg := oldCfg.Clone()
	compat := false
	newCfg.MCPSessionBinding.ListenerRequireStateToken = &compat

	warnings := config.ValidateReload(oldCfg, newCfg)
	foundWarning := false
	for _, w := range warnings {
		if w.Field == "mcp_session_binding.listener_require_state_token" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatal("strict listener_require_state_token teardown emitted no reload warning")
	}
	if torn := requiredModeTeardowns(oldCfg, newCfg); len(torn) != 1 || torn[0] != "mcp_session_binding.listener_require_state_token" {
		t.Fatalf("requiredModeTeardowns = %v, want exactly mcp_session_binding.listener_require_state_token", torn)
	}
	reason := reloadDowngradeRejectReason(oldCfg, newCfg, warnings)
	if !strings.Contains(reason, "mcp_session_binding.listener_require_state_token") {
		t.Fatalf("strict reload rejection = %q, want listener state-token teardown", reason)
	}
}

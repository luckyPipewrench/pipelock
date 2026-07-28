// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestMCPTrustedSessionRegistryConcurrentAccess(t *testing.T) {
	registry := &mcpTrustedSessionRegistry{sessions: make(map[string]time.Time)}

	var wg sync.WaitGroup
	for i := range 25 {
		sessionKey := fmt.Sprintf("session-%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				registry.Register(sessionKey)
				if !registry.Known(sessionKey) {
					t.Errorf("%s unexpectedly unknown after register", sessionKey)
					return
				}
				registry.Forget(sessionKey)
			}
		}()
	}
	wg.Wait()
}

// A nil registry and an empty session key must both be refused rather than
// panicking or admitting an empty-string session. Known must answer false in
// both cases, because a true here would let an unidentified caller satisfy the
// trusted-session requirement that gates denial-of-wallet enforcement.
func TestMCPTrustedSessionRegistryRefusesNilAndEmptyKeys(t *testing.T) {
	var nilRegistry *mcpTrustedSessionRegistry
	nilRegistry.Register("session-a")
	nilRegistry.Forget("session-a")
	if nilRegistry.Known("session-a") {
		t.Fatal("nil registry reported a session as known")
	}

	registry := &mcpTrustedSessionRegistry{sessions: make(map[string]time.Time)}
	registry.Register("")
	if registry.Known("") {
		t.Fatal("empty session key was admitted as known")
	}
	if len(registry.sessions) != 0 {
		t.Fatalf("empty session key stored %d entries, want 0", len(registry.sessions))
	}

	// Forget on an absent key is a no-op, and must not disturb a live entry.
	registry.Register("session-b")
	registry.Forget("")
	registry.Forget("session-absent")
	if !registry.Known("session-b") {
		t.Fatal("a live session was lost while forgetting absent keys")
	}

	// Assert the real removal too. Without this a Forget that silently did
	// nothing would satisfy every check above, since the only other assertions
	// are that absent-key forgets leave things alone.
	registry.Forget("session-b")
	if registry.Known("session-b") {
		t.Fatal("Forget did not remove a live session")
	}
	if len(registry.sessions) != 0 {
		t.Fatalf("registry retained %d entries after forgetting every session", len(registry.sessions))
	}
}

func TestResolveMCPDoWBudgetNilConfig(t *testing.T) {
	if got := resolveMCPDoWBudget(nil, "agent-a"); got != nil {
		t.Fatalf("resolveMCPDoWBudget(nil) = %+v, want nil", got)
	}
}

func TestMCPDoWRuntimeDisabledStartupEnabledByReloadEnforces(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = make(map[string]config.AgentProfile)
	cfg.Agents["_default"] = config.AgentProfile{}
	runtime := newMCPDoWRuntime(cfg, "_default")
	wiring := runtime.Wiring()
	if wiring == nil {
		t.Fatal("DoW runtime did not produce reusable wiring while disabled")
	}
	if wiring.Enabled() {
		t.Fatal("DoW runtime enabled without configured DoW fields")
	}
	if allowed, _, reason, budgetType := wiring.Check("subject-a", "search", `{"q":"one"}`); !allowed || reason != "" || budgetType != "" {
		t.Fatalf("disabled DoW check = allowed:%v reason:%q budget:%q, want clean skip", allowed, reason, budgetType)
	}

	reloaded := cfg.Clone()
	profile := reloaded.Agents["_default"]
	profile.Budget.MaxToolCallsPerSession = 1
	profile.Budget.DoWAction = config.ActionBlock
	reloaded.Agents["_default"] = profile
	runtime.UpdateConfig(reloaded)

	if !wiring.Enabled() {
		t.Fatal("DoW runtime stayed disabled after reload enabled a DoW budget")
	}
	if allowed, action, reason, budgetType := wiring.Check("subject-a", "search", `{"q":"one"}`); !allowed || action != config.ActionBlock || reason != "" || budgetType != "" {
		t.Fatalf("first enabled DoW check = allowed:%v action:%q reason:%q budget:%q, want allowed block-mode accounting",
			allowed, action, reason, budgetType)
	}
	allowed, action, reason, budgetType := wiring.Check("subject-a", "search", `{"q":"two"}`)
	if allowed || action != config.ActionBlock || budgetType != proxy.BudgetToolCalls || reason == "" {
		t.Fatalf("second enabled DoW check = allowed:%v action:%q reason:%q budget:%q, want tool-call denial",
			allowed, action, reason, budgetType)
	}
}

func TestMCPDoWRuntimeNilReceiverMethods(t *testing.T) {
	var runtime *mcpDoWRuntime
	runtime.UpdateConfig(config.Defaults())
	if runtime.Enabled() {
		t.Fatal("nil DoW runtime reported enabled")
	}
	if allowed, action, reason, budgetType := runtime.Check("subject-a", "search", "{}"); !allowed || action != config.ActionBlock || reason != "" || budgetType != "" {
		t.Fatalf("nil DoW runtime check = allowed:%v action:%q reason:%q budget:%q, want clean allow",
			allowed, action, reason, budgetType)
	}
	if wiring := runtime.Wiring(); wiring != nil {
		t.Fatalf("nil DoW runtime wiring = %+v, want nil", wiring)
	}
}

func TestServerRefreshRuntimeStateUpdatesExistingMCPDoWRuntime(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{"_default": {}}
	s := &Server{hasMCPListen: true}
	s.refreshRuntimeState(nil, cfg, nil, nil)
	if s.mcpDoW == nil {
		t.Fatal("refreshRuntimeState did not initialize MCP DoW runtime")
	}
	first := s.mcpDoW

	reloaded := cfg.Clone()
	profile := reloaded.Agents["_default"]
	profile.Budget.MaxToolCallsPerSession = 1
	profile.Budget.DoWAction = config.ActionBlock
	reloaded.Agents["_default"] = profile
	s.refreshRuntimeState(cfg, reloaded, nil, nil)

	if s.mcpDoW != first {
		t.Fatal("refreshRuntimeState replaced MCP DoW runtime instead of updating it in place")
	}
	if !first.Enabled() {
		t.Fatal("existing MCP DoW runtime was not updated from reloaded config")
	}
}

func TestMCPDoWRuntimeReloadUpdatesAction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Agents = map[string]config.AgentProfile{
		"_default": {
			Budget: config.BudgetConfig{
				MaxToolCallsPerSession: 1,
				DoWAction:              config.ActionBlock,
			},
		},
	}
	runtime := newMCPDoWRuntime(cfg, "_default")
	wiring := runtime.Wiring()
	if wiring == nil {
		t.Fatal("DoW runtime did not produce wiring")
	}

	if allowed, _, reason, _ := wiring.Check("subject-a", "search", `{"q":"one"}`); !allowed || reason != "" {
		t.Fatalf("first call blocked before budget was spent: allowed=%v reason=%q", allowed, reason)
	}
	allowed, action, _, budgetType := wiring.Check("subject-a", "search", `{"q":"two"}`)
	if allowed || action != config.ActionBlock || budgetType != proxy.BudgetToolCalls {
		t.Fatalf("startup block action = allowed:%v action:%q budget:%q, want block refusal",
			allowed, action, budgetType)
	}

	reloaded := cfg.Clone()
	profile := reloaded.Agents["_default"]
	profile.Budget.DoWAction = config.ActionWarn
	reloaded.Agents["_default"] = profile
	runtime.UpdateConfig(reloaded)

	allowed, action, _, budgetType = wiring.Check("subject-a", "search", `{"q":"three"}`)
	if allowed || action != config.ActionWarn || budgetType != proxy.BudgetToolCalls {
		t.Fatalf("reloaded warn action = allowed:%v action:%q budget:%q, want warn refusal",
			allowed, action, budgetType)
	}

	profile.Budget.DoWAction = config.ActionBlock
	reloaded.Agents["_default"] = profile
	runtime.UpdateConfig(reloaded)

	allowed, action, _, budgetType = wiring.Check("subject-a", "search", `{"q":"four"}`)
	if allowed || action != config.ActionBlock || budgetType != proxy.BudgetToolCalls {
		t.Fatalf("reloaded block action = allowed:%v action:%q budget:%q, want block refusal",
			allowed, action, budgetType)
	}
}

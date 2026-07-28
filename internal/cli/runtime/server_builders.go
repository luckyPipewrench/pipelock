// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func buildToolPolicyCfg(cfg *config.Config) *policy.Config {
	if cfg == nil || !cfg.MCPToolPolicy.Enabled {
		return nil
	}
	return policy.New(cfg.MCPToolPolicy)
}

func buildMCPInputCfg(cfg *config.Config) *mcp.InputScanConfig {
	if cfg == nil {
		return nil
	}
	if !cfg.MCPInputScanning.Enabled && cfg.MCPInputScanning.ResponseTimeoutSeconds <= 0 {
		return nil
	}
	return &mcp.InputScanConfig{
		Enabled:                cfg.MCPInputScanning.Enabled,
		Action:                 cfg.MCPInputScanning.Action,
		OnParseError:           cfg.MCPInputScanning.OnParseError,
		ResponseTimeoutSeconds: cfg.MCPInputScanning.ResponseTimeoutSeconds,
	}
}

func buildMCPToolCfg(
	cfg *config.Config,
	extraPoison []*tools.ExtraPoisonPattern,
	baseline *tools.ToolBaseline,
) *tools.ToolScanConfig {
	if cfg == nil || !cfg.MCPToolScanning.Enabled {
		return nil
	}
	toolCfg := &tools.ToolScanConfig{
		Baseline:    baseline,
		Action:      cfg.MCPToolScanning.Action,
		DetectDrift: cfg.MCPToolScanning.DetectDrift,
		ExtraPoison: extraPoison,
	}
	if cfg.MCPSessionBinding.Enabled {
		toolCfg.BindingUnknownAction = cfg.MCPSessionBinding.UnknownToolAction
		toolCfg.BindingNoBaselineAction = cfg.MCPSessionBinding.NoBaselineAction
	}
	return toolCfg
}

func buildMCPChainMatcher(cfg *config.Config, m *metrics.Metrics) *chains.Matcher {
	if cfg == nil || !cfg.ToolChainDetection.Enabled {
		return nil
	}
	return chains.New(&cfg.ToolChainDetection).WithMetrics(m)
}

func buildMCPCEE(cfg *config.Config, m *metrics.Metrics) *mcp.CEEDeps {
	if cfg == nil || !cfg.CrossRequestDetection.Enabled {
		return nil
	}
	ceeCfg := cfg.CrossRequestDetection
	deps := &mcp.CEEDeps{Config: &ceeCfg, Metrics: m}
	if ceeCfg.EntropyBudget.Enabled {
		deps.Tracker = scanner.NewEntropyTracker(
			ceeCfg.EntropyBudget.BitsPerWindow,
			ceeCfg.EntropyBudget.WindowMinutes*60,
		)
	}
	if ceeCfg.FragmentReassembly.Enabled {
		deps.Buffer = scanner.NewFragmentBuffer(
			ceeCfg.FragmentReassembly.MaxBufferBytes,
			10000,
			ceeCfg.FragmentReassembly.WindowMinutes*60,
		)
	}
	return deps
}

type mcpDoWWiring struct {
	Check            mcp.DoWCheckFunc
	SubjectAgent     string
	SubjectAgentAuth envelope.ActorAuth
	KnownSession     func(string) bool
	RegisterSession  func(string)
	ForgetSession    func(string)
}

func buildMCPDoWWiring(cfg *config.Config, agentName string) *mcpDoWWiring {
	budget := resolveMCPDoWBudget(cfg, agentName)
	if budget == nil || !budget.HasDoWFields() {
		return nil
	}
	manager := proxy.NewDoWSubjectManager(proxy.DoWSubjectManagerConfig{
		TrackerConfig: proxy.DoWConfig{
			MaxToolCallsPerSession: budget.MaxToolCallsPerSession,
			MaxWallClockMinutes:    budget.MaxWallClockMinutes,
			WindowMinutes:          budget.WindowMinutes,
			MaxRetriesPerTool:      budget.MaxRetriesPerTool,
			LoopDetectionWindow:    budget.LoopDetectionWindow,
			Action:                 budget.DoWAction,
		},
	})
	trustedSessions := &mcpTrustedSessionRegistry{sessions: make(map[string]time.Time)}
	dowAction := budget.DoWAction
	if dowAction == "" {
		dowAction = config.ActionBlock
	}
	subjectAgent := agentName
	if subjectAgent == "" {
		subjectAgent = cfg.DefaultAgentIdentity
	}
	subjectAgentAuth := envelope.ActorAuth("")
	if subjectAgent != "" {
		subjectAgentAuth = envelope.ActorAuthConfigDefault
	}
	return &mcpDoWWiring{
		Check: func(subjectKey, toolName, argsJSON string) (bool, string, string, string) {
			result := manager.Check(subjectKey, toolName, argsJSON)
			return result.Allowed, dowAction, result.Reason, result.BudgetType
		},
		SubjectAgent:     subjectAgent,
		SubjectAgentAuth: subjectAgentAuth,
		KnownSession:     trustedSessions.Known,
		RegisterSession:  trustedSessions.Register,
		ForgetSession:    trustedSessions.Forget,
	}
}

const (
	// mcpTrustedSessionIdleTTL bounds how long a session stays trusted without
	// being used. The TTL is idle-based, not absolute: Known refreshes the
	// entry, so an in-use session never expires out from under its client and
	// only abandoned sessions age out.
	mcpTrustedSessionIdleTTL = time.Hour

	// mcpTrustedSessionMaxEntries caps the registry so a client that opens
	// sessions and abandons them cannot grow it without bound. This mirrors
	// DoWSubjectManager, which bounds itself the same way.
	mcpTrustedSessionMaxEntries = 10000
)

// mcpTrustedSessionRegistry tracks server-issued MCP session ids that are
// allowed to satisfy the trusted-session requirement gating denial-of-wallet
// enforcement. It is bounded in both directions: entries age out on an idle
// TTL, and the table refuses new entries once full.
//
// At the cap it refuses NEW sessions rather than evicting an existing one.
// Evicting a live entry would silently un-trust a session already in use,
// which is the same shape as the budget-reset bug the subject manager had:
// filling the table would become a way to disturb other clients' accounting.
// Refusing new registrations instead fails closed for the new session only,
// and the idle TTL is what keeps the table from staying full.
type mcpTrustedSessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	now      func() time.Time
}

func (r *mcpTrustedSessionRegistry) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// reapExpiredLocked drops entries idle beyond the TTL. Callers hold r.mu.
func (r *mcpTrustedSessionRegistry) reapExpiredLocked(now time.Time) {
	for key, lastSeen := range r.sessions {
		if !now.Before(lastSeen.Add(mcpTrustedSessionIdleTTL)) {
			delete(r.sessions, key)
		}
	}
}

func (r *mcpTrustedSessionRegistry) Register(sessionKey string) {
	if r == nil || sessionKey == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	if _, exists := r.sessions[sessionKey]; exists {
		r.sessions[sessionKey] = now
		return
	}
	r.reapExpiredLocked(now)
	if len(r.sessions) >= mcpTrustedSessionMaxEntries {
		// Full of live sessions. Refuse rather than evict: this session simply
		// never becomes trusted, so its requests fail closed on the DoW gate.
		return
	}
	r.sessions[sessionKey] = now
}

func (r *mcpTrustedSessionRegistry) Known(sessionKey string) bool {
	if r == nil || sessionKey == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	lastSeen, ok := r.sessions[sessionKey]
	if !ok {
		return false
	}
	now := r.clock()
	if !now.Before(lastSeen.Add(mcpTrustedSessionIdleTTL)) {
		delete(r.sessions, sessionKey)
		return false
	}
	// Refresh so an actively used session does not age out mid-use.
	r.sessions[sessionKey] = now
	return true
}

func (r *mcpTrustedSessionRegistry) Forget(sessionKey string) {
	if r == nil || sessionKey == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sessionKey)
}

func applyMCPDoWOpts(opts *mcp.MCPProxyOpts, wiring *mcpDoWWiring, requireTrustedSession bool) {
	if opts == nil || wiring == nil {
		return
	}
	opts.DoWCheck = wiring.Check
	opts.DoWSubjectAgent = wiring.SubjectAgent
	opts.DoWSubjectAgentAuth = wiring.SubjectAgentAuth
	if requireTrustedSession {
		opts.DoWRequireTrustedSession = true
		opts.DoWSessionKnown = wiring.KnownSession
		opts.DoWRegisterSession = wiring.RegisterSession
		opts.DoWForgetSession = wiring.ForgetSession
	}
}

func resolveMCPDoWBudget(cfg *config.Config, agentName string) *config.BudgetConfig {
	if cfg == nil {
		return nil
	}
	var budget *config.BudgetConfig
	if ap, ok := cfg.Agents["_default"]; ok {
		budget = &ap.Budget
	}
	if agentName != "" && agentName != "_default" {
		if ap, ok := cfg.Agents[agentName]; ok {
			budget = &ap.Budget
		}
	}
	return budget
}

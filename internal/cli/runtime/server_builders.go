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
		Baseline:               baseline,
		Action:                 cfg.MCPToolScanning.Action,
		DetectDrift:            cfg.MCPToolScanning.DetectDrift,
		ListenerDriftResetFile: cfg.MCPToolScanning.ListenerDriftResetFile,
		ExtraPoison:            extraPoison,
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
	return mcp.NewCEEDeps(cfg.CrossRequestDetection, m)
}

// reloadMCPCEE applies a reload to the MCP listener's independently-owned CEE
// state. The CEE runtime serializes each check with its policy snapshot while
// enabled trackers retain the security history accumulated by active sessions.
func reloadMCPCEE(current *mcp.CEEDeps, cfg *config.Config, m *metrics.Metrics) *mcp.CEEDeps {
	if cfg == nil || !cfg.CrossRequestDetection.Enabled {
		if current != nil {
			current.Close()
		}
		return nil
	}
	if current == nil {
		return buildMCPCEE(cfg, m)
	}
	current.Reconfigure(cfg.CrossRequestDetection, m)
	return current
}

type mcpDoWWiring struct {
	Check            mcp.DoWCheckFunc
	Enabled          func() bool
	SubjectAgent     string
	SubjectAgentAuth envelope.ActorAuth
	MinSubjectTrust  func() config.DoWSubjectTrust
	KnownSession     func(string) bool
	RegisterSession  func(string)
	ForgetSession    func(string)
}

func buildMCPDoWWiring(cfg *config.Config, agentName string) *mcpDoWWiring {
	runtime := newMCPDoWRuntime(cfg, agentName)
	if runtime == nil || !runtime.Enabled() {
		return nil
	}
	return runtime.Wiring()
}

type mcpDoWRuntime struct {
	mu               sync.RWMutex
	manager          *proxy.DoWSubjectManager
	enabled          bool
	action           string
	subjectAgent     string
	subjectAgentAuth envelope.ActorAuth
	minSubjectTrust  config.DoWSubjectTrust
	trustedSessions  *mcpTrustedSessionRegistry
	agentName        string
}

func newMCPDoWRuntime(cfg *config.Config, agentName string) *mcpDoWRuntime {
	runtime := &mcpDoWRuntime{
		trustedSessions: &mcpTrustedSessionRegistry{sessions: make(map[string]time.Time)},
		agentName:       agentName,
	}
	runtime.UpdateConfig(cfg)
	return runtime
}

func (r *mcpDoWRuntime) UpdateConfig(cfg *config.Config) {
	if r == nil {
		return
	}
	budget := resolveMCPDoWBudget(cfg, r.agentName)
	enabled := budget != nil && budget.HasDoWFields()
	dowAction := ""
	if budget != nil {
		dowAction = budget.DoWAction
	}
	if dowAction == "" {
		dowAction = config.ActionBlock
	}
	minSubjectTrust := config.DoWTrustNetwork
	if budget != nil {
		minSubjectTrust = budget.MinSubjectTrust()
	}
	var trackerCfg proxy.DoWConfig
	if budget != nil {
		trackerCfg = mcpDoWTrackerConfig(*budget)
	}
	subjectAgent := r.agentName
	if subjectAgent == "" && cfg != nil {
		subjectAgent = cfg.DefaultAgentIdentity
	}
	subjectAgentAuth := envelope.ActorAuth("")
	if subjectAgent != "" {
		subjectAgentAuth = envelope.ActorAuthConfigDefault
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if enabled {
		if r.manager == nil {
			r.manager = proxy.NewDoWSubjectManager(proxy.DoWSubjectManagerConfig{
				TrackerConfig: trackerCfg,
			})
		} else {
			r.manager.UpdateConfig(trackerCfg)
		}
	}
	r.enabled = enabled
	r.action = dowAction
	r.subjectAgent = subjectAgent
	r.subjectAgentAuth = subjectAgentAuth
	r.minSubjectTrust = minSubjectTrust
}

func (r *mcpDoWRuntime) Enabled() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

func (r *mcpDoWRuntime) Check(subjectKey, toolName, argsJSON string) (bool, string, string, string) {
	if r == nil {
		return true, config.ActionBlock, "", ""
	}
	r.mu.RLock()
	enabled := r.enabled
	manager := r.manager
	action := r.action
	r.mu.RUnlock()
	if !enabled || manager == nil {
		return true, action, "", ""
	}
	result := manager.Check(subjectKey, toolName, argsJSON)
	return result.Allowed, action, result.Reason, result.BudgetType
}

// MinSubjectTrust reports the operator-declared weakest subject grade this
// budget may be billed against. Read under the lock so a hot reload that
// changes it takes effect on the next request.
func (r *mcpDoWRuntime) MinSubjectTrust() config.DoWSubjectTrust {
	if r == nil {
		return config.DoWTrustNetwork
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.minSubjectTrust
}

func (r *mcpDoWRuntime) Wiring() *mcpDoWWiring {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	subjectAgent := r.subjectAgent
	subjectAgentAuth := r.subjectAgentAuth
	r.mu.RUnlock()
	return &mcpDoWWiring{
		Check:            r.Check,
		Enabled:          r.Enabled,
		SubjectAgent:     subjectAgent,
		SubjectAgentAuth: subjectAgentAuth,
		MinSubjectTrust:  r.MinSubjectTrust,
		KnownSession:     r.trustedSessions.Known,
		RegisterSession:  r.trustedSessions.Register,
		ForgetSession:    r.trustedSessions.Forget,
	}
}

func mcpDoWTrackerConfig(budget config.BudgetConfig) proxy.DoWConfig {
	return proxy.DoWConfig{
		MaxToolCallsPerSession: budget.MaxToolCallsPerSession,
		MaxWallClockMinutes:    budget.MaxWallClockMinutes,
		WindowMinutes:          budget.WindowMinutes,
		MaxRetriesPerTool:      budget.MaxRetriesPerTool,
		LoopDetectionWindow:    budget.LoopDetectionWindow,
		Action:                 budget.DoWAction,
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
	opts.DoWEnabledFn = wiring.Enabled
	opts.DoWSubjectAgent = wiring.SubjectAgent
	opts.DoWSubjectAgentAuth = wiring.SubjectAgentAuth
	opts.DoWMinSubjectTrustFn = wiring.MinSubjectTrust
	if requireTrustedSession {
		opts.DoWEnforceSubjectTrust = true
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

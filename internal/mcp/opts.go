package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/filesentry"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// MCPProxyOpts groups the shared dependencies for MCP proxy functions.
// Construct once per proxy invocation; pass by value so callers can
// override fields (e.g. Rec, ToolCfg) without affecting the original.
//
// Required: Scanner (dereferenced unconditionally in all scan paths).
// Optional (nil-safe): all other fields — functions check before use.
type MCPProxyOpts struct {
	// Scanning
	Scanner      *scanner.Scanner
	Approver     *hitl.Approver
	InputCfg     *InputScanConfig
	ToolCfg      *tools.ToolScanConfig
	PolicyCfg    *policy.Config
	KillSwitch   *killswitch.Controller
	ChainMatcher *chains.Matcher

	// Session and adaptive enforcement
	Store       session.Store
	Rec         session.Recorder // set by RunProxy after Store.GetOrCreate
	AdaptiveCfg *config.AdaptiveEnforcement

	// Cross-request exfiltration detection
	CEE *CEEDeps

	// Observability
	AuditLogger *audit.Logger
	Metrics     *metrics.Metrics

	// Redirect handler runtime config (nil-safe).
	RedirectRT *RedirectRuntime

	// A2A protocol scanning (nil-safe).
	A2ACfg       *config.A2AScanning
	CardBaseline *CardBaseline

	// Policy capture observer for recording scan verdicts.
	// Defaults to capture.NopObserver{} when nil.
	CaptureObs capture.CaptureObserver

	// Transport identifies the MCP transport for capture records.
	// Set to "mcp_stdio" for stdio proxy or "mcp_http" for HTTP proxy.
	Transport string

	// File sentry (stdio proxy only)
	Lineage      filesentry.Lineage
	OnChildReady func() // called after child process starts
}

// captureObserver returns the observer, defaulting to NopObserver when nil.
func (o MCPProxyOpts) captureObserver() capture.CaptureObserver {
	if o.CaptureObs != nil {
		return o.CaptureObs
	}
	return capture.NopObserver{}
}

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/filesentry"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// DoWCheckFunc checks a tool call against denial-of-wallet budgets.
// Returns (allowed, action, reason, budgetType). Action is "block" or "warn".
// When action is "warn", the caller logs but does not block the request.
type DoWCheckFunc func(toolName, argsJSON string) (allowed bool, action, reason, budgetType string)

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
	Store         session.Store
	Rec           session.Recorder // set by RunProxy after Store.GetOrCreate
	AdaptiveCfg   *config.AdaptiveEnforcement
	AdaptiveCfgFn AdaptiveConfigFunc // hot-reload aware; used by listener proxy. Nil = use static AdaptiveCfg.

	// Cross-request exfiltration detection
	CEE *CEEDeps

	// Observability
	AuditLogger *audit.Logger
	Metrics     *metrics.Metrics

	// Redirect handler runtime config (nil-safe).
	RedirectRT *RedirectRuntime

	// Provenance verification for MCP tools (nil-safe).
	ProvenanceCfg *config.MCPToolProvenance

	// A2A protocol scanning (nil-safe).
	A2ACfg       *config.A2AScanning
	CardBaseline *CardBaseline

	// Frozen tool enforcement for airlock hard tier (nil-safe).
	// When non-nil and a stable key is frozen, only tools in the frozen set
	// are allowed. Injected from proxy.FrozenToolRegistry via the interface.
	ToolFreezer session.ToolFreezer

	// FrozenToolStableKey identifies the MCP instance for frozen tool lookups.
	// Set by the proxy when constructing opts from the stable identity.
	FrozenToolStableKey string

	// Denial-of-wallet tracking (nil-safe).
	DoWCheck DoWCheckFunc

	// Policy capture observer for recording scan verdicts.
	// Defaults to capture.NopObserver{} when nil.
	CaptureObs capture.CaptureObserver

	// Transport identifies the MCP transport for capture records.
	// Set by each proxy surface, for example "mcp_stdio", "mcp_http_upstream",
	// "mcp_http_listener", or "mcp_ws".
	Transport string

	// ReceiptEmitter emits signed action receipts for MCP decisions.
	// Nil-safe (no-op when nil).
	ReceiptEmitter *receipt.Emitter

	// EnvelopeEmitter builds mediation envelopes for MCP allow decisions.
	// When non-nil, tools/call messages forwarded on allow get a
	// com.pipelock/mediation entry injected into params._meta.
	// Nil-safe (no-op when nil).
	EnvelopeEmitter *envelope.Emitter

	// Pre-spawn binary integrity verification (nil-safe).
	IntegrityCfg *config.MCPBinaryIntegrity

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

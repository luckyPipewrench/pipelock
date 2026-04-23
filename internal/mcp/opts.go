package mcp

import (
	"context"

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
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// DoWCheckFunc checks a tool call against denial-of-wallet budgets.
// Returns (allowed, action, reason, budgetType). Action is "block" or "warn".
// When action is "warn", the caller logs but does not block the request.
type DoWCheckFunc func(toolName, argsJSON string) (allowed bool, action, reason, budgetType string)

const (
	transportMCPStdio = "mcp_stdio"
	transportMCPHTTP  = "mcp_http"
	mcpWarnMethod     = "MCP"
	mcpServerResponse = "server_response"
)

// MCPRedactionConfig snapshots the request-side redaction settings used for a
// single MCP message or HTTP request.
type MCPRedactionConfig struct {
	Matcher *redact.Matcher
	Limits  redact.Limits
	Profile string
}

// MCPProxyOpts groups the shared dependencies for MCP proxy functions.
// Construct once per proxy invocation; pass by value so callers can
// override fields (e.g. Rec, ToolCfg) without affecting the original.
//
// Required: Scanner (dereferenced unconditionally in all scan paths).
// Optional (nil-safe): all other fields — functions check before use.
type MCPProxyOpts struct {
	// Scanning
	Scanner        *scanner.Scanner
	ScannerFn      func() *scanner.Scanner
	Approver       *hitl.Approver
	InputCfg       *InputScanConfig
	InputCfgFn     func() *InputScanConfig
	ToolCfg        *tools.ToolScanConfig
	ToolCfgFn      func() *tools.ToolScanConfig
	PolicyCfg      *policy.Config
	PolicyCfgFn    func() *policy.Config
	KillSwitch     *killswitch.Controller
	ChainMatcher   *chains.Matcher
	ChainMatcherFn func() *chains.Matcher

	// Session and adaptive enforcement
	Store         session.Store
	Rec           session.Recorder // set by RunProxy after Store.GetOrCreate
	AdaptiveCfg   *config.AdaptiveEnforcement
	AdaptiveCfgFn AdaptiveConfigFunc // hot-reload aware; used by listener proxy. Nil = use static AdaptiveCfg.
	TaintCfg      *config.TaintConfig
	TaintCfgFn    func() *config.TaintConfig
	// TaintExternalSource marks responses from this MCP transport as external
	// content by default (HTTP/SSE and WebSocket upstreams).
	TaintExternalSource bool

	// Cross-request exfiltration detection
	CEE   *CEEDeps
	CEEFn func() *CEEDeps

	// Observability
	AuditLogger *audit.Logger
	Metrics     *metrics.Metrics

	// Redirect handler runtime config (nil-safe).
	RedirectRT   *RedirectRuntime
	RedirectRTFn func() *RedirectRuntime

	// Provenance verification for MCP tools (nil-safe).
	ProvenanceCfg   *config.MCPToolProvenance
	ProvenanceCfgFn func() *config.MCPToolProvenance

	// A2A protocol scanning (nil-safe).
	A2ACfg       *config.A2AScanning
	A2ACfgFn     func() *config.A2AScanning
	CardBaseline *CardBaseline

	// MediaPolicy enforces response-side media handling for base64 tool
	// result content blocks (image/audio/video) before generic text scanning.
	// Nil-safe: MCP media policy is disabled when unset.
	MediaPolicy   *config.MediaPolicy
	MediaPolicyFn func() *config.MediaPolicy

	// Request-side redaction for tools/call params.arguments. Nil matcher
	// disables MCP redaction. Limits use redact package defaults when zero.
	RedactMatcher  *redact.Matcher
	RedactLimits   redact.Limits
	RedactProfile  string
	RedactionCfgFn func() MCPRedactionConfig

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

	// WarnContext is the parent context used to attach per-request DLP warn
	// metadata before MCP payload scans. Nil-safe: falls back to Background.
	WarnContext context.Context

	// ReceiptEmitter emits signed action receipts for MCP decisions.
	// Nil-safe (no-op when nil).
	ReceiptEmitter   *receipt.Emitter
	ReceiptEmitterFn func() *receipt.Emitter

	// EnvelopeEmitter builds mediation envelopes for MCP allow decisions.
	// When non-nil, tools/call messages forwarded on allow get a
	// com.pipelock/mediation entry injected into params._meta.
	// Nil-safe (no-op when nil).
	EnvelopeEmitter   *envelope.Emitter
	EnvelopeEmitterFn func() *envelope.Emitter

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

func (o MCPProxyOpts) warnContext() context.Context {
	if o.WarnContext != nil {
		return o.WarnContext
	}
	return context.Background()
}

func (o MCPProxyOpts) scanner() *scanner.Scanner {
	if o.ScannerFn != nil {
		return o.ScannerFn()
	}
	return o.Scanner
}

func (o MCPProxyOpts) inputCfg() *InputScanConfig {
	if o.InputCfgFn != nil {
		return o.InputCfgFn()
	}
	return o.InputCfg
}

func (o MCPProxyOpts) toolCfg() *tools.ToolScanConfig {
	if o.ToolCfgFn != nil {
		return o.ToolCfgFn()
	}
	return o.ToolCfg
}

func (o MCPProxyOpts) policyCfg() *policy.Config {
	if o.PolicyCfgFn != nil {
		return o.PolicyCfgFn()
	}
	return o.PolicyCfg
}

func (o MCPProxyOpts) chainMatcher() *chains.Matcher {
	if o.ChainMatcherFn != nil {
		return o.ChainMatcherFn()
	}
	return o.ChainMatcher
}

func (o MCPProxyOpts) adaptiveCfg() *config.AdaptiveEnforcement {
	if o.AdaptiveCfgFn != nil {
		return o.AdaptiveCfgFn()
	}
	return o.AdaptiveCfg
}

func (o MCPProxyOpts) taintCfg() *config.TaintConfig {
	if o.TaintCfgFn != nil {
		return o.TaintCfgFn()
	}
	return o.TaintCfg
}

func (o MCPProxyOpts) cee() *CEEDeps {
	if o.CEEFn != nil {
		return o.CEEFn()
	}
	return o.CEE
}

func (o MCPProxyOpts) redirectRT() *RedirectRuntime {
	if o.RedirectRTFn != nil {
		return o.RedirectRTFn()
	}
	return o.RedirectRT
}

func (o MCPProxyOpts) provenanceCfg() *config.MCPToolProvenance {
	if o.ProvenanceCfgFn != nil {
		return o.ProvenanceCfgFn()
	}
	return o.ProvenanceCfg
}

func (o MCPProxyOpts) a2aCfg() *config.A2AScanning {
	if o.A2ACfgFn != nil {
		return o.A2ACfgFn()
	}
	return o.A2ACfg
}

func (o MCPProxyOpts) mediaPolicy() *config.MediaPolicy {
	if o.MediaPolicyFn != nil {
		return o.MediaPolicyFn()
	}
	return o.MediaPolicy
}

func (o MCPProxyOpts) redactionConfig() MCPRedactionConfig {
	if o.RedactionCfgFn != nil {
		return o.RedactionCfgFn()
	}
	return MCPRedactionConfig{
		Matcher: o.RedactMatcher,
		Limits:  o.RedactLimits,
		Profile: o.RedactProfile,
	}
}

func (o MCPProxyOpts) receiptEmitter() *receipt.Emitter {
	if o.ReceiptEmitterFn != nil {
		return o.ReceiptEmitterFn()
	}
	return o.ReceiptEmitter
}

func (o MCPProxyOpts) envelopeEmitter() *envelope.Emitter {
	if o.EnvelopeEmitterFn != nil {
		return o.EnvelopeEmitterFn()
	}
	return o.EnvelopeEmitter
}

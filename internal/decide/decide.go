package decide

import (
	"encoding/json"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// EventKind identifies the type of agent action being evaluated.
type EventKind string

const (
	EventShellExecution EventKind = "beforeShellExecution"
	EventMCPExecution   EventKind = "beforeMCPExecution"
	EventReadFile       EventKind = "beforeReadFile"

	// Claude Code hook event kinds (tool_name values, no "before" prefix).
	EventWebFetch  EventKind = "WebFetch"
	EventWriteFile EventKind = "WriteFile"
)

// ShellPayload holds fields specific to shell execution events.
type ShellPayload struct {
	Command string `json:"command"`
	CWD     string `json:"cwd"`
}

// MCPPayload holds fields specific to MCP tool execution events.
type MCPPayload struct {
	Server    string `json:"server"`
	ToolName  string `json:"tool_name"`
	ToolInput string `json:"tool_input"` // escaped JSON string
	Command   string `json:"command"`
}

// FilePayload holds fields specific to file read events.
type FilePayload struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

// WebFetchPayload holds fields specific to URL fetch events.
type WebFetchPayload struct {
	URL string `json:"url"`
}

// WritePayload holds fields specific to file write/edit events.
type WritePayload struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
	// OldString is the content being replaced (Edit tool). It is intentionally
	// not scanned: it represents text already in the file, not new output from
	// the agent, so it carries no exfiltration or injection risk.
	OldString string `json:"old_string,omitempty"`
}

// Action describes an agent action to be evaluated.
type Action struct {
	Source string    // originating IDE (e.g., "cursor")
	Kind   EventKind // event type

	// Exactly one payload is set, matching Kind.
	Shell    *ShellPayload
	MCP      *MCPPayload
	File     *FilePayload
	WebFetch *WebFetchPayload
	Write    *WritePayload
}

// Outcome is the decision result: allow or deny.
type Outcome string

const (
	Allow Outcome = "allow"
	Deny  Outcome = "deny"
)

// Evidence records why a decision was made.
type Evidence struct {
	Scanner  string `json:"scanner"`            // which scanner triggered (dlp, injection, policy)
	Pattern  string `json:"pattern"`            // pattern name or rule name
	Severity string `json:"severity,omitempty"` // critical, high, medium, low
	Detail   string `json:"detail,omitempty"`   // human-readable detail
	Action   string `json:"action"`             // block, warn (determines outcome)
}

// Decision is the result of evaluating an Action.
type Decision struct {
	Outcome      Outcome    `json:"outcome"`
	Evidence     []Evidence `json:"evidence,omitempty"`
	UserMessage  string     `json:"user_message,omitempty"`  // shown to the user
	AgentMessage string     `json:"agent_message,omitempty"` // shown to the agent
}

// Decide evaluates an agent action against pipelock's scanning pipeline.
// policyCfg may be nil if tool policy is disabled. The cfg.Enforce flag
// controls whether block-level findings deny the action or just warn.
func Decide(cfg *config.Config, sc *scanner.Scanner, policyCfg *policy.Config, action Action) Decision {
	switch action.Kind {
	case EventShellExecution:
		return decideShell(cfg, sc, policyCfg, action.Shell)
	case EventMCPExecution:
		return decideMCP(cfg, sc, policyCfg, action.MCP)
	case EventReadFile:
		return decideFile(cfg, sc, policyCfg, action.File)
	case EventWebFetch:
		return decideWebFetch(cfg, sc, action.WebFetch)
	case EventWriteFile:
		return decideWrite(cfg, sc, policyCfg, action.Write)
	default:
		return Decision{
			Outcome:     Deny,
			UserMessage: "pipelock: unknown event type",
			Evidence:    []Evidence{{Scanner: "decide", Detail: "unrecognized event kind: " + string(action.Kind), Action: config.ActionBlock}},
		}
	}
}

func decideShell(cfg *config.Config, sc *scanner.Scanner, policyCfg *policy.Config, p *ShellPayload) Decision {
	if p == nil {
		return deny("pipelock: missing shell payload")
	}

	var evidence []Evidence

	// DLP: scan the command for secrets. DLP findings are always block-level.
	dlpResult := sc.ScanTextForDLP(p.Command)
	evidence = append(evidence, evidenceFromDLP(dlpResult)...)

	// Injection: scan command for prompt injection relay.
	if cfg.ResponseScanning.Enabled {
		injResult := sc.ScanResponse(p.Command)
		evidence = append(evidence, evidenceFromInjection(injResult, cfg.ResponseScanning.Action)...)
	}

	// Policy: map shell execution to tool name "bash" to reuse existing rules.
	if policyCfg != nil {
		policyVerdict := policyCfg.CheckToolCall("bash", []string{p.Command})
		evidence = append(evidence, evidenceFromPolicy(policyVerdict)...)
	}

	return buildDecision(cfg, evidence)
}

func decideMCP(cfg *config.Config, sc *scanner.Scanner, policyCfg *policy.Config, p *MCPPayload) Decision {
	if p == nil {
		return deny("pipelock: missing MCP payload")
	}

	var evidence []Evidence

	// Extract all strings from tool_input for scanning.
	var argStrings []string
	var scanText string
	if p.ToolInput != "" {
		if !json.Valid([]byte(p.ToolInput)) {
			// Malformed JSON in tool_input: block-level finding (fail-closed).
			// Still scan the raw text for diagnostic DLP/injection evidence.
			evidence = append(evidence, Evidence{
				Scanner:  "decide",
				Pattern:  "Malformed MCP Input",
				Severity: config.SeverityHigh,
				Detail:   "tool_input is not valid JSON",
				Action:   config.ActionBlock,
			})
			scanText = p.ToolInput
		} else {
			argStrings = ExtractAllStringsFromJSON(json.RawMessage(p.ToolInput))
			scanText = strings.Join(argStrings, " ")
		}
	}

	// DLP + injection: respect MCP input scanning toggle and action.
	if scanText != "" && cfg.MCPInputScanning.Enabled {
		dlpResult := sc.ScanTextForDLP(scanText)
		evidence = append(evidence, evidenceFromDLP(dlpResult)...)

		injResult := sc.ScanResponse(scanText)
		evidence = append(evidence, evidenceFromInjection(injResult, cfg.MCPInputScanning.Action)...)
	}

	// Policy: check tool name + args.
	if policyCfg != nil {
		policyVerdict := policyCfg.CheckToolCall(p.ToolName, argStrings)
		evidence = append(evidence, evidenceFromPolicy(policyVerdict)...)
	}

	return buildDecision(cfg, evidence)
}

func decideFile(cfg *config.Config, sc *scanner.Scanner, policyCfg *policy.Config, p *FilePayload) Decision {
	if p == nil {
		return deny("pipelock: missing file payload")
	}
	return decideFileContent(cfg, sc, policyCfg, "read_file", p.FilePath, p.Content)
}

func decideWebFetch(cfg *config.Config, sc *scanner.Scanner, p *WebFetchPayload) Decision {
	if p == nil {
		return deny("pipelock: missing WebFetch payload")
	}

	// Empty URL: fail-closed on missing input.
	if p.URL == "" {
		return deny("pipelock: missing WebFetch URL")
	}

	// Run the full URL scanner pipeline (scheme, blocklist, DLP, SSRF, etc.).
	result := sc.Scan(p.URL)
	if result.Allowed {
		return Decision{Outcome: Allow}
	}

	evidence := []Evidence{{
		Scanner:  result.Scanner,
		Pattern:  result.Reason,
		Severity: config.SeverityHigh,
		Action:   config.ActionBlock,
	}}

	return buildDecision(cfg, evidence)
}

func decideWrite(cfg *config.Config, sc *scanner.Scanner, policyCfg *policy.Config, p *WritePayload) Decision {
	if p == nil {
		return deny("pipelock: missing WriteFile payload")
	}
	return decideFileContent(cfg, sc, policyCfg, "write_file", p.FilePath, p.Content)
}

// decideFileContent is the shared logic for file read and write events.
// It runs policy checks (using toolName to distinguish read vs write rules),
// then DLP and injection scanning on the file content.
func decideFileContent(cfg *config.Config, sc *scanner.Scanner, policyCfg *policy.Config, toolName, filePath, content string) Decision {
	var evidence []Evidence

	if policyCfg != nil {
		policyVerdict := policyCfg.CheckToolCall(toolName, []string{filePath})
		evidence = append(evidence, evidenceFromPolicy(policyVerdict)...)
	}

	if content != "" {
		dlpResult := sc.ScanTextForDLP(content)
		evidence = append(evidence, evidenceFromDLP(dlpResult)...)

		if cfg.ResponseScanning.Enabled {
			injResult := sc.ScanResponse(content)
			evidence = append(evidence, evidenceFromInjection(injResult, cfg.ResponseScanning.Action)...)
		}
	}

	return buildDecision(cfg, evidence)
}

func deny(msg string) Decision {
	return Decision{
		Outcome:     Deny,
		UserMessage: msg,
	}
}

// buildDecision determines the outcome from evidence, respecting action
// semantics (block vs warn) and the enforce flag.
func buildDecision(cfg *config.Config, evidence []Evidence) Decision {
	if len(evidence) == 0 {
		return Decision{Outcome: Allow}
	}

	// Find the strictest action across all evidence.
	strictest := ""
	for _, e := range evidence {
		strictest = policy.StricterAction(strictest, e.Action)
	}

	// Build a human-readable message from evidence.
	var parts []string
	for _, e := range evidence {
		parts = append(parts, e.Pattern)
	}
	summary := strings.Join(parts, ", ")

	// Warn-only findings or enforce=false: allow with advisory message.
	if strictest == config.ActionWarn || !cfg.EnforceEnabled() {
		verb := "warning"
		if !cfg.EnforceEnabled() {
			verb = "detected (enforce off)"
		}
		return Decision{
			Outcome:      Allow,
			Evidence:     evidence,
			UserMessage:  "pipelock: " + verb + " (" + summary + ")",
			AgentMessage: "Pipelock detected a potential issue but allowed the action.",
		}
	}

	return Decision{
		Outcome:      Deny,
		Evidence:     evidence,
		UserMessage:  "pipelock: blocked (" + summary + ")",
		AgentMessage: "This action was blocked by pipelock security scanning.",
	}
}

func evidenceFromDLP(result scanner.TextDLPResult) []Evidence {
	if result.Clean {
		return nil
	}
	var ev []Evidence
	for _, m := range result.Matches {
		ev = append(ev, Evidence{
			Scanner:  "dlp",
			Pattern:  m.PatternName,
			Severity: m.Severity,
			Action:   config.ActionBlock, // DLP findings are always block-level
		})
	}
	return ev
}

func evidenceFromInjection(result scanner.ResponseScanResult, cfgAction string) []Evidence {
	if result.Clean {
		return nil
	}
	action := cfgAction
	if action == "" {
		action = config.ActionBlock // fail-closed default
	}
	var ev []Evidence
	for _, m := range result.Matches {
		ev = append(ev, Evidence{
			Scanner: "injection",
			Pattern: m.PatternName,
			Detail:  m.MatchText,
			Action:  action,
		})
	}
	return ev
}

func evidenceFromPolicy(verdict policy.Verdict) []Evidence {
	if !verdict.Matched {
		return nil
	}
	action := verdict.Action
	if action == "" {
		action = config.ActionBlock // fail-closed default
	}
	var ev []Evidence
	for _, rule := range verdict.Rules {
		sev := "high"
		if action == config.ActionWarn {
			sev = "medium"
		}
		ev = append(ev, Evidence{
			Scanner:  "policy",
			Pattern:  rule,
			Severity: sev,
			Detail:   "action=" + action,
			Action:   action,
		})
	}
	return ev
}

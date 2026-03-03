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

// Action describes an agent action to be evaluated.
type Action struct {
	Source string    // originating IDE (e.g., "cursor")
	Kind   EventKind // event type

	// Exactly one payload is set, matching Kind.
	Shell *ShellPayload
	MCP   *MCPPayload
	File  *FilePayload
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
	injResult := sc.ScanResponse(p.Command)
	evidence = append(evidence, evidenceFromInjection(injResult, cfg.ResponseScanning.Action)...)

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
				Severity: "high",
				Detail:   "tool_input is not valid JSON",
				Action:   config.ActionBlock,
			})
			scanText = p.ToolInput
		} else {
			argStrings = ExtractAllStringsFromJSON(json.RawMessage(p.ToolInput))
			scanText = strings.Join(argStrings, " ")
		}
	}

	// DLP: scan for secrets.
	if scanText != "" {
		dlpResult := sc.ScanTextForDLP(scanText)
		evidence = append(evidence, evidenceFromDLP(dlpResult)...)
	}

	// Injection: scan for prompt injection.
	if scanText != "" {
		injResult := sc.ScanResponse(scanText)
		evidence = append(evidence, evidenceFromInjection(injResult, cfg.ResponseScanning.Action)...)
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

	var evidence []Evidence

	// Policy: check file path against credential file access rules.
	// Map to "read_file" tool name to match the Credential File Access rule.
	if policyCfg != nil {
		policyVerdict := policyCfg.CheckToolCall("read_file", []string{p.FilePath})
		evidence = append(evidence, evidenceFromPolicy(policyVerdict)...)
	}

	// Content scanning only when content is present and non-empty.
	if p.Content != "" {
		dlpResult := sc.ScanTextForDLP(p.Content)
		evidence = append(evidence, evidenceFromDLP(dlpResult)...)

		injResult := sc.ScanResponse(p.Content)
		evidence = append(evidence, evidenceFromInjection(injResult, cfg.ResponseScanning.Action)...)
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

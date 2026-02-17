package mcp

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// PolicyConfig holds compiled tool call policy rules for pre-execution checking.
// A nil PolicyConfig disables policy checking entirely.
type PolicyConfig struct {
	Action string // default action: warn, block
	Rules  []*CompiledPolicyRule
}

// CompiledPolicyRule is a pre-compiled policy rule ready for matching.
type CompiledPolicyRule struct {
	Name        string
	ToolPattern *regexp.Regexp
	ArgPattern  *regexp.Regexp // nil = match on tool name alone
	Action      string         // per-rule override, empty = use PolicyConfig.Action
}

// PolicyVerdict describes the outcome of checking a tool call against policy.
type PolicyVerdict struct {
	Matched bool
	Action  string   // effective action (from rule override or default)
	Rules   []string // names of matched rules
}

// NewPolicyConfig compiles policy rules from config. Returns nil if disabled
// or no rules are configured. Panics on invalid regex — caller must validate
// config first (config.Validate compiles all patterns).
func NewPolicyConfig(cfg config.MCPToolPolicy) *PolicyConfig {
	if !cfg.Enabled || len(cfg.Rules) == 0 {
		return nil
	}
	pc := &PolicyConfig{Action: cfg.Action}
	for _, r := range cfg.Rules {
		compiled := &CompiledPolicyRule{
			Name:        r.Name,
			ToolPattern: regexp.MustCompile(r.ToolPattern),
			Action:      r.Action,
		}
		if r.ArgPattern != "" {
			compiled.ArgPattern = regexp.MustCompile(r.ArgPattern)
		}
		pc.Rules = append(pc.Rules, compiled)
	}
	return pc
}

// CheckToolCall evaluates a tool call against policy rules.
// toolName is the MCP tool name (params.name). argStrings are all string
// values extracted from params.arguments. The joined string is a space-delimited
// concatenation of all argStrings, used to catch field-splitting evasion where
// dangerous commands are split across array elements or separate fields
// (e.g. {"argv":["rm","-rf","/"]} or {"cmd":"git","args":"push --force"}).
func (pc *PolicyConfig) CheckToolCall(toolName string, argStrings []string) PolicyVerdict {
	if pc == nil || len(pc.Rules) == 0 {
		return PolicyVerdict{}
	}

	// Build a joined view so split-argument evasions are caught.
	// Example: ["rm", "-rf", "/tmp"] → "rm -rf /tmp" matches rm\s+-[a-z]*[rf].
	joined := strings.Join(argStrings, " ")

	var matchedRules []string
	strictest := ""

	for _, rule := range pc.Rules {
		if !rule.ToolPattern.MatchString(toolName) {
			continue
		}

		// No arg pattern — tool name match alone triggers the rule.
		if rule.ArgPattern == nil {
			matchedRules = append(matchedRules, rule.Name)
			action := rule.Action
			if action == "" {
				action = pc.Action
			}
			strictest = stricterAction(strictest, action)
			continue
		}

		// Check the joined argument string first (catches field-splitting evasion),
		// then fall through to individual strings (catches path patterns like .ssh/id_rsa).
		if rule.ArgPattern.MatchString(joined) {
			matchedRules = append(matchedRules, rule.Name)
			action := rule.Action
			if action == "" {
				action = pc.Action
			}
			strictest = stricterAction(strictest, action)
			continue
		}
		for _, arg := range argStrings {
			if rule.ArgPattern.MatchString(arg) {
				matchedRules = append(matchedRules, rule.Name)
				action := rule.Action
				if action == "" {
					action = pc.Action
				}
				strictest = stricterAction(strictest, action)
				break // One match per rule is sufficient.
			}
		}
	}

	if len(matchedRules) == 0 {
		return PolicyVerdict{}
	}

	return PolicyVerdict{
		Matched: true,
		Action:  strictest,
		Rules:   matchedRules,
	}
}

// CheckRequest evaluates a JSON-RPC request (single or batch) against policy.
// Returns a clean verdict for non-tools/call methods and unparseable messages.
func (pc *PolicyConfig) CheckRequest(line []byte) PolicyVerdict {
	if pc == nil {
		return PolicyVerdict{}
	}

	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return PolicyVerdict{}
	}

	// Batch request — iterate elements.
	if trimmed[0] == '[' {
		return pc.checkBatch(trimmed)
	}

	return pc.checkSingle(trimmed)
}

// checkSingle parses one JSON-RPC request and checks it against policy.
func (pc *PolicyConfig) checkSingle(line []byte) PolicyVerdict {
	tc := parseToolCall(line)
	if tc == nil {
		return PolicyVerdict{}
	}
	var argStrings []string
	if len(tc.Arguments) > 0 && string(tc.Arguments) != jsonNull {
		// Use values-only extraction (not extractAllStringsFromJSON which
		// includes map keys). Keys like "cmd","flags","target" would pollute
		// the joined string and break regex adjacency for policy matching.
		argStrings = extractStringsFromJSON(tc.Arguments)
	}
	return pc.CheckToolCall(tc.Name, argStrings)
}

// checkBatch evaluates a batch of JSON-RPC requests and aggregates policy results.
func (pc *PolicyConfig) checkBatch(line []byte) PolicyVerdict {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return PolicyVerdict{}
	}

	var allRules []string
	strictest := ""

	for _, elem := range batch {
		v := pc.checkSingle(elem)
		if v.Matched {
			allRules = append(allRules, v.Rules...)
			strictest = stricterAction(strictest, v.Action)
		}
	}

	if len(allRules) == 0 {
		return PolicyVerdict{}
	}

	return PolicyVerdict{
		Matched: true,
		Action:  strictest,
		Rules:   allRules,
	}
}

// toolCallParams holds the parsed fields of a tools/call request.
type toolCallParams struct {
	Name      string
	Arguments json.RawMessage
}

// parseToolCall extracts tool name and arguments from a tools/call JSON-RPC request.
// Returns nil if the method is not "tools/call", params don't contain a name field,
// or the message can't be parsed.
func parseToolCall(line []byte) *toolCallParams {
	var rpc struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(line, &rpc); err != nil {
		return nil
	}
	if rpc.Method != "tools/call" {
		return nil
	}
	if len(rpc.Params) == 0 || string(rpc.Params) == jsonNull {
		return nil
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(rpc.Params, &params); err != nil {
		return nil
	}
	if params.Name == "" {
		return nil
	}

	return &toolCallParams{
		Name:      params.Name,
		Arguments: params.Arguments,
	}
}

// actionRank maps action strings to strictness levels for comparison.
// Unknown values are treated as block (fail-closed).
var actionRank = map[string]int{"": 0, "warn": 1, "ask": 2, "block": 3}

// stricterAction returns the more restrictive of two actions.
// block > ask > warn > "" (empty). Unknown values are treated as block (fail-closed).
func stricterAction(a, b string) string {
	ra, aOK := actionRank[a]
	rb, bOK := actionRank[b]
	if !aOK {
		a = "block"
		ra = actionRank["block"]
	}
	if !bOK {
		b = "block"
		rb = actionRank["block"]
	}
	if rb > ra {
		return b
	}
	return a
}

// DefaultToolPolicyRules returns the built-in set of tool call policy rules
// covering common dangerous operations that agents might attempt.
func DefaultToolPolicyRules() []config.ToolPolicyRule {
	return []config.ToolPolicyRule{
		{
			Name:        "Destructive File Delete",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\brm\s+(--\s+)?-[a-z]*[rf]\b`,
			Action:      "block",
		},
		{
			Name:        "Recursive Permission Change",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\b(chmod\s+-R\s+777|chown\s+-R)\b`,
		},
		{
			Name:        "Credential File Access",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|read_file|file_read)$`,
			ArgPattern:  `(?i)(\.ssh/(id_|authorized)|\.aws/credentials|\.env\b|\.netrc|/etc/shadow)`,
			Action:      "block",
		},
		{
			Name:        "Network Exfiltration",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\b(curl|wget)\b.*(-d\s|--data|--upload-file|-T\s|-X\s+POST|--post-data)`,
		},
		{
			Name:        "Reverse Shell",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)(bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+|nc\s+-e|ncat\s+-e)`,
			Action:      "block",
		},
		{
			Name:        "Disk Wipe Command",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\b(dd\s+if=.*of=/dev/|mkfs\.|fdisk)\b`,
			Action:      "block",
		},
		{
			Name:        "Package Install",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\b(pip|npm|gem|cargo|go)\s+install\b`,
		},
		{
			Name:        "Destructive Git Operation",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|git)$`,
			ArgPattern:  `(?i)(\bgit\s+)?(push\s+--force|reset\s+--hard|clean\s+-fd)\b`,
			Action:      "block",
		},
	}
}

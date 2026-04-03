// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package policy provides MCP tool call policy rules for pre-execution checking.
// Rules match tool names and argument patterns to detect dangerous operations.
package policy

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// shellExpansionRe matches shell variable expansions used as whitespace substitutes.
// Attackers use ${IFS} or $IFS to replace spaces: "rm${IFS}-rf" expands to "rm -rf"
// at runtime, but policy sees the literal "${IFS}" token. Normalizing these to spaces
// before regex matching ensures policy catches the intended command.
//
// Covers common parameter expansion forms:
//   - $IFS (bare), ${IFS} (braced)
//   - ${IFS:0:1} (substring), ${IFS%%?} / ${IFS#?} (pattern removal)
//   - ${!IFS} (indirect expansion)
var shellExpansionRe = regexp.MustCompile(`\$\{!?IFS(?:[^a-zA-Z0-9_}][^}]*)?\}|\$IFS\b`)

// shellOctalRe matches shell octal escape sequences (\NNN where N is 0-7).
// In bash, $'\155' decodes to 'm'. Decoding these reveals the intended command:
// "r\155 -rf" becomes "rm -rf". Must run before shellEscapeRe.
var shellOctalRe = regexp.MustCompile(`\\([0-7]{1,3})`)

// shellHexRe matches shell hex escape sequences (\xHH).
// In bash, $'\x6d' decodes to 'm'. Decoding these reveals the intended command.
var shellHexRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// shellEscapeRe matches backslash-escaped word characters used to break command
// keywords. In bash, backslash before a non-special character is a no-op:
// "r\m -rf" executes identically to "rm -rf". Stripping these lets policy
// regex see the intended command. Runs after octal/hex decode.
var shellEscapeRe = regexp.MustCompile(`\\(\w)`)

// shellPositionalRe strips $@ and $* which expand to empty when there are no
// positional parameters (the common case in non-interactive MCP tool calls).
// Attackers insert these to break command keywords: "r$@m" → "rm".
// Only covers $@ $* ${@} ${*} — these are reliably empty in MCP contexts.
// Does NOT strip $0-$9, $?, $_, etc. which are non-empty in real bash.
//
// Assumption: MCP tool calls execute commands without positional parameters.
// If a wrapper script passes args into the shell (e.g. "set -- X; r$@m"),
// $@ is non-empty and stripping it synthesizes a false match. This is an
// accepted trade-off: blocking a benign wrapped command is safer than
// letting "r$@m -rf /" through in the vastly more common parameterless case.
var shellPositionalRe = regexp.MustCompile(`\$\{[@*]\}|\$[@*]`)

// shellHomeSlashRe matches parameter substring expansions that evaluate to "/"
// at runtime. Attackers use these to build file paths dynamically:
// "cat ${HOME:0:1}etc${HOME:0:1}passwd" → "cat /etc/passwd".
// Covers both bash substring forms:
//   - ${HOME:0:1} (standard offset:length)
//   - ${HOME::1}  (omitted offset, equivalent to :0:1)
//
// Matches HOME, PWD, OLDPWD — variables whose first character is always "/".
var shellHomeSlashRe = regexp.MustCompile(`\$\{(?:HOME|PWD|OLDPWD)(?::0:1|::1)\}`)

// simpleCmdSubRe matches simple command substitutions used to build command names.
// $(printf rm), $(echo rm), and $(printf %s rm) are evasion techniques that hide
// the real command. The optional (?:['"]?%\S*['"]?\s+)* handles printf format
// arguments: $(printf %s rm), $(printf '%b' rm), etc.
var simpleCmdSubRe = regexp.MustCompile(`\$\(\s*(?:echo|printf)\s+(?:['"]?%\S*['"]?\s+)*['"]?(\w+)['"]?\s*\)`)

// backtickCmdSubRe matches backtick command substitutions equivalent to $().
// `printf rm`, `echo rm` are evasion techniques identical to $(printf rm).
// Backticks are stripped by shellQuoteStripper, but the command inside needs
// to be resolved first — otherwise `printf rm` becomes "printf rm" (literal)
// instead of "rm" (resolved).
var backtickCmdSubRe = regexp.MustCompile("`\\s*(?:echo|printf)\\s+(?:['\"]?%\\S*['\"]?\\s+)*['\"]?(\\w+)['\"]?\\s*`")

// simpleAssignRe matches shell variable assignment followed by separator.
// "x=rm;$x -rf" hides the command name in a variable.
// Value group captures non-whitespace/non-separator chars to handle IFS
// manipulation: "IFS=,;CMD=r,m;$CMD" assigns `,` and `r,m` respectively.
var simpleAssignRe = regexp.MustCompile(`(\w+)=([^\s;&|]+)\s*[;&|]`)

// braceExpansionRe matches bash brace expansion used to construct commands.
// {rm,-rf,/tmp} expands to "rm -rf /tmp" at runtime. Requires at least two
// comma-separated items. Items may be empty to catch evasion patterns like
// {rm,} (trailing empty) and {,rm} (leading empty), both of which bash
// expands to include "rm". At least one item must contain a shell-safe
// character to avoid false positives on JSON or other brace-delimited syntax.
var braceExpansionRe = regexp.MustCompile(`\{([\w./:~@=*?+-]*(?:,[\w./:~@=*?+-]*)+)\}`)

// shellQuoteStripper removes shell quoting artifacts left over from ANSI-C
// quoting (e.g. $'\x6d' framing). After decodeShellEscapes, r$'\x6d' becomes
// r$'m' — the $' prefix and trailing quote prevent regex from seeing "rm".
// The $' pair is stripped first (ANSI-C opening), then remaining lone quotes.
var shellQuoteStripper = strings.NewReplacer("$'", "", `$"`, "", "'", "", `"`, "", "`", "")

// policyPreNormalize maps ambiguous confusables to their command-relevant Latin
// equivalent. The shared confusableMap maps Cyrillic у → 'y' (correct for injection
// detection: "you are now"), but this creates a bypass for command matching:
// c\u0443rl normalizes to "cyrl" instead of "curl", evading the Network Exfiltration
// rule. This replacer runs BEFORE normalize.ForMatching in the policy-specific
// normalization view only.
//
// IMPORTANT: Some mappings here conflict with the shared confusable map:
//   - в → 'b' here vs в → 'v' in confusableMap (affects mv, vi, shred)
//   - н → 'n' here vs н → 'h' in confusableMap (affects sh, shred)
//
// The policy matcher uses dual-view matching to handle this: it checks BOTH
// the policy-normalized form (pre-normalizer + ForMatching) and the baseline
// form (ForMatching only). A match on either view triggers the rule.
var policyPreNormalize = strings.NewReplacer(
	"\u0443", "u", // Cyrillic у — used as 'u' in curl/sudo/su/run
	"\u0423", "U", // Cyrillic У (uppercase)
	"\u0432", "b", // Cyrillic в — used as 'b' in bash/base64
	"\u0412", "B", // Cyrillic В (uppercase)
	"\u043D", "n", // Cyrillic н — used as 'n' in node/npm/nc
	"\u041D", "N", // Cyrillic Н (uppercase)
)

// Config holds compiled tool call policy rules for pre-execution checking.
// A nil Config disables policy checking.
type Config struct {
	Action           string // default action: warn, block, redirect
	Rules            []*CompiledRule
	RedirectProfiles map[string]config.RedirectProfile // keyed by profile name
}

// CompiledRule holds a pre-compiled policy rule ready for matching.
type CompiledRule struct {
	Name            string
	ToolPattern     *regexp.Regexp
	ArgPattern      *regexp.Regexp // nil = match on tool name alone
	ArgKey          *regexp.Regexp // nil = match all arg values; non-nil = scope to matching keys
	Action          string         // per-rule override, empty = use Config.Action
	RedirectProfile string         // key in redirect_profiles (when action=redirect)
}

// Verdict describes the outcome of checking a tool call against policy.
type Verdict struct {
	Matched         bool
	Action          string   // effective action (from rule override or default)
	Rules           []string // names of matched rules
	RedirectProfile string   // redirect profile key (set when action=redirect)
}

// New compiles policy rules from config. Returns nil if disabled or no rules
// are configured. Panics on invalid regex; the caller must validate config
// first (config.Validate compiles all patterns).
func New(cfg config.MCPToolPolicy) *Config {
	if !cfg.Enabled || len(cfg.Rules) == 0 {
		return nil
	}
	pc := &Config{Action: cfg.Action, RedirectProfiles: cfg.RedirectProfiles}
	for _, r := range cfg.Rules {
		compiled := &CompiledRule{
			Name:            r.Name,
			ToolPattern:     regexp.MustCompile(r.ToolPattern),
			Action:          r.Action,
			RedirectProfile: r.RedirectProfile,
		}
		if r.ArgPattern != "" {
			compiled.ArgPattern = regexp.MustCompile(r.ArgPattern)
		}
		if r.ArgKey != "" {
			compiled.ArgKey = regexp.MustCompile(r.ArgKey)
		}
		pc.Rules = append(pc.Rules, compiled)
	}
	return pc
}

// CheckToolCall evaluates a tool call against policy rules.
// toolName is the MCP tool name (params.name). argStrings are all string
// values extracted from params.arguments.
// Equivalent to CheckToolCallWithArgs(toolName, argStrings, nil).
func (pc *Config) CheckToolCall(toolName string, argStrings []string) Verdict {
	return pc.CheckToolCallWithArgs(toolName, argStrings, nil)
}

// CheckToolCallWithArgs evaluates a tool call against policy rules.
// argStrings contains all argument values (for rules without arg_key).
// rawArgs is the raw JSON arguments (for rules with arg_key that need
// key-scoped extraction). rawArgs may be nil if no rules use arg_key.
//
// Three matching strategies handle different evasion techniques:
//  1. Joined string — catches array-split evasion (["rm","-rf","/"])
//  2. Individual strings — catches path patterns (.ssh/id_rsa)
//  3. Pairwise token combinations — catches map-ordering evasion where
//     command and flags land in separate values with non-deterministic order
func (pc *Config) CheckToolCallWithArgs(toolName string, argStrings []string, rawArgs json.RawMessage) Verdict {
	if pc == nil || len(pc.Rules) == 0 {
		return Verdict{}
	}

	// Two tool-name normalization views catch both policy-specific and
	// baseline confusable mappings. The policy pre-normalizer maps Cyrillic
	// в→b and н→n (for bash/base64/node/npm/nc), but the shared confusable
	// map maps в→v and н→h (for mv/shred/vi/sh). Running the pre-normalizer
	// first permanently destroys the baseline mappings, so we check BOTH:
	//  - policyToolName: policyPreNormalize then ForMatching (catches curl, sudo, bash, etc.)
	//  - baselineToolName: ForMatching only (catches mv, vi, sh, etc.)
	policyToolName := normalize.ForMatching(policyPreNormalize.Replace(toolName))
	baselineToolName := normalize.ForMatching(toolName)

	// Flatten multi-token values (e.g. "-r -f" → ["-r", "-f"]) so that
	// flags split within a single field are treated as separate tokens.
	//
	// Normalization pipeline (order matters):
	//  - Unicode normalization (zero-width, homoglyphs, combining marks)
	//  - Octal/hex escape decode (\155 → m, \x6d → m)
	//  - Backtick command substitution resolve (`printf rm` → rm)
	//  - Shell quote strip ($'...' framing, lone quotes, backticks)
	//  - Backslash escape strip (\m → m)
	//  - Positional parameter strip ($@ / $* → empty)
	//  - Command substitution + variable assignment resolve ($(printf rm) → rm)
	//  - HOME/PWD slash replacement (${HOME:0:1}, ${HOME::1} → /)
	//  - Brace expansion resolve ({rm,-rf,/tmp} → rm -rf /tmp)
	//  - Shell expansion normalize (${IFS} → space)
	//
	// Three normalization views catch different evasion strategies:
	//  - Primary (policy): policyPreNormalize + drop invisible (catches curl, bash, node)
	//  - Alt (policy): policyPreNormalize + invisible→space (catches ZW separators)
	//  - Baseline: no pre-normalizer + drop invisible (catches mv, shred, vi, sh via в→v, н→h)
	// A match on ANY view triggers the rule.
	tokens, joined := normalizeArgTokens(argStrings, normalize.ForMatching, policyPreNormalize)
	altTokens, altJoined := normalizeArgTokens(argStrings, normalize.ForPolicy, policyPreNormalize)
	baseTokens, baseJoined := normalizeArgTokens(argStrings, normalize.ForMatching, nil)

	var matchedRules []string
	strictest := ""
	redirectProfile := ""

	for _, rule := range pc.Rules {
		// Check tool name against both normalization views.
		if !rule.ToolPattern.MatchString(policyToolName) && !rule.ToolPattern.MatchString(baselineToolName) {
			continue
		}

		// No arg pattern — tool name match alone triggers the rule.
		if rule.ArgPattern == nil {
			matchedRules = append(matchedRules, rule.Name)
			action := rule.Action
			if action == "" {
				action = pc.Action
			}
			prev := strictest
			strictest = StricterAction(strictest, action)
			if strictest != prev && action == config.ActionRedirect {
				redirectProfile = rule.RedirectProfile
			}
			continue
		}

		// Key-scoped rules: extract only values under matching top-level keys,
		// then normalize and match those instead of all values. If raw
		// arguments are unavailable, skip the rule rather than falling
		// back to unscoped matching (safety net for future callers).
		ruleTokens, ruleJoined := tokens, joined
		ruleAltTokens, ruleAltJoined := altTokens, altJoined
		ruleBaseTokens, ruleBaseJoined := baseTokens, baseJoined
		if rule.ArgKey != nil {
			if len(rawArgs) == 0 {
				continue // cannot scope without raw JSON — skip rule
			}
			scopedStrings := jsonrpc.ExtractStringsForKeys(rawArgs, rule.ArgKey)
			ruleTokens, ruleJoined = normalizeArgTokens(scopedStrings, normalize.ForMatching, policyPreNormalize)
			ruleAltTokens, ruleAltJoined = normalizeArgTokens(scopedStrings, normalize.ForPolicy, policyPreNormalize)
			ruleBaseTokens, ruleBaseJoined = normalizeArgTokens(scopedStrings, normalize.ForMatching, nil)
		}

		if matchArgPattern(rule.ArgPattern, ruleTokens, ruleJoined) ||
			matchArgPattern(rule.ArgPattern, ruleAltTokens, ruleAltJoined) ||
			matchArgPattern(rule.ArgPattern, ruleBaseTokens, ruleBaseJoined) {
			matchedRules = append(matchedRules, rule.Name)
			action := rule.Action
			if action == "" {
				action = pc.Action
			}
			prev := strictest
			strictest = StricterAction(strictest, action)
			if strictest != prev && action == config.ActionRedirect {
				redirectProfile = rule.RedirectProfile
			}
		}
	}

	if len(matchedRules) == 0 {
		return Verdict{}
	}

	// Clear redirect profile if a stricter action (block) won.
	if strictest != config.ActionRedirect {
		redirectProfile = ""
	}

	return Verdict{
		Matched:         true,
		Action:          strictest,
		Rules:           matchedRules,
		RedirectProfile: redirectProfile,
	}
}

// normalizeArgTokens applies an optional pre-normalizer, a Unicode normalization
// function, shell escape decoding, and shell construction resolution to
// each argument string, then splits into tokens. normFn selects the Unicode
// normalization strategy (normalize.ForMatching drops invisible chars,
// normalize.ForPolicy replaces them with spaces). preNorm applies policy-specific
// confusable remapping before Unicode normalization; pass nil to use only the
// baseline confusable map from normalize.ForMatching.
func normalizeArgTokens(argStrings []string, normFn func(string) string, preNorm *strings.Replacer) ([]string, string) {
	var tokens []string
	for _, s := range argStrings {
		if preNorm != nil {
			s = preNorm.Replace(s)
		}
		normalized := normFn(s)
		normalized = decodeShellEscapes(normalized)
		normalized = backtickCmdSubRe.ReplaceAllString(normalized, "$1")
		normalized = shellQuoteStripper.Replace(normalized)
		normalized = shellEscapeRe.ReplaceAllString(normalized, "$1")
		normalized = shellPositionalRe.ReplaceAllString(normalized, "")
		normalized = resolveShellConstruction(normalized)
		normalized = shellHomeSlashRe.ReplaceAllString(normalized, "/")
		normalized = expandBraces(normalized)
		normalized = shellExpansionRe.ReplaceAllString(normalized, " ")
		tokens = append(tokens, strings.Fields(normalized)...)
	}
	return tokens, strings.Join(tokens, " ")
}

// maxPairwiseTokens caps token count for O(n²) pairwise matching.
// Kept at 64 to bound worst-case regex work (~4K pairs × rules).
// Higher values create DoS risk (256 tokens = ~2M regex matches).
const maxPairwiseTokens = 64

// matchArgPattern checks if a regex pattern matches against any view of the
// argument tokens. It uses three strategies:
//  1. Full joined string (fast path for ordered arrays)
//  2. Individual tokens (catches self-contained patterns like file paths)
//  3. Pairwise token combinations (catches map-ordering evasion where command
//     and flags end up in separate tokens with non-deterministic iteration order)
func matchArgPattern(pat *regexp.Regexp, tokens []string, joined string) bool {
	if pat.MatchString(joined) {
		return true
	}
	for _, t := range tokens {
		if pat.MatchString(t) {
			return true
		}
	}
	// Pairwise: check "A B" and "B A" for every distinct pair.
	// Typical arg lists have 3-10 tokens, so this is 6-90 checks — negligible cost.
	// Capped at maxPairwiseTokens to prevent DoS from adversarial inputs.
	if len(tokens) <= maxPairwiseTokens {
		for i, a := range tokens {
			for j, b := range tokens {
				if i != j && pat.MatchString(a+" "+b) {
					return true
				}
			}
		}
	}
	return false
}

// CheckRequest evaluates a JSON-RPC request (single or batch) against policy.
// Returns a clean verdict for non-tools/call methods and unparseable messages.
func (pc *Config) CheckRequest(line []byte) Verdict {
	if pc == nil {
		return Verdict{}
	}

	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return Verdict{}
	}

	// Batch request — iterate elements.
	if trimmed[0] == '[' {
		return pc.checkBatch(trimmed)
	}

	return pc.checkSingle(trimmed)
}

// checkSingle parses one JSON-RPC request and checks it against policy.
func (pc *Config) checkSingle(line []byte) Verdict {
	tc := parseToolCall(line)
	if tc == nil {
		return Verdict{}
	}
	var argStrings []string
	hasArgs := len(tc.Arguments) > 0 && string(tc.Arguments) != jsonrpc.Null
	if hasArgs {
		// Use values-only extraction (not extractAllStringsFromJSON which
		// includes map keys). Keys like "cmd","flags","target" would pollute
		// the joined string and break regex adjacency for policy matching.
		argStrings = jsonrpc.ExtractStringsFromJSON(tc.Arguments)
	}

	// If any rule uses ArgKey, we need per-rule key-scoped extraction.
	// Pass raw arguments so CheckToolCallWithArgs can extract per-key.
	var rawArgs json.RawMessage
	if hasArgs {
		for _, rule := range pc.Rules {
			if rule.ArgKey != nil {
				rawArgs = tc.Arguments
				break
			}
		}
	}

	return pc.CheckToolCallWithArgs(tc.Name, argStrings, rawArgs)
}

// checkBatch evaluates a batch of JSON-RPC requests and aggregates policy results.
func (pc *Config) checkBatch(line []byte) Verdict {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return Verdict{}
	}

	var allRules []string
	strictest := ""
	redirectProfile := ""

	for _, elem := range batch {
		v := pc.checkSingle(elem)
		if v.Matched {
			allRules = append(allRules, v.Rules...)
			prev := strictest
			strictest = StricterAction(strictest, v.Action)
			// Track redirect profile from the verdict that set the effective action.
			if strictest != prev && v.Action == config.ActionRedirect {
				redirectProfile = v.RedirectProfile
			}
		}
	}

	if len(allRules) == 0 {
		return Verdict{}
	}

	// Clear redirect profile if a stricter action (block) won.
	if strictest != config.ActionRedirect {
		redirectProfile = ""
	}

	return Verdict{
		Matched:         true,
		Action:          strictest,
		Rules:           allRules,
		RedirectProfile: redirectProfile,
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
	if len(rpc.Params) == 0 || string(rpc.Params) == jsonrpc.Null {
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
// block > redirect > ask > warn > "" (empty).
// Unknown values are treated as block (fail-closed).
var actionRank = map[string]int{
	"":                    0,
	config.ActionWarn:     1,
	config.ActionAsk:      2,
	config.ActionRedirect: 3,
	config.ActionBlock:    4,
}

// StricterAction returns the more restrictive of two actions.
// block > redirect > ask > warn > "" (empty). Unknown values are treated as block (fail-closed).
func StricterAction(a, b string) string {
	ra, aOK := actionRank[a]
	rb, bOK := actionRank[b]
	if !aOK {
		a = config.ActionBlock
		ra = actionRank[config.ActionBlock]
	}
	if !bOK {
		b = config.ActionBlock
		rb = actionRank[config.ActionBlock]
	}
	if rb > ra {
		return b
	}
	return a
}

// decodeShellEscapes resolves octal (\NNN) and hex (\xHH) escape sequences
// to their character equivalents. This catches evasion like r\155 → rm.
func decodeShellEscapes(s string) string {
	s = shellHexRe.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
	s = shellOctalRe.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[1:], 8, 8)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
	return s
}

// resolveShellConstruction iteratively resolves simple command substitutions
// and variable assignments used to build command names indirectly:
//   - $(printf rm) → rm
//   - $(echo rm) → rm
//   - $($(printf echo) rm) → rm (nested, resolved over 2 iterations)
//   - x=rm;$x → x=rm;rm
//   - v=IFS;${!v} → v=IFS;${IFS} (indirect expansion)
//
// Iterates until no further changes occur, bounded to prevent infinite loops
// on pathological input.
func resolveShellConstruction(s string) string {
	const maxIterations = 10
	for range maxIterations {
		prev := s
		s = simpleCmdSubRe.ReplaceAllString(s, "$1")
		matches := simpleAssignRe.FindAllStringSubmatch(s, 10)

		// Detect IFS reassignment: IFS=<char> sets the field separator.
		// When IFS is non-default, variable expansions should split on
		// the IFS char. We apply this by replacing the IFS char with
		// space in expanded values (over-approximation, safe for detection).
		ifsChar := ""
		for _, m := range matches {
			if m[1] == "IFS" && len(m[2]) == 1 {
				ifsChar = m[2]
			}
		}

		for _, m := range matches {
			value := m[2]
			// Apply IFS-aware concatenation: remove the IFS char from
			// expanded values so "CMD=r,m" with IFS="," expands $CMD
			// to "rm". In bash, unquoted $CMD would word-split into
			// separate tokens, but the attacker's intent is command
			// construction. Concatenation is the safe over-approximation
			// for detection (reveals the assembled command name).
			if ifsChar != "" && m[1] != "IFS" {
				value = strings.ReplaceAll(value, ifsChar, "")
			}
			// Direct expansion: ${var} and $var → value.
			s = strings.ReplaceAll(s, "${"+m[1]+"}", value)
			s = strings.ReplaceAll(s, "$"+m[1], value)
			// Indirect expansion: ${!var...} → ${value...}.
			// In bash, ${!v} expands the variable whose name is v's value.
			// Replacing the prefix ${!varname with ${value converts e.g.
			// v=IFS;${!v:0:1} → v=IFS;${IFS:0:1}, which shellExpansionRe catches.
			s = strings.ReplaceAll(s, "${!"+m[1], "${"+m[2])
		}
		if s == prev {
			break
		}
	}
	return s
}

// expandBraces resolves bash brace expansion patterns. {rm,-rf,/tmp} becomes
// "rm -rf /tmp" — commas become spaces. Only expands patterns with at least two
// items containing shell-safe characters to avoid false positives.
func expandBraces(s string) string {
	return braceExpansionRe.ReplaceAllStringFunc(s, func(m string) string {
		inner := m[1 : len(m)-1] // strip { and }
		return strings.ReplaceAll(inner, ",", " ")
	})
}

// DefaultToolPolicyRules returns the built-in set of tool call policy rules
// covering common dangerous operations that agents might attempt.
func DefaultToolPolicyRules() []config.ToolPolicyRule {
	return []config.ToolPolicyRule{
		{
			Name:        "Destructive File Delete",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\brm\s+(--\s+)?(-[a-z]*[rf]\b|--(?:recursive|force)\b)`,
			Action:      config.ActionBlock,
		},
		{
			Name:        "Recursive Permission Change",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\b(chmod\s+(-R|--recursive)\s+(777|666)|chmod\s+(777|666)\s+(-R|--recursive)|chown\s+(-R|--recursive))\b`,
		},
		{
			Name:        "Credential File Access",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|read_file|file_read)$`,
			ArgPattern:  `(?i)(\.ssh/(id_|authorized)|\.aws/credentials|\.env\b|\.netrc|/etc/shadow)`,
			Action:      config.ActionBlock,
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
			Action:      config.ActionBlock,
		},
		{
			Name:        "Disk Wipe Command",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\b(dd\s+if=.*of=/dev/|mkfs\.|fdisk)\b`,
			Action:      config.ActionBlock,
		},
		{
			Name:        "Package Install",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\b(pip|npm|gem|cargo|go)\s+install\b`,
		},
		{
			Name:        "Destructive Git Operation",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|git)$`,
			ArgPattern:  `(?i)(\bgit\s+)?(push\s+(--force(\s|$)|-f\b)|reset\s+--hard\b|clean\s+-fd\b)`,
			Action:      config.ActionBlock,
		},
		{
			Name:        "Encoded Command Execution",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)(\beval\b.*\bbase64\b|\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b)`,
			Action:      config.ActionBlock,
		},
		{
			Name:        "Cron Job Persistence",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)(\bcrontab\s+(-\w+\s+\S+\s+)*-e\b|\bcrontab\s+(-\w+\s+\S+\s+)*[^-\s]|>{1,2}\s*/(?:var/spool/cron|etc/cron)|\|\s*crontab\b)`,
			Action:      config.ActionBlock,
		},
		{
			Name:        "Systemd Service Persistence",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\bsystemctl\s+(-{1,2}\w+\s+)*(enable|daemon-reload)\b`,
			Action:      config.ActionBlock,
		},
		{
			// File write tools targeting cron/systemd/init/launchd persistence paths.
			// Covers system-wide (/etc/systemd, /lib/systemd) and user-scoped
			// (~/.config/systemd/user/) systemd paths, plus macOS LaunchAgents/Daemons.
			Name:        "Persistence Path Write",
			ToolPattern: `(?i)^(write_file|file_write|edit_file|create_file|modify_file|append_file)$`,
			ArgPattern:  `(?i)(/etc/crontab\b|/etc/cron\.(d|daily|hourly|weekly|monthly)/|/var/spool/cron/|/etc/init\.d/|/etc/systemd/|/lib/systemd/|/usr/lib/systemd/|\.config/systemd/user/|/Library/Launch(Daemons|Agents)/)`,
			Action:      config.ActionBlock,
		},
		{
			// Shell commands writing into cron/systemd/init/launchd persistence paths.
			// Covers cp, mv, install, ln (destination-aware via (\S+\s+)+ prefix),
			// tee, sed -i, and shell redirects. Read operations pass through.
			Name:        "Persistence Path Write via Command",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)(>{1,2}\s*[^;|&]*(/etc/crontab\b|/etc/cron\.(d|daily|hourly|weekly|monthly)/|/var/spool/cron/|/etc/init\.d/|/etc/systemd/|/lib/systemd/|/usr/lib/systemd/|\.config/systemd/user/|/Library/Launch(Daemons|Agents)/)|\b(tee|sed\s+-i)\s+[^;|&]*(/etc/crontab\b|/etc/cron\.(d|daily|hourly|weekly|monthly)/|/var/spool/cron/|/etc/init\.d/|/etc/systemd/|/lib/systemd/|/usr/lib/systemd/|\.config/systemd/user/|/Library/Launch(Daemons|Agents)/)|\b(cp|mv|install|ln)\b\s+(\S+\s+)+\S*(/etc/crontab\b|/etc/cron\.(d|daily|hourly|weekly|monthly)/|/var/spool/cron/|/etc/init\.d/|/etc/systemd/|/lib/systemd/|/usr/lib/systemd/|\.config/systemd/user/|/Library/Launch(Daemons|Agents)/))`,
			Action:      config.ActionBlock,
		},
		{
			// File write tools: any mention of a profile file implies modification.
			Name:        "Shell Profile Modification",
			ToolPattern: `(?i)^(write_file|file_write|edit_file|create_file|modify_file|append_file)$`,
			ArgPattern:  `(?i)((?:^|/)\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_logout)\b|/etc/profile\b)`,
			Action:      config.ActionBlock,
		},
		{
			// Exec tools: require a write indicator near a profile file, or an
			// alias definition. Reads like cat/grep pass through.
			// Redirect/tee branches use [^;|&]*(?:^|[/\s]) so the engine can
			// backtrack and consume a slash (full path) or space (bare dotfile).
			// The cp/mv branch keeps (\S+\s+)+ to require at least one arg
			// before the dotfile, defeating pairwise token false positives.
			// (?:\S*/)? matches an optional path prefix before the dotfile.
			Name:        "Shell Profile Write via Command",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)(>{1,2}[^;|&]*(?:^|[/\s])\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_logout)\b|\b(tee|sed\s+-i)[^;|&]*(?:^|[/\s])\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_logout)\b|\b(cp|mv|install|ln)\b\s+(\S+\s+)+(?:\S*/)?\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_logout)\s*$|\balias\s+\w+=|>{1,2}[^;|&]*/etc/profile\b|\b(tee|sed\s+-i)[^;|&]*/etc/profile\b|\b(cp|mv|install|ln)\b\s+(\S+\s+)+\S*/etc/profile\s*$)`,
			Action:      config.ActionBlock,
		},
		{
			Name:        "Detached Process Spawning",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)(\bnohup\s+|\bdisown\b|\bsetsid\s+|\bscreen\s+(-\S+\s+)*-[dDm]|\btmux\s+(new-session|new)\s+-d)`,
		},
		{
			Name:        "Audit Log Tampering",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec|write_file|file_write|edit_file|create_file|modify_file|append_file)$`,
			ArgPattern:  `(?i)(\b(rm|truncate|shred)\b[^;|&]*/var/log/|\b(rm|truncate|shred)\b[^;|&]*\.(log|audit|jsonl)\b|>{1,2}\s*[^;|&]*(/var/log/|\.(log|audit|jsonl)\b)|\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bexport\s+HISTFILE=/dev/null\b)`,
		},
	}
}

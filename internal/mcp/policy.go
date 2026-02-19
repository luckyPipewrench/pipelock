package mcp

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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

// simpleCmdSubRe matches simple command substitutions used to build command names.
// $(printf rm) and $(echo rm) are evasion techniques that hide the real command.
var simpleCmdSubRe = regexp.MustCompile(`\$\(\s*(?:echo|printf)\s+['"]?(\w+)['"]?\s*\)`)

// simpleAssignRe matches shell variable assignment followed by separator.
// "x=rm;$x -rf" hides the command name in a variable.
var simpleAssignRe = regexp.MustCompile(`(\w+)=(\w+)\s*[;&|]`)

// shellQuoteStripper removes shell quoting artifacts left over from ANSI-C
// quoting (e.g. $'\x6d' framing). After decodeShellEscapes, r$'\x6d' becomes
// r$'m' — the $' prefix and trailing quote prevent regex from seeing "rm".
// The $' pair is stripped first (ANSI-C opening), then remaining lone quotes.
var shellQuoteStripper = strings.NewReplacer("$'", "", `$"`, "", "'", "", `"`, "", "`", "")

// policyPreNormalize maps ambiguous confusables to their command-relevant Latin
// equivalent. The shared confusableMap maps Cyrillic у → 'y' (correct for injection
// detection: "you are now"), but this creates a bypass for command matching:
// c\u0443rl normalizes to "cyrl" instead of "curl", evading the Network Exfiltration
// rule. This replacer runs BEFORE NormalizeForMatching in policy checking only,
// so injection detection keeps the shared у→'y' mapping unaffected.
var policyPreNormalize = strings.NewReplacer(
	"\u0443", "u", // Cyrillic у — used as 'u' in curl/sudo/su/run
	"\u0423", "U", // Cyrillic У (uppercase)
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
// values extracted from params.arguments.
//
// Three matching strategies handle different evasion techniques:
//  1. Joined string — catches array-split evasion (["rm","-rf","/"])
//  2. Individual strings — catches path patterns (.ssh/id_rsa)
//  3. Pairwise token combinations — catches map-ordering evasion where
//     command and flags land in separate values with non-deterministic order
func (pc *PolicyConfig) CheckToolCall(toolName string, argStrings []string) PolicyVerdict {
	if pc == nil || len(pc.Rules) == 0 {
		return PolicyVerdict{}
	}

	// Pre-normalize ambiguous confusables for policy matching before the
	// shared Unicode normalization. This resolves Cyrillic у → 'u' for
	// command tokens (curl, sudo) without affecting injection detection.
	toolName = policyPreNormalize.Replace(toolName)

	// Normalize tool name and arg strings to defeat zero-width/invisible
	// character insertion (e.g. "r\u200bm" → "rm"), homoglyph attacks
	// (Cyrillic/Greek lookalikes), and combining mark evasion.
	toolName = scanner.NormalizeForMatching(toolName)

	// Flatten multi-token values (e.g. "-r -f" → ["-r", "-f"]) so that
	// flags split within a single field are treated as separate tokens.
	//
	// Normalization pipeline (order matters):
	//  1. Unicode normalization (zero-width, homoglyphs, combining marks)
	//  2. Octal/hex escape decode (\155 → m, \x6d → m)
	//  3. Backslash escape strip (\m → m)
	//  4. Command substitution resolve ($(printf rm) → rm)
	//  5. Variable assignment resolve (x=rm;$x → x=rm;rm)
	//  6. Shell expansion normalize (${IFS} → space)
	//
	// Two normalization passes handle different ZW-char insertion strategies:
	//  - Primary: drop invisible chars (catches mid-word: "r\u200bm" → "rm")
	//  - Secondary: replace invisible with space (catches separator: "rm\u200b-rf" → "rm -rf")
	tokens, joined := normalizeArgTokens(argStrings, scanner.NormalizeForMatching)
	altTokens, altJoined := normalizeArgTokens(argStrings, scanner.NormalizeForPolicy)

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

		if matchArgPattern(rule.ArgPattern, tokens, joined) || matchArgPattern(rule.ArgPattern, altTokens, altJoined) {
			matchedRules = append(matchedRules, rule.Name)
			action := rule.Action
			if action == "" {
				action = pc.Action
			}
			strictest = stricterAction(strictest, action)
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

// normalizeArgTokens applies policyPreNormalize, a Unicode normalization
// function, shell escape decoding, and shell construction resolution to
// each argument string, then splits into tokens. normFn selects the Unicode
// normalization strategy (NormalizeForMatching drops invisible chars,
// NormalizeForPolicy replaces them with spaces).
func normalizeArgTokens(argStrings []string, normFn func(string) string) ([]string, string) {
	var tokens []string
	for _, s := range argStrings {
		s = policyPreNormalize.Replace(s)
		normalized := normFn(s)
		normalized = decodeShellEscapes(normalized)
		normalized = shellQuoteStripper.Replace(normalized)
		normalized = shellEscapeRe.ReplaceAllString(normalized, "$1")
		normalized = resolveShellConstruction(normalized)
		normalized = shellExpansionRe.ReplaceAllString(normalized, " ")
		tokens = append(tokens, strings.Fields(normalized)...)
	}
	return tokens, strings.Join(tokens, " ")
}

// maxPairwiseTokens caps token count for O(n²) pairwise matching.
// Prevents DoS from extremely long whitespace-heavy argument strings.
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
		a = "block" //nolint:goconst // action string used as-is from config
		ra = actionRank[a]
	}
	if !bOK {
		b = "block" //nolint:goconst // action string used as-is from config
		rb = actionRank[b]
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
	const maxIterations = 5
	for range maxIterations {
		prev := s
		s = simpleCmdSubRe.ReplaceAllString(s, "$1")
		matches := simpleAssignRe.FindAllStringSubmatch(s, 10)
		for _, m := range matches {
			// Direct expansion: ${var} and $var → value.
			s = strings.ReplaceAll(s, "${"+m[1]+"}", m[2])
			s = strings.ReplaceAll(s, "$"+m[1], m[2])
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

// DefaultToolPolicyRules returns the built-in set of tool call policy rules
// covering common dangerous operations that agents might attempt.
func DefaultToolPolicyRules() []config.ToolPolicyRule {
	return []config.ToolPolicyRule{
		{
			Name:        "Destructive File Delete",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)\brm\s+(--\s+)?(-[a-z]*[rf]\b|--(?:recursive|force)\b)`,
			Action:      "block",
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
			ArgPattern:  `(?i)(\bgit\s+)?(push\s+(--force(\s|$)|-f\b)|reset\s+--hard\b|clean\s+-fd\b)`,
			Action:      "block",
		},
		{
			Name:        "Encoded Command Execution",
			ToolPattern: `(?i)^(bash|shell|exec|run_command|execute|terminal|bash_exec)$`,
			ArgPattern:  `(?i)(\beval\b.*\bbase64\b|\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b)`,
			Action:      "block",
		},
	}
}

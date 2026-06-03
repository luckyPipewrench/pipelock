// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package skillscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// comboWindow is the maximum line distance, inside a single executable region,
// for a source and sink to be treated as a co-occurrence. Same-line pairs are
// direct only when the rule has enough syntax-level proof; otherwise they fall
// back to co-occurrence. Farther-apart pairs are not paired at all. This
// replaces the original "first source anywhere + first sink anywhere" model
// that paired causally unrelated lines hundreds of lines apart.
const comboWindow = 10

var (
	credentialSourcePattern     = regexp.MustCompile(`(?i)(~/.aws/credentials|~/.ssh/[A-Za-z0-9_.*-]+|~/.kube/config|~/.config/gcloud/[A-Za-z0-9_./*-]+|~/.netrc|~/.docker/config\.json|(^|[ /"'])\.env($|[ "'/])|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|AWS_SECRET_ACCESS_KEY|KUBECONFIG)`)
	networkSinkPattern          = regexp.MustCompile(`(?i)\b(curl|wget|http)\b.*https?://|fetch\s*\(\s*['"]https?://|requests\.(get|post|put|delete)\s*\(\s*['"]https?://`)
	guardTargetPattern          = regexp.MustCompile(`(?i)(~/.claude/settings\.json|~/.claude/hooks/[A-Za-z0-9_./*-]+|~/.codex/hooks\.json|~/.codex/AGENTS\.md|(^|[ /])CLAUDE\.md($|[ "']))`)
	shellTargetPattern          = regexp.MustCompile(`(?i)(~/.bashrc|~/.zshrc|~/.profile|~/.config/fish/config\.fish)`)
	cronTargetPattern           = regexp.MustCompile(`(?i)(\bcrontab\b|systemctl\s+--user\s+enable|/etc/cron\.d/[A-Za-z0-9_./*-]+|~/.config/systemd/user/[A-Za-z0-9_./*-]+\.timer)`)
	clipboardSourcePattern      = regexp.MustCompile(`(?i)\b(xclip|pbpaste|wl-paste)\b`)
	writeSinkPattern            = regexp.MustCompile(`(?i)(>\s*[^&]|>>|tee\s+|os\.WriteFile|writeFile\s*\(|open\s*\([^,\n]+,\s*['"][wa]|\binstall\s+)`)
	pipeNetworkSinkPattern      = regexp.MustCompile(`(?i)\|\s*(?:[A-Z_][A-Z0-9_]*=\S+\s+)*(curl|wget|http)\b`)
	curlDirectSourcePattern     = regexp.MustCompile(`(?i)\b(curl|http)\b.*\s(--data(?:-binary|-raw)?|-d|--form|-F|--upload-file|-T)\s+@?(~/.aws/credentials|~/.ssh/[A-Za-z0-9_.*-]+|~/.kube/config|~/.config/gcloud/[A-Za-z0-9_./*-]+|~/.netrc|~/.docker/config\.json|\.env)\b`)
	strongCredentialFilePattern = regexp.MustCompile(`(?i)(~/.aws/credentials|~/.ssh/[A-Za-z0-9_.*-]+|~/.kube/config|~/.config/gcloud/[A-Za-z0-9_./*-]+|~/.netrc|~/.docker/config\.json|\.env\b)`)
	curlPayloadFlagPattern      = regexp.MustCompile(`(?i)\b(curl|http)\b.*(?:--data(?:-binary|-raw|-urlencode)?|-d|--form|-F)(?:\s+|=)@?["]?$`)
	requestDirectSourcePattern  = regexp.MustCompile(
		`(?i)requests\.(post|put|delete)\s*\(.*\b(data|files|json)\s*=.*(~/.aws/credentials|~/.ssh/[A-Za-z0-9_.*-]+|~/.kube/config|~/.config/gcloud/[A-Za-z0-9_./*-]+|~/.netrc|~/.docker/config\.json|\.env)`,
	)

	// sinkURLHostPattern extracts the host[:port] of each http(s) URL on a line
	// so the loopback check evaluates the real sink target rather than
	// substring-matching the whole line (which a comment or an attacker host
	// like "localhost.evil.com" could otherwise abuse).
	sinkURLHostPattern = regexp.MustCompile("(?i)https?://([^/\\s\"'`)]+)")
)

type comboRule struct {
	directKind      ComboKind
	cooccurKind     ComboKind
	directSeverity  Severity
	cooccurSeverity Severity
	source          *regexp.Regexp
	sink            *regexp.Regexp
	networkSink     bool
	direct          func(string) bool
	directMsg       string
	cooccurMsg      string
}

var comboRules = []comboRule{
	{
		directKind: ComboCredentialExfil, cooccurKind: ComboCredentialCooccur,
		directSeverity: SeverityHigh, cooccurSeverity: SeverityMedium,
		source: credentialSourcePattern, sink: networkSinkPattern, networkSink: true, direct: directNetworkTransferLine,
		directMsg:  "credential source transferred to an outbound network sink in one command",
		cooccurMsg: "credential source and outbound network sink co-occur in the same code region",
	},
	{
		directKind: ComboGuardWrite, cooccurKind: ComboGuardCooccur,
		directSeverity: SeverityHigh, cooccurSeverity: SeverityMedium,
		source: guardTargetPattern, sink: writeSinkPattern,
		directMsg:  "filesystem write targets a guard file in one command",
		cooccurMsg: "guard file target and filesystem write co-occur in the same code region",
	},
	{
		directKind: ComboShellWrite, cooccurKind: ComboShellCooccur,
		directSeverity: SeverityMedium, cooccurSeverity: SeverityLow,
		source: shellTargetPattern, sink: writeSinkPattern,
		directMsg:  "filesystem write targets a shell startup file in one command",
		cooccurMsg: "shell startup file target and filesystem write co-occur in the same code region",
	},
	{
		directKind: ComboCronWrite, cooccurKind: ComboCronCooccur,
		directSeverity: SeverityMedium, cooccurSeverity: SeverityLow,
		source: cronTargetPattern, sink: writeSinkPattern,
		directMsg:  "scheduled task target written or enabled in one command",
		cooccurMsg: "scheduled task target and write or enable operation co-occur in the same code region",
	},
	{
		directKind: ComboClipboardExfil, cooccurKind: ComboClipboardCooccur,
		directSeverity: SeverityMedium, cooccurSeverity: SeverityLow,
		source: clipboardSourcePattern, sink: networkSinkPattern, networkSink: true, direct: directNetworkTransferLine,
		directMsg:  "clipboard read transferred to an outbound network sink in one command",
		cooccurMsg: "clipboard read and outbound network sink co-occur in the same code region",
	},
}

// detectCombos finds direct transfer patterns and source/sink co-occurrences
// within each executable region of a skill. Each (rule, region) yields at most
// one combo: a direct match (same line with syntax-level proof) is preferred
// over a co-occurrence (nearest in-window pair).
func detectCombos(input skillInput) []Combo {
	var combos []Combo
	for _, file := range input.files {
		for _, region := range codeRegionsFor(file) {
			for _, rule := range comboRules {
				if combo, ok := regionCombo(input.id, region, rule); ok {
					combos = append(combos, combo)
				}
			}
		}
	}
	sortCombos(combos)
	return combos
}

type comboHit struct {
	n    int
	line string
}

func regionCombo(skillID string, region codeRegion, rule comboRule) (Combo, bool) {
	var sources, sinks []comboHit
	for _, ls := range region.lines {
		if rule.source.MatchString(ls.text) {
			sources = append(sources, comboHit{ls.n, ls.text})
		}
		if rule.sink.MatchString(ls.text) {
			if rule.networkSink && !sinkTargetsNonLocal(ls.text) {
				continue
			}
			sinks = append(sinks, comboHit{ls.n, ls.text})
		}
	}
	if len(sources) == 0 || len(sinks) == 0 {
		return Combo{}, false
	}

	// Direct: source and sink on the same line, plus any rule-specific
	// proof that the source is actually transferred or written.
	for _, src := range sources {
		for _, snk := range sinks {
			if src.n == snk.n && (rule.direct == nil || rule.direct(src.line)) {
				return buildCombo(skillID, region, rule, true, src, snk), true
			}
		}
	}

	// Co-occurrence: nearest source/sink pair within the window.
	best := comboWindow + 1
	var bestSrc, bestSnk comboHit
	for _, src := range sources {
		for _, snk := range sinks {
			if d := abs(src.n - snk.n); d <= comboWindow && d < best {
				best, bestSrc, bestSnk = d, src, snk
			}
		}
	}
	if best > comboWindow {
		return Combo{}, false
	}
	return buildCombo(skillID, region, rule, false, bestSrc, bestSnk), true
}

func buildCombo(skillID string, region codeRegion, rule comboRule, direct bool, src, snk comboHit) Combo {
	kind, severity, message := rule.cooccurKind, rule.cooccurSeverity, rule.cooccurMsg
	if direct {
		kind, severity, message = rule.directKind, rule.directSeverity, rule.directMsg
	}
	return Combo{
		Kind:        kind,
		Severity:    severity,
		Direct:      direct,
		RegionID:    region.id,
		Fingerprint: comboFingerprint(skillID, kind, region.relPath, src.line, snk.line),
		Message:     message,
		Evidence: []Evidence{
			{Path: region.relPath, Line: src.n, Pattern: "source for " + string(kind)},
			{Path: region.relPath, Line: snk.n, Pattern: "sink for " + string(kind)},
		},
	}
}

// comboFingerprint is a stable identifier for a specific combination so an
// operator can allowlist it exactly and so a lock baseline can suppress it
// until the evidence changes. It binds the skill, the combo kind (which encodes
// direct vs co-occurrence), the file, and the FULL normalized source and sink
// lines, so behaviorally different code in the same region produces a different
// fingerprint and cannot be masked by an allowlist entry for a sibling line.
// The relative path (not a line-numbered region id) keeps it stable across
// benign reflowing; the 128-bit width makes accidental collision negligible.
func comboFingerprint(skillID string, kind ComboKind, relPath, srcLine, sinkLine string) string {
	parts := []string{skillID, string(kind), relPath, normalizeSnippet(srcLine), normalizeSnippet(sinkLine)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func normalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func directNetworkTransferLine(line string) bool {
	return pipeNetworkSinkPattern.MatchString(line) ||
		curlDirectSourcePattern.MatchString(line) ||
		requestDirectSourcePattern.MatchString(line) ||
		credentialSubstitutionTransfer(line)
}

func credentialSubstitutionTransfer(line string) bool {
	for _, segment := range shellCommandSegments(line) {
		if !networkSinkPattern.MatchString(segment) || !sinkTargetsNonLocal(segment) {
			continue
		}
		idx := executableCredentialSubstitutionIndex(segment)
		if idx < 0 {
			continue
		}
		if curlPayloadFlagPattern.MatchString(segment[:idx]) {
			return true
		}
	}
	return false
}

func executableCredentialSubstitutionIndex(line string) int {
	inSingle := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '\\' {
			i++
			continue
		}
		switch {
		case ch == '`':
			end := strings.IndexByte(line[i+1:], '`')
			if end < 0 {
				continue
			}
			end += i + 1
			if strongCredentialFilePattern.MatchString(line[i : end+1]) {
				return i
			}
			i = end
		case i+1 < len(line) && (ch == '$' || ch == '<') && line[i+1] == '(':
			end := commandSubstitutionEnd(line, i+2)
			if strongCredentialFilePattern.MatchString(line[i:end]) {
				return i
			}
			i = end - 1
		}
	}
	return -1
}

func commandSubstitutionEnd(line string, start int) int {
	depth := 1
	inSingle, inDouble, inBacktick := false, false, false
	for i := start; i < len(line); i++ {
		ch := line[i]
		if ch == '\\' {
			i++
			continue
		}
		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
			}
		case inDouble:
			if ch == '"' {
				inDouble = false
			}
		case inBacktick:
			if ch == '`' {
				inBacktick = false
			}
		case ch == '\'':
			inSingle = true
		case ch == '"':
			inDouble = true
		case ch == '`':
			inBacktick = true
		case i+1 < len(line) && (ch == '$' || ch == '<') && line[i+1] == '(':
			depth++
			i++
		case ch == ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(line)
}

func shellCommandSegments(line string) []string {
	var segments []string
	start := 0
	inSingle, inDouble, inBacktick := false, false, false
	substDepth := 0
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '\\' {
			i++
			continue
		}
		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
			}
		case inDouble:
			if ch == '"' {
				inDouble = false
			}
		case inBacktick:
			if ch == '`' {
				inBacktick = false
			}
		case ch == '\'':
			inSingle = true
		case ch == '"':
			inDouble = true
		case ch == '`':
			inBacktick = true
		case i+1 < len(line) && (ch == '$' || ch == '<') && line[i+1] == '(':
			substDepth++
			i++
		case ch == ')' && substDepth > 0:
			substDepth--
		case substDepth == 0 && ch == ';':
			segments = append(segments, strings.TrimSpace(line[start:i]))
			start = i + 1
		case substDepth == 0 && i+1 < len(line) && ((ch == '&' && line[i+1] == '&') || (ch == '|' && line[i+1] == '|')):
			segments = append(segments, strings.TrimSpace(line[start:i]))
			i++
			start = i + 1
		}
	}
	segments = append(segments, strings.TrimSpace(line[start:]))
	return segments
}

// sinkTargetsNonLocal reports whether any http(s) URL on the line targets a
// non-loopback host. A line whose only URLs are loopback (localhost / 127.0.0.0/8
// / ::1) is treated as local and not paired as a network sink.
func sinkTargetsNonLocal(line string) bool {
	matches := sinkURLHostPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return false
	}
	for _, m := range matches {
		if !hostIsLoopback(m[1]) {
			return true
		}
	}
	return false
}

func hostIsLoopback(hostport string) bool {
	host := hostport
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	switch {
	case strings.HasPrefix(host, "["):
		// Bracketed IPv6: take the address inside the brackets, drop any :port.
		if end := strings.Index(host, "]"); end >= 0 {
			host = host[1:end]
		}
	case strings.Count(host, ":") == 1:
		// host:port. A bare IPv6 address has multiple colons and is left intact.
		host = host[:strings.Index(host, ":")]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func sortCombos(combos []Combo) {
	sort.SliceStable(combos, func(i, j int) bool {
		a, b := combos[i], combos[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Fingerprint < b.Fingerprint
	})
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Allowlist suppresses specific combo fingerprints. Entries are scoped to an
// exact fingerprint (not a broad skill+combo pair), require a justification,
// and may carry an optional expiry so that stale exceptions are forced back
// through review.
type Allowlist struct {
	Allow []AllowEntry `yaml:"allow"`
}

type AllowEntry struct {
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires,omitempty"`
}

func loadAllowlist(path string) (Allowlist, error) {
	if path == "" {
		return Allowlist{}, nil
	}
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean)
	if err != nil {
		return Allowlist{}, fmt.Errorf("read allowlist %s: %w", clean, err)
	}
	var allowlist Allowlist
	if err := yaml.Unmarshal(data, &allowlist); err != nil {
		return Allowlist{}, fmt.Errorf("parse allowlist %s: %w", clean, err)
	}
	return allowlist, nil
}

// entry finds the allowlist entry for a fingerprint, if any.
func (a Allowlist) entry(fingerprint string) (AllowEntry, bool) {
	for _, e := range a.Allow {
		if e.Fingerprint == fingerprint {
			return e, true
		}
	}
	return AllowEntry{}, false
}

// suppresses reports whether an allowlist entry actively suppresses a combo: it
// must carry a non-empty justification and must not be expired as of now. An
// entry without a reason, or one past its expiry, does not suppress (the combo
// resurfaces for review).
func (e AllowEntry) suppresses(now time.Time) bool {
	return strings.TrimSpace(e.Reason) != "" && !e.expired(now)
}

func (e AllowEntry) expired(now time.Time) bool {
	if strings.TrimSpace(e.Expires) == "" {
		return false
	}
	exp, err := time.Parse("2006-01-02", strings.TrimSpace(e.Expires))
	if err != nil {
		// An unparseable expiry is treated as expired so a malformed date
		// fails closed (the exception stops applying) rather than open.
		return true
	}
	return now.After(exp.Add(24 * time.Hour))
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/contract/privacy"
)

// MaxMCPAckHorizon bounds how far ahead an acknowledgment may expire. It
// matches the 180-day horizon of the other incident-style exemptions: long
// enough to review the tool and move the wording upstream, short enough that
// an acknowledgment cannot become a permanent exception.
const MaxMCPAckHorizon = 180 * 24 * time.Hour

// maxMCPAckHorizonDays is MaxMCPAckHorizon in calendar days, the bound for the
// date form of expires.
const maxMCPAckHorizonDays = 180

// MCPAckFindingRequestDirective is the only finding an acknowledgment may
// name. It is the built-in Credential Request Directive; a community rule
// that reuses the name is not covered, because the acknowledgment binds the
// built-in finding and its detector revision.
const MCPAckFindingRequestDirective = "Credential Request Directive"

const (
	maxMCPAckText        = 512
	maxMCPAckPointer     = 1024
	maxMCPAckOccurrences = 64
)

// MCPAcknowledgedFinding records that an operator reviewed every occurrence of
// one finding in one exact tool definition from one configured server, and
// accepts forwarding that definition unchanged. It accepts nothing else, and
// it never relaxes any other finding. An entry that exists for the server,
// tool and finding but no longer matches (any change to the tool, to a field
// holding an occurrence, to the set of occurrences, to the detector revision
// or to the transport binding) or has expired refuses the tools/list response
// under every mcp_tool_scanning.action, warn included: a reviewed exception
// that has gone stale is never silently downgraded to a warning. With no
// entry for the tool, the finding follows mcp_tool_scanning.action as usual.
type MCPAcknowledgedFinding struct {
	// Server is the operator-supplied server name. An upstream's own
	// serverInfo.name is a self-report and is never consulted.
	Server string `yaml:"server"`
	// ServerBindingHMAC is the keyed transport binding,
	// "hmac-sha256-v1:<key id>:<mac>", so a name reused for a different
	// destination, credential, header or environment invalidates the entry.
	// It is keyed with mcp_tool_scanning.acknowledgment_key because an
	// unkeyed digest of the transport would let anyone who reads the
	// configuration test a guessed credential offline.
	ServerBindingHMAC string `yaml:"server_binding_hmac"`
	// LegacyServerBindingSHA256 is the unkeyed field this replaced. It is
	// read only so that a configuration still carrying it is refused with a
	// pointer to the keyed form instead of being silently ignored.
	LegacyServerBindingSHA256 string `yaml:"server_binding_sha256" json:"-"`
	// Tool is the exact raw tool name.
	Tool string `yaml:"tool"`
	// Finding is the built-in finding being acknowledged.
	Finding string `yaml:"finding"`
	// FamilyRevision is the detector revision of the finding's patterns that
	// the occurrences were produced by. A semantic change to those patterns
	// bumps the revision and invalidates every entry for the finding.
	FamilyRevision int `yaml:"family_revision"`
	// ToolSHA256 is the SHA-256 of the complete tool definition as received:
	// every member, including _meta and any provenance it carries.
	ToolSHA256 string `yaml:"tool_sha256"`
	// Occurrences lists every match of the finding in the tool, one entry per
	// match. The current matches must equal this list exactly.
	Occurrences []MCPAckOccurrence `yaml:"occurrences"`
	// Owner names who owns this acknowledgment.
	Owner string `yaml:"owner"`
	// Reason says why the reviewed wording is acceptable.
	Reason string `yaml:"reason"`
	// Expires is a required UTC expiry: an RFC 3339 timestamp ending in Z, at
	// most 180 days ahead, or a YYYY-MM-DD date valid through the end of that
	// UTC day, at most 180 calendar days ahead. It is checked again whenever
	// the acknowledgment would apply.
	Expires string `yaml:"expires"`
}

// MCPAckOccurrence identifies one match of the acknowledged finding.
type MCPAckOccurrence struct {
	// Field is the RFC 6901 pointer of the field holding the match, relative
	// to the tool object, such as /inputSchema/properties/key/description.
	Field string `yaml:"field"`
	// FieldTextSHA256 is the SHA-256 of the field's exact decoded UTF-8 text,
	// with no normalization.
	FieldTextSHA256 string `yaml:"field_text_sha256"`
	// Pattern is the index of the matching pattern within the finding's
	// patterns.
	Pattern int `yaml:"pattern"`
	// Ordinal counts earlier matches of the same pattern in the same field.
	Ordinal int `yaml:"ordinal"`
	// Start and End are byte offsets of the match in the field's normalized
	// text.
	Start int `yaml:"start"`
	End   int `yaml:"end"`
	// MatchSHA256 is the SHA-256 of the normalized matched text.
	MatchSHA256 string `yaml:"match_sha256"`
}

// ParseMCPAckExpiry parses an acknowledgment expiry and returns the first
// instant at which the acknowledgment no longer applies. A YYYY-MM-DD date
// stays valid through the end of that UTC day; a timestamp must be RFC 3339
// with a Z suffix.
func ParseMCPAckExpiry(value string) (time.Time, error) {
	expires, _, err := parseMCPAckExpiry(value)
	return expires, err
}

// parseMCPAckExpiry also reports whether value used the date form, which is
// bounded in calendar days rather than in hours.
func parseMCPAckExpiry(value string) (time.Time, bool, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return time.Time{}, false, fmt.Errorf("expires is required")
	}
	if day, err := time.Parse("2006-01-02", v); err == nil {
		return day.UTC().AddDate(0, 0, 1), true, nil
	}
	if !strings.HasSuffix(v, "Z") {
		return time.Time{}, false, fmt.Errorf("expires %q must be YYYY-MM-DD or an RFC 3339 UTC timestamp ending in Z", value)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("expires %q must be YYYY-MM-DD or an RFC 3339 UTC timestamp ending in Z: %w", value, err)
	}
	return t.UTC(), false, nil
}

// mcpAckExpiryWithinHorizon applies the 180-day cap to each form exactly. A
// timestamp may be at most MaxMCPAckHorizon after now. A date may be at most
// 180 calendar days after today's UTC date, so it is valid through the end of
// that day and no later.
func mcpAckExpiryWithinHorizon(expires time.Time, dateForm bool, now time.Time) bool {
	if !dateForm {
		return !expires.After(now.Add(MaxMCPAckHorizon))
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	lastDay := today.AddDate(0, 0, maxMCPAckHorizonDays)
	return !expires.After(lastDay.AddDate(0, 0, 1))
}

func validMCPAckHex(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func mcpAckPlainText(v string) bool {
	if strings.TrimSpace(v) == "" || len(v) > maxMCPAckText {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// validMCPAckPointer reports whether p is a non-empty RFC 6901 pointer: it
// starts with "/" and every "~" is the start of "~0" or "~1".
func validMCPAckPointer(p string) bool {
	if len(p) < 2 || len(p) > maxMCPAckPointer || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case 0:
			return false
		case '~':
			if i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1') {
				return false
			}
		}
	}
	return true
}

// MCPAckActive reports whether an acknowledgment that passed load validation
// still applies at now. Runtime callers check it every time, so a
// long-running process cannot keep honoring an entry that expired after load.
func MCPAckActive(e MCPAcknowledgedFinding, now time.Time) bool {
	expires, err := ParseMCPAckExpiry(e.Expires)
	return err == nil && now.Before(expires)
}

func validateMCPAckOccurrences(field string, occs []MCPAckOccurrence) error {
	if len(occs) == 0 {
		return fmt.Errorf("%s.occurrences must list every match of the finding in the tool", field)
	}
	if len(occs) > maxMCPAckOccurrences {
		return fmt.Errorf("%s.occurrences lists %d matches; at most %d are accepted", field, len(occs), maxMCPAckOccurrences)
	}
	type key struct {
		field   string
		pattern int
		ordinal int
	}
	seen := make(map[key]int, len(occs))
	fieldText := make(map[string]string, len(occs))
	for i, o := range occs {
		at := fmt.Sprintf("%s.occurrences[%d]", field, i)
		if !validMCPAckPointer(o.Field) {
			return fmt.Errorf("%s.field %q must be an RFC 6901 JSON pointer relative to the tool object, such as /inputSchema/properties/key/description", at, o.Field)
		}
		if !validMCPAckHex(strings.ToLower(o.FieldTextSHA256)) {
			return fmt.Errorf("%s.field_text_sha256 must be 64 hex characters", at)
		}
		if !validMCPAckHex(strings.ToLower(o.MatchSHA256)) {
			return fmt.Errorf("%s.match_sha256 must be 64 hex characters", at)
		}
		if o.Pattern < 0 || o.Ordinal < 0 {
			return fmt.Errorf("%s.pattern and ordinal must not be negative", at)
		}
		if o.Start < 0 || o.End <= o.Start {
			return fmt.Errorf("%s.start and end must satisfy 0 <= start < end", at)
		}
		k := key{o.Field, o.Pattern, o.Ordinal}
		if prior, dup := seen[k]; dup {
			return fmt.Errorf("%s repeats occurrences[%d] (same field, pattern and ordinal)", at, prior)
		}
		seen[k] = i
		text := strings.ToLower(o.FieldTextSHA256)
		if prior, ok := fieldText[o.Field]; ok && prior != text {
			return fmt.Errorf("%s.field_text_sha256 disagrees with an earlier occurrence in the same field", at)
		}
		fieldText[o.Field] = text
	}
	return nil
}

// validateMCPAcknowledgedFindings checks every acknowledgment at load. Expiry
// is checked again whenever one would be applied (MCPAckActive).
func validateMCPAcknowledgedFindings(entries []MCPAcknowledgedFinding, now time.Time) error {
	type key struct{ server, tool, finding string }
	seen := make(map[key]int, len(entries))
	for i, e := range entries {
		field := fmt.Sprintf("mcp_tool_scanning.acknowledged_findings[%d]", i)
		if !mcpAckPlainText(e.Server) {
			return fmt.Errorf("%s.server is required (the configured server name), at most %d bytes, without control characters", field, maxMCPAckText)
		}
		if e.LegacyServerBindingSHA256 != "" {
			return fmt.Errorf("%s.server_binding_sha256 is no longer accepted: it was an unkeyed digest of transport credentials; set mcp_tool_scanning.acknowledgment_key and copy server_binding_hmac from the candidate the proxy logs", field)
		}
		if !ValidMCPAckBindingHMAC(e.ServerBindingHMAC) {
			return fmt.Errorf("%s.server_binding_hmac must be %s<16 hex key id>:<64 hex>, as logged in the acknowledgment candidate", field, MCPAckBindingHMACPrefix)
		}
		if !mcpAckPlainText(e.Tool) {
			return fmt.Errorf("%s.tool is required, at most %d bytes, without control characters", field, maxMCPAckText)
		}
		if e.Finding != MCPAckFindingRequestDirective {
			return fmt.Errorf("%s.finding %q is not supported: only %q can be acknowledged", field, e.Finding, MCPAckFindingRequestDirective)
		}
		if e.FamilyRevision < 1 {
			return fmt.Errorf("%s.family_revision is required: the detector revision printed with the finding", field)
		}
		if !validMCPAckHex(strings.ToLower(e.ToolSHA256)) {
			return fmt.Errorf("%s.tool_sha256 must be 64 hex characters", field)
		}
		if err := validateMCPAckOccurrences(field, e.Occurrences); err != nil {
			return err
		}
		if !mcpAckPlainText(e.Owner) {
			return fmt.Errorf("%s.owner is required: name who owns this acknowledgment", field)
		}
		if !mcpAckPlainText(e.Reason) {
			return fmt.Errorf("%s.reason is required: say why the reviewed wording is acceptable (at most %d bytes)", field, maxMCPAckText)
		}
		expires, dateForm, err := parseMCPAckExpiry(e.Expires)
		if err != nil {
			return fmt.Errorf("%s.%w", field, err)
		}
		if !expires.After(now) {
			return fmt.Errorf("%s.expires %q is already expired", field, e.Expires)
		}
		if !mcpAckExpiryWithinHorizon(expires, dateForm, now) {
			return fmt.Errorf("%s.expires %q is more than %d days ahead; review it again before then", field, e.Expires, maxMCPAckHorizonDays)
		}
		k := key{e.Server, e.Tool, e.Finding}
		if prior, dup := seen[k]; dup {
			return fmt.Errorf("%s duplicates mcp_tool_scanning.acknowledged_findings[%d] for the same server, tool and finding; keep one entry listing every occurrence", field, prior)
		}
		seen[k] = i
	}
	return nil
}

// MCPAckBindingHMACPrefix names the keyed binding scheme and its version.
const MCPAckBindingHMACPrefix = "hmac-sha256-v1:"

// MinMCPAckKeyBytes is the shortest acknowledgment key accepted: a key short
// enough to guess would restore the offline test the key exists to prevent.
const MinMCPAckKeyBytes = 32

// ValidMCPAckBindingHMAC reports whether v has the keyed binding form
// "hmac-sha256-v1:<16 lowercase hex key id>:<64 lowercase hex mac>".
func ValidMCPAckBindingHMAC(v string) bool {
	rest, ok := strings.CutPrefix(v, MCPAckBindingHMACPrefix)
	if !ok {
		return false
	}
	keyID, mac, ok := strings.Cut(rest, ":")
	return ok && len(keyID) == 16 && validLowerHex(keyID) && len(mac) == 64 && validLowerHex(mac)
}

func validLowerHex(v string) bool {
	for _, r := range v {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return v != ""
}

// ResolveMCPAckKey resolves the acknowledgment key source exactly as
// configuration load does. The runtime uses it to recheck a pinned key after
// a reload fails, so a key that is gone or rotated stops being honored.
func ResolveMCPAckKey(source string) ([]byte, error) {
	return resolveMCPAckKey(source)
}

// resolveMCPAckKey resolves the acknowledgment key source. Only an
// environment reference or an absolute file reference is accepted; the
// resolver refuses symlinks and files readable by group or others.
func resolveMCPAckKey(source string) ([]byte, error) {
	const field = "mcp_tool_scanning.acknowledgment_key"
	isEnv := strings.HasPrefix(source, "${") && strings.HasSuffix(source, "}") && len(source) > 3
	if !isEnv && !strings.HasPrefix(source, "file:") {
		return nil, fmt.Errorf("%s must be \"${ENV_VAR}\" or \"file:/absolute/path\"; a literal key in the configuration would be readable by everyone who can read the entries it protects", field)
	}
	key, err := privacy.LoadSalt(source)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if len(key) < MinMCPAckKeyBytes {
		return nil, fmt.Errorf("%s resolves to %d bytes; at least %d are required", field, len(key), MinMCPAckKeyBytes)
	}
	return key, nil
}

// ValidateMCPAcknowledgedFinding checks one entry exactly as configuration
// load does. The tool scanner uses it before offering an operator a
// candidate, so it never prints an entry the configuration would refuse.
func ValidateMCPAcknowledgedFinding(e MCPAcknowledgedFinding, now time.Time) error {
	return validateMCPAcknowledgedFindings([]MCPAcknowledgedFinding{e}, now)
}

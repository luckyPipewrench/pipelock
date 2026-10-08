// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// credentialRequestFamilyRevision is the detector revision of the Credential
// Request Directive patterns. An acknowledgment binds the revision its
// occurrences were produced by. Bump it for any semantic change to the
// family's patterns, which invalidates every acknowledgment of the finding;
// TestCredentialRequestFamilyRevisionGuard fails until the bump is made.
// Revision 2: the family's patterns became markup tolerant, so emphasis and
// code markers between words match like the plain sentence.
const credentialRequestFamilyRevision = 2

// Credential acknowledgment outcomes, recorded on the tool's match.
const (
	CredentialAckAcknowledged       = "acknowledged"
	CredentialAckExpired            = "expired"
	CredentialAckBindingMismatch    = "binding_mismatch"
	CredentialAckRevisionChanged    = "revision_changed"
	CredentialAckToolChanged        = "tool_changed"
	CredentialAckUnattributable     = "unattributable"
	CredentialAckOccurrencesChanged = "occurrences_changed"
	CredentialAckFieldChanged       = "field_changed"
)

// ServerBindingDigest returns the digest an operator copies into an
// acknowledgment's server_binding_sha256. kind names the transport
// ("subprocess" or "upstream") and parts are its identity: the launch command
// and arguments, or the upstream URL. Each part is length-prefixed so no two
// different part lists share a digest.
func ServerBindingDigest(kind string, parts ...string) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = fmt.Fprintf(h, "%d:", len(s))
		_, _ = h.Write([]byte(s))
	}
	write("pipelock-mcp-server-binding-v1")
	write(kind)
	for _, p := range parts {
		write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// UpstreamBindingDigest is the transport binding digest for a configured
// upstream URL. Every part that can select a different destination, tenant
// or principal is bound: scheme and host (lowercased, as they are
// case-insensitive), user info, an opaque part, the escaped path, whether an
// empty query was written ("/mcp?" is a different request target from
// "/mcp"), the raw query exactly as written including parameter order, and the
// fragment. Only the digest is
// ever printed, so credentials in the URL never reach a log. A URL that does
// not parse is bound by its exact bytes.
func UpstreamBindingDigest(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ServerBindingDigest("upstream-raw", raw)
	}
	userinfo := ""
	if u.User != nil {
		userinfo = u.User.String()
	}
	return ServerBindingDigest("upstream", strings.ToLower(u.Scheme), strings.ToLower(u.Host), userinfo, u.Opaque, u.EscapedPath(), strconv.FormatBool(u.ForceQuery), u.RawQuery, u.EscapedFragment())
}

// WithServer returns a copy of c bound to the configured server name and
// transport binding that acknowledgments are matched against. The name comes
// from the operator's configuration, never from the upstream's serverInfo.
func (c *ToolScanConfig) WithServer(name, binding string) *ToolScanConfig {
	if c == nil {
		return nil
	}
	cp := *c
	cp.ServerName = name
	cp.ServerBindingSHA256 = binding
	return &cp
}

// completeToolDigest is the SHA-256 of the whole tool definition as received,
// in canonical JSON: every member, including _meta and any provenance it
// carries. It is separate from the drift hash and from the provenance signing
// digest, both of which deliberately cover less. A definition that has no raw
// bytes or is ambiguous JSON has no digest and cannot be acknowledged.
func completeToolDigest(t ToolDef) (string, bool) {
	canonical, err := strictCanonicalToolJSON(t.raw)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), true
}

// strictCanonicalToolJSON re-encodes a tool definition with sorted object keys
// and numbers exactly as written. It refuses anything a reviewer could read
// two ways: a duplicate member name at any depth (decoders disagree on which
// copy wins, and a map would silently drop one), a top level that is not an
// object, and trailing data after it. It is used only to decide whether an
// acknowledgment may apply.
func strictCanonicalToolJSON(raw []byte) ([]byte, error) {
	// Invalid UTF-8, a lone surrogate escape and U+FFFD itself all decode to
	// U+FFFD, so their canonical forms would collide while the forwarded
	// bytes differ. Refuse them: such a definition cannot be acknowledged.
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("tool definition is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := first.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("tool definition is not a JSON object")
	}
	var out bytes.Buffer
	if err := canonicalObject(dec, &out, 0); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("trailing data after the tool definition")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out.Bytes(), nil
}

const maxCanonicalToolDepth = 256

// canonicalObject consumes an object whose opening brace was already read.
func canonicalObject(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	if depth > maxCanonicalToolDepth {
		return fmt.Errorf("tool definition nests too deeply")
	}
	members := make(map[string][]byte)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("object key is not a string")
		}
		if strings.ContainsRune(key, utf8.RuneError) {
			return fmt.Errorf("object key decodes to U+FFFD")
		}
		if _, dup := members[key]; dup {
			return fmt.Errorf("duplicate member %q", key)
		}
		var value bytes.Buffer
		if err := canonicalValue(dec, &value, depth+1); err != nil {
			return err
		}
		members[key] = value.Bytes()
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return err
	}
	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		enc, err := json.Marshal(k)
		if err != nil {
			return err
		}
		out.Write(enc)
		out.WriteByte(':')
		out.Write(members[k])
	}
	out.WriteByte('}')
	return nil
}

func canonicalValue(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return canonicalObject(dec, out, depth)
		case '[':
			if depth > maxCanonicalToolDepth {
				return fmt.Errorf("tool definition nests too deeply")
			}
			out.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := canonicalValue(dec, out, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // closing bracket
				return err
			}
			out.WriteByte(']')
			return nil
		default:
			return fmt.Errorf("unexpected delimiter %q", v)
		}
	case json.Number:
		out.WriteString(v.String())
	case string:
		if strings.ContainsRune(v, utf8.RuneError) {
			return fmt.Errorf("string value decodes to U+FFFD")
		}
		enc, err := json.Marshal(v)
		if err != nil {
			return err
		}
		out.Write(enc)
	default:
		enc, err := json.Marshal(v)
		if err != nil {
			return err
		}
		out.Write(enc)
	}
	return nil
}

// toolFieldText resolves an RFC 6901 pointer against the raw tool definition
// and returns the string it names.
func toolFieldText(t ToolDef, pointer string) (string, bool) {
	if len(t.raw) == 0 || !strings.HasPrefix(pointer, "/") {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(t.raw))
	dec.UseNumber()
	var node any
	if err := dec.Decode(&node); err != nil {
		return "", false
	}
	for _, tok := range strings.Split(pointer[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch n := node.(type) {
		case map[string]any:
			child, ok := n[tok]
			if !ok {
				return "", false
			}
			node = child
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(n) || strconv.Itoa(i) != tok {
				return "", false
			}
			node = n[i]
		default:
			return "", false
		}
	}
	s, ok := node.(string)
	return s, ok
}

func ackOccurrenceKey(field string, pattern, ordinal, start, end int, match string) string {
	return fmt.Sprintf("%s\x00%d\x00%d\x00%d\x00%d\x00%s", field, pattern, ordinal, start, end, strings.ToLower(match))
}

// findCredentialAck returns the configured acknowledgment for this server,
// tool and finding, if any. At most one exists; load validation refuses
// duplicates.
func findCredentialAck(cfg *ToolScanConfig, toolName string) (config.MCPAcknowledgedFinding, bool) {
	if cfg == nil || cfg.ServerName == "" {
		return config.MCPAcknowledgedFinding{}, false
	}
	for _, e := range cfg.CredentialAcks {
		if e.Server == cfg.ServerName && e.Tool == toolName && e.Finding == config.MCPAckFindingRequestDirective {
			return e, true
		}
	}
	return config.MCPAcknowledgedFinding{}, false
}

// evaluateCredentialAck decides whether entry acknowledges every Credential
// Request Directive occurrence in tool. att must be the attribution of the
// exact text, spans and normalized string the detector matched. The first
// failing check names the outcome; only CredentialAckAcknowledged applies.
func evaluateCredentialAck(entry config.MCPAcknowledgedFinding, cfg *ToolScanConfig, tool ToolDef, att credentialRequestAttribution, now time.Time) string {
	if !config.MCPAckActive(entry, now) {
		return CredentialAckExpired
	}
	if cfg.ServerBindingSHA256 == "" || !strings.EqualFold(entry.ServerBindingSHA256, cfg.ServerBindingSHA256) {
		return CredentialAckBindingMismatch
	}
	if entry.FamilyRevision != credentialRequestFamilyRevision {
		return CredentialAckRevisionChanged
	}
	digest, ok := completeToolDigest(tool)
	if !ok || !strings.EqualFold(entry.ToolSHA256, digest) {
		return CredentialAckToolChanged
	}
	if !att.Attributable {
		return CredentialAckUnattributable
	}
	want := make([]string, 0, len(entry.Occurrences))
	for _, o := range entry.Occurrences {
		want = append(want, ackOccurrenceKey(o.Field, o.Pattern, o.Ordinal, o.Start, o.End, o.MatchSHA256))
	}
	got := make([]string, 0, len(att.Occurrences))
	for _, o := range att.Occurrences {
		got = append(got, ackOccurrenceKey(o.Pointer, o.Pattern, o.Ordinal, o.Start, o.End, o.MatchSHA256))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return CredentialAckOccurrencesChanged
	}
	for _, o := range entry.Occurrences {
		text, ok := toolFieldText(tool, o.Field)
		if !ok {
			return CredentialAckFieldChanged
		}
		sum := sha256.Sum256([]byte(text))
		if !strings.EqualFold(o.FieldTextSHA256, hex.EncodeToString(sum[:])) {
			return CredentialAckFieldChanged
		}
	}
	return CredentialAckAcknowledged
}

// CredentialAckRefused reports whether a configured acknowledgment exists for
// some tool but did not apply. The response must then be refused whatever
// mcp_tool_scanning.action says.
func (r ToolScanResult) CredentialAckRefused() bool {
	for _, m := range r.Matches {
		if m.CredentialAck != "" && m.CredentialAck != CredentialAckAcknowledged {
			return true
		}
	}
	return false
}

// CredentialAckApplied reports whether an acknowledgment lifted a finding in
// this response. Such a response is not evidence of clean behavior and must
// not earn adaptive-enforcement credit.
func (r ToolScanResult) CredentialAckApplied() bool {
	for _, o := range r.Observations {
		if o.CredentialAck == CredentialAckAcknowledged {
			return true
		}
	}
	return false
}

// CredentialAckCandidate is the acknowledgment an operator would add, after
// reviewing the tool, to accept its current Credential Request Directive
// occurrences. It is offered only when every occurrence is attributable and
// the configured server name and binding are known. It carries digests and
// field pointers, never field text. Owner, reason and expiry are left for the
// operator to supply.
type CredentialAckCandidate struct {
	Server              string                    `json:"server"`
	ServerBindingSHA256 string                    `json:"server_binding_sha256"`
	Tool                string                    `json:"tool"`
	Finding             string                    `json:"finding"`
	FamilyRevision      int                       `json:"family_revision"`
	ToolSHA256          string                    `json:"tool_sha256"`
	Occurrences         []CredentialAckOccurrence `json:"occurrences"`
}

// CredentialAckOccurrence is one occurrence in a candidate.
type CredentialAckOccurrence struct {
	Field           string `json:"field"`
	FieldTextSHA256 string `json:"field_text_sha256"`
	Pattern         int    `json:"pattern"`
	Ordinal         int    `json:"ordinal"`
	Start           int    `json:"start"`
	End             int    `json:"end"`
	MatchSHA256     string `json:"match_sha256"`
}

// credentialAckCandidate returns the candidate, or nil and the reason an
// entry cannot represent this tool. A tool with no candidate still enforces.
func credentialAckCandidate(cfg *ToolScanConfig, tool ToolDef, att credentialRequestAttribution) (*CredentialAckCandidate, string) {
	c := buildCredentialAckCandidate(cfg, tool, att)
	if c == nil {
		return nil, ""
	}
	// The real configuration validator is the oracle: an entry it would
	// refuse (too many occurrences, an unusable name) is never offered.
	probe := c.entry()
	probe.Owner, probe.Reason = "operator", "reviewed"
	probe.Expires = cfg.now().Add(24 * time.Hour).Format(time.RFC3339)
	if err := config.ValidateMCPAcknowledgedFinding(probe, cfg.now()); err != nil {
		return nil, err.Error()
	}
	return c, ""
}

// entry converts the candidate to a configuration entry without the fields
// only an operator can supply.
func (c *CredentialAckCandidate) entry() config.MCPAcknowledgedFinding {
	e := config.MCPAcknowledgedFinding{
		Server: c.Server, ServerBindingSHA256: c.ServerBindingSHA256, Tool: c.Tool, Finding: c.Finding,
		FamilyRevision: c.FamilyRevision, ToolSHA256: c.ToolSHA256,
	}
	for _, o := range c.Occurrences {
		e.Occurrences = append(e.Occurrences, config.MCPAckOccurrence{
			Field: o.Field, FieldTextSHA256: o.FieldTextSHA256, Pattern: o.Pattern, Ordinal: o.Ordinal,
			Start: o.Start, End: o.End, MatchSHA256: o.MatchSHA256,
		})
	}
	return e
}

func buildCredentialAckCandidate(cfg *ToolScanConfig, tool ToolDef, att credentialRequestAttribution) *CredentialAckCandidate {
	if cfg == nil || cfg.ServerName == "" || cfg.ServerBindingSHA256 == "" || !att.Attributable || len(att.Occurrences) == 0 {
		return nil
	}
	digest, ok := completeToolDigest(tool)
	if !ok {
		return nil
	}
	c := &CredentialAckCandidate{
		Server:              cfg.ServerName,
		ServerBindingSHA256: cfg.ServerBindingSHA256,
		Tool:                tool.Name,
		Finding:             config.MCPAckFindingRequestDirective,
		FamilyRevision:      credentialRequestFamilyRevision,
		ToolSHA256:          digest,
	}
	for _, o := range att.Occurrences {
		text, ok := toolFieldText(tool, o.Pointer)
		if !ok {
			return nil
		}
		sum := sha256.Sum256([]byte(text))
		c.Occurrences = append(c.Occurrences, CredentialAckOccurrence{
			Field: o.Pointer, FieldTextSHA256: hex.EncodeToString(sum[:]),
			Pattern: o.Pattern, Ordinal: o.Ordinal, Start: o.Start, End: o.End, MatchSHA256: o.MatchSHA256,
		})
	}
	return c
}

// logCredentialAckCandidate prints the acknowledgment entry an operator could
// add once they have reviewed the tool. It never prints field text.
func logCredentialAckCandidate(logW io.Writer, lineNum int, m ToolScanMatch) {
	if m.CredentialAckCandidate == nil {
		if m.CredentialAckUnsupported != "" {
			// Neutral on purpose: whether the list is refused depends on the
			// action and on any configured entry, decided elsewhere.
			_, _ = fmt.Fprintf(logW, "pipelock: line %d: tool %q: no acknowledgment candidate available (%s)\n",
				lineNum, m.ToolName, m.CredentialAckUnsupported)
		}
		return
	}
	enc, err := json.Marshal(m.CredentialAckCandidate)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(logW, "pipelock: line %d: tool %q: after reviewing it, this entry (plus owner, reason and expires) acknowledges its current %s occurrences under mcp_tool_scanning.acknowledged_findings: %s\n",
		lineNum, m.ToolName, m.CredentialAckCandidate.Finding, enc)
}

// credentialAckHasOtherFindings reports whether m carries any finding besides
// the Credential Request Directive, which an acknowledgment cannot lift.
func credentialAckHasOtherFindings(m ToolScanMatch) bool {
	if len(m.Injection) > 0 || m.DriftDetected {
		return true
	}
	for _, f := range m.ToolPoison {
		if f != handoverRequestFinding {
			return true
		}
	}
	return false
}

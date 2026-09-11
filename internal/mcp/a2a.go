// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"mime"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/a2amethods"
)

// FieldClass tells callers which scanner pipeline a leaf value needs.
type FieldClass int

const (
	// FieldURL routes through scanner.Scan() (SSRF + scheme + blocklist + DLP).
	FieldURL FieldClass = iota
	// FieldText routes through scanner.ScanResponse() (injection) + ScanTextForDLP().
	FieldText
	// FieldSecret routes through scanner.ScanTextForDLP() with high severity.
	FieldSecret
	// FieldOpaque routes through scanner.ScanResponse() (injection) + ScanTextForDLP().
	// Same scanners as FieldText but lower classification confidence.
	FieldOpaque
	// FieldKeyEntropy emits JSON object keys for content-entropy scanning only.
	// The A2A scanner intentionally does not run prompt-injection or DLP on
	// every structural key, but opaque data can be hidden in keys.
	FieldKeyEntropy
	// FieldBudgetExceeded signals the walker hit its node budget. Caller should
	// fail closed - the payload is too wide for classified scanning.
	FieldBudgetExceeded
)

const (
	// maxWalkDepth bounds recursion depth to prevent stack overflow.
	maxWalkDepth = 20
	// maxWalkNodes bounds total leaves visited to prevent CPU exhaustion
	// on wide payloads. When exceeded, walker emits FieldBudgetExceeded.
	maxWalkNodes = 10000
)

// Canonical URL, text, and secret field name lists are in init() below,
// where they are normalized into lookup maps for case/style-insensitive
// matching. See normalizedURLFields, normalizedTextFields, normalizedSecretFields.

// uriHierarchicalRe matches hierarchical URI schemes (scheme://).
var uriHierarchicalRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// nonHierarchicalSchemes lists URI schemes that use scheme: without //.
// These are security-relevant: data: can embed HTML/JS, javascript: runs code,
// mailto: can trigger email sends. Included for FieldURL promotion.
var nonHierarchicalSchemes = map[string]bool{
	"data":       true,
	"javascript": true,
	"mailto":     true,
	"tel":        true,
	"blob":       true,
}

// isURILike returns true for strings that look like URI references.
// Matches both hierarchical (scheme://) and non-hierarchical (data:, javascript:) forms.
func isURILike(s string) bool {
	if uriHierarchicalRe.MatchString(s) {
		return true
	}
	// Check non-hierarchical: "data:...", "javascript:..."
	idx := strings.IndexByte(s, ':')
	if idx > 0 && idx < 12 { // scheme names are short
		scheme := strings.ToLower(s[:idx])
		return nonHierarchicalSchemes[scheme]
	}
	return false
}

// normalizedURLFields is a lookup map for URL field names, keyed by their
// normalized form (lowercase, underscores stripped). This allows matching
// camelCase, snake_case, and mixed-case variants of the same field name.
var normalizedURLFields map[string]bool

// normalizedTextFields is a lookup map for text field names, keyed by normalized form.
var normalizedTextFields map[string]bool

// normalizedSecretFields is a lookup map for secret field names, keyed by normalized form.
var normalizedSecretFields map[string]bool

func init() {
	// Build normalized lookup maps from canonical field names.
	// Each canonical name is normalized (lowercase + strip underscores)
	// so that classifyFieldName works with any casing or underscore variant.
	urlNames := []string{
		"url", "uri",
		"documentationUrl", "iconUrl",
		"authorizationUrl", "tokenUrl", "refreshUrl",
		"deviceAuthorizationUrl", "openIdConnectUrl", "oauth2MetadataUrl",
		// snake_case variants (normalizes to same key as camelCase, but
		// listed explicitly for clarity)
		"documentation_url", "icon_url",
		"authorization_url", "token_url", "refresh_url",
		"device_authorization_url", "open_id_connect_url", "oauth2_metadata_url",
	}
	normalizedURLFields = make(map[string]bool, len(urlNames))
	for _, n := range urlNames {
		normalizedURLFields[normalizeFieldName(n)] = true
	}

	textNames := []string{"text", "description", "name"}
	normalizedTextFields = make(map[string]bool, len(textNames))
	for _, n := range textNames {
		normalizedTextFields[normalizeFieldName(n)] = true
	}

	secretNames := []string{"credentials", "token", "secret", "apiKey", "password", "api_key"}
	normalizedSecretFields = make(map[string]bool, len(secretNames))
	for _, n := range secretNames {
		normalizedSecretFields[normalizeFieldName(n)] = true
	}
}

// normalizeFieldName strips underscores and lowercases a field name.
// This maps camelCase, snake_case, and mixed variants to the same key:
// "apiKey", "api_key", "API_KEY", "Api_Key" all become "apikey".
func normalizeFieldName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", ""))
}

// classifyFieldName returns the FieldClass for a known field name.
// Normalizes the input (lowercase + strip underscores) so camelCase,
// snake_case, and mixed-case variants all match. Returns -1 if the
// name is not in any known set.
func classifyFieldName(name string) FieldClass {
	norm := normalizeFieldName(name)
	if normalizedURLFields[norm] {
		return FieldURL
	}
	if normalizedTextFields[norm] {
		return FieldText
	}
	if normalizedSecretFields[norm] {
		return FieldSecret
	}
	return -1
}

// WalkA2AJSON recursively visits a JSON value, classifying each string leaf
// by field name and URI heuristic, then calling emit for each.
//
// Both object KEYS and values are emitted (keys can be URLs).
// The walker normalizes camelCase field names internally for classification
// but preserves original names in the emitted path.
//
// Bounds: maxWalkDepth (stack), maxWalkNodes (total leaves). On node budget
// breach, emits a single FieldBudgetExceeded and stops.
func WalkA2AJSON(data json.RawMessage, emit func(path string, value string, class FieldClass)) {
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return
	}
	nodeCount := 0
	walkValue(parsed, "", "", &nodeCount, 0, emit)
}

// walkValue recursively walks a JSON value.
// parentKey is the field name of the current value (empty for root or array elements).
func walkValue(v interface{}, path, parentKey string, nodeCount *int, depth int, emit func(string, string, FieldClass)) {
	if depth > maxWalkDepth {
		return
	}
	if *nodeCount >= maxWalkNodes {
		emit(path, "", FieldBudgetExceeded)
		return
	}

	switch val := v.(type) {
	case string:
		*nodeCount++
		class := classifyLeafValue(parentKey, val)
		emit(path, val, class)

	case float64:
		// Numbers are not security-relevant for classification
		*nodeCount++

	case bool:
		*nodeCount++

	case []interface{}:
		for i, item := range val {
			elemPath := path + "[]"
			if i == 0 {
				elemPath = path + "[0]"
			}
			walkValue(item, elemPath, parentKey, nodeCount, depth+1, emit)
			if *nodeCount >= maxWalkNodes {
				emit(path, "", FieldBudgetExceeded)
				return
			}
		}

	case map[string]interface{}:
		// Sort keys for deterministic traversal.
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			*nodeCount++
			if *nodeCount >= maxWalkNodes {
				emit(path, "", FieldBudgetExceeded)
				return
			}

			childPath := path
			if childPath == "" {
				childPath = k
			} else {
				childPath = path + "." + k
			}

			// Emit the key itself as a leaf - keys can be URLs or secrets.
			// Also emit every key to the entropy-only class so A2A content
			// entropy covers key surfaces without a second JSON parse.
			emit(childPath+"@key", k, FieldKeyEntropy)
			keyClass := classifyKeyAsLeaf(k)
			if keyClass >= 0 {
				emit(childPath+"@key", k, keyClass)
			}

			// Recurse into the value with this key as context.
			walkValue(val[k], childPath, k, nodeCount, depth+1, emit)
			if *nodeCount >= maxWalkNodes {
				emit(path, "", FieldBudgetExceeded)
				return
			}
		}

	case nil:
		// JSON null - nothing to scan.
	}
}

// classifyLeafValue classifies a string value based on its parent field name
// and the value's content (URI heuristic).
func classifyLeafValue(parentKey, value string) FieldClass {
	// Known field name takes priority. classifyFieldName normalizes
	// the name (lowercase + strip underscores) for case/style parity.
	if parentKey != "" {
		if class := classifyFieldName(parentKey); class >= 0 {
			return class
		}
	}

	// URI heuristic: promote any URL-like value to FieldURL.
	if isURILike(value) {
		return FieldURL
	}

	// Default: opaque (injection + DLP).
	return FieldOpaque
}

// classifyKeyAsLeaf classifies an object key when emitted as a leaf.
// Returns -1 if the key should not be emitted (not interesting).
func classifyKeyAsLeaf(key string) FieldClass {
	if isURILike(key) {
		return FieldURL
	}
	// Don't emit boring keys - only emit keys that look like URIs or secrets.
	// Regular field names are structural, not attacker content.
	if normalizedSecretFields[normalizeFieldName(key)] {
		return FieldSecret
	}
	return -1
}

// --- A2A Detection ---

// IsA2AMethod returns true if the JSON-RPC method name is an A2A method.
func IsA2AMethod(method string) bool {
	return a2amethods.Is(method)
}

const (
	methodGetExtendedAgentCard         = "GetExtendedAgentCard"
	methodGetAuthenticatedExtendedCard = "agent/getAuthenticatedExtendedCard"
)

// isAgentCardMethod reports whether method is an A2A JSON-RPC call whose
// result is an Agent Card. Matching uses the canonical method name so a
// case variant cannot skip card signature and drift enforcement.
func isAgentCardMethod(method string) bool {
	canonical, ok := a2amethods.Canonical(method)
	if !ok {
		return false
	}
	switch canonical {
	case methodGetExtendedAgentCard, methodGetAuthenticatedExtendedCard:
		return true
	default:
		return false
	}
}

// a2aPathRe matches A2A REST endpoint paths after version prefix stripping.
// Covers: /.well-known/agent-card.json, /message:send, /message:stream,
// /tasks, /tasks/{id}, /tasks/{id}:cancel, /tasks/{id}:subscribe,
// /tasks/{id}/pushNotificationConfigs, /extendedAgentCard.
var a2aPathRe = regexp.MustCompile(
	`^(?:/\.well-known/agent-card\.json` +
		`|/message:(?:send|stream)` +
		`|/tasks(?:/[^/]+(?::(?:cancel|subscribe)|/pushNotificationConfigs(?:/[^/]+)?)?)?` +
		`|/extendedAgentCard)$`)

// versionPrefixRe matches a vN/ version prefix (without leading slash).
// Used on path[1:] to strip /vN/ from the start of a URL path.
var versionPrefixRe = regexp.MustCompile(`^v\d+(/|$)`)

// a2aContentType is the registered A2A media type.
const a2aContentType = "application/a2a+json"

// IsA2ARequest returns true if the URL path and/or Content-Type indicate
// A2A protocol traffic. Path matching strips optional /vN/ and /{tenant}/
// prefixes before comparison.
func IsA2ARequest(path, contentType string) bool {
	// Content-Type signal: application/a2a+json is definitive.
	// Use mime.ParseMediaType for exact media type comparison, ignoring
	// parameters (charset, boundary, etc.) and preventing substring matches
	// like "application/x-a2a+json" from being misdetected.
	if contentType != "" {
		mt, _, err := mime.ParseMediaType(contentType)
		if err == nil && strings.EqualFold(mt, a2aContentType) {
			return true
		}
	}

	if len(path) < 2 {
		return false
	}

	// Strip version prefix: /v1/message:send → /message:send
	stripped := stripVersionPrefix(path)
	if stripped == "" || stripped[0] != '/' {
		return false
	}

	// Try direct match.
	if a2aPathRe.MatchString(stripped) {
		return true
	}

	// Strip one tenant segment: /tenant1/message:send → /message:send
	if len(stripped) > 1 {
		if idx := strings.IndexByte(stripped[1:], '/'); idx >= 0 {
			tenantStripped := stripped[idx+1:]
			// Also strip version prefix after tenant: /tenant1/v2/tasks → /tasks
			tenantStripped = stripVersionPrefix(tenantStripped)
			if a2aPathRe.MatchString(tenantStripped) {
				return true
			}
		}
	}

	return false
}

// stripVersionPrefix removes an optional /vN/ prefix from a path.
// Input must start with '/'. "/v1/tasks" → "/tasks", "/tasks" → "/tasks".
func stripVersionPrefix(path string) string {
	if len(path) < 2 {
		return path
	}
	// Match /vN/ at the start: path[1:] starts with "vN/"
	rest := path[1:] // "v1/tasks" or "tasks/123"
	if versionPrefixRe.MatchString(rest) {
		// Find the '/' after vN
		idx := strings.IndexByte(rest, '/')
		if idx >= 0 {
			return "/" + rest[idx+1:] // "/tasks"
		}
		// /vN with no trailing content - treat as bare version path
		return "/"
	}
	return path
}

// IsAgentCardPath returns true if the path is an Agent Card endpoint.
func IsAgentCardPath(path string) bool {
	if len(path) < 2 || path[0] != '/' {
		return false
	}
	stripped := stripVersionPrefix(path)
	if isAgentCardBare(stripped) {
		return true
	}
	// Tenant variant: /{tenant}/.well-known/agent-card.json or /{tenant}/extendedAgentCard
	if len(stripped) > 1 {
		if idx := strings.IndexByte(stripped[1:], '/'); idx >= 0 {
			tenantStripped := stripVersionPrefix(stripped[idx+1:])
			return isAgentCardBare(tenantStripped)
		}
	}
	return false
}

// isAgentCardBare checks if a bare (no tenant/version prefix) path is an Agent Card endpoint.
func isAgentCardBare(path string) bool {
	return path == "/.well-known/agent-card.json" || path == "/extendedAgentCard"
}

// --- A2A Types ---

// A2APart represents a single content part in an A2A message.
// Uses proto3 oneof: exactly one of Text, URL, Raw, or Data is set.
type A2APart struct {
	Text      string          `json:"text,omitempty"`
	URL       string          `json:"url,omitempty"`
	Raw       string          `json:"raw,omitempty"` // base64-encoded bytes
	Data      json.RawMessage `json:"data,omitempty"`
	MediaType string          `json:"mediaType,omitempty"`
	Filename  string          `json:"filename,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// A2AMessage represents an A2A message with parts.
type A2AMessage struct {
	MessageID        string          `json:"messageId,omitempty"`
	Role             string          `json:"role,omitempty"`
	Parts            []A2APart       `json:"parts,omitempty"`
	ContextID        string          `json:"contextId,omitempty"`
	TaskID           string          `json:"taskId,omitempty"`
	ReferenceTaskIDs []string        `json:"referenceTaskIds,omitempty"`
	Extensions       []string        `json:"extensions,omitempty"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
}

// A2ASkill represents a skill in an Agent Card.
type A2ASkill struct {
	ID           string          `json:"id,omitempty"`
	Name         string          `json:"name,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
}

// A2AInterface represents a supported interface in an Agent Card.
type A2AInterface struct {
	URL             string `json:"url,omitempty"`
	ProtocolBinding string `json:"protocolBinding,omitempty"`
	Tenant          string `json:"tenant,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
}

// A2AExtension represents an extension declared in Agent Card capabilities.
type A2AExtension struct {
	URI         string          `json:"uri,omitempty"`
	Description string          `json:"description,omitempty"`
	Required    bool            `json:"required,omitempty"`
	Params      json.RawMessage `json:"params,omitempty"`
}

// A2ACapabilities represents Agent Card capabilities.
type A2ACapabilities struct {
	Streaming         *bool          `json:"streaming,omitempty"`
	PushNotifications *bool          `json:"pushNotifications,omitempty"`
	ExtendedAgentCard *bool          `json:"extendedAgentCard,omitempty"`
	Extensions        []A2AExtension `json:"extensions,omitempty"`
}

// A2AProvider represents the agent provider metadata.
type A2AProvider struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// A2AAgentCard represents a full Agent Card response.
type A2AAgentCard struct {
	Name                 string          `json:"name,omitempty"`
	Description          string          `json:"description,omitempty"`
	URL                  string          `json:"url,omitempty"`
	Version              string          `json:"version,omitempty"`
	DocumentationURL     string          `json:"documentationUrl,omitempty"`
	IconURL              string          `json:"iconUrl,omitempty"`
	Provider             A2AProvider     `json:"provider,omitempty"`
	Skills               []A2ASkill      `json:"skills,omitempty"`
	SupportedInterfaces  []A2AInterface  `json:"supportedInterfaces,omitempty"`
	Capabilities         A2ACapabilities `json:"capabilities,omitempty"`
	SecuritySchemes      json.RawMessage `json:"securitySchemes,omitempty"`
	SecurityRequirements json.RawMessage `json:"securityRequirements,omitempty"`
	DefaultInputModes    []string        `json:"defaultInputModes,omitempty"`
	DefaultOutputModes   []string        `json:"defaultOutputModes,omitempty"`
	// Signatures excluded from semantic hash (re-signing is not drift).
}

// A2AArtifact represents a task artifact.
type A2AArtifact struct {
	ID         string          `json:"id,omitempty"`
	Name       string          `json:"name,omitempty"`
	MediaType  string          `json:"mediaType,omitempty"`
	Parts      []A2APart       `json:"parts,omitempty"`
	Extensions []string        `json:"extensions,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// A2ATask represents an A2A task object.
type A2ATask struct {
	ID         string          `json:"id,omitempty"`
	ContextID  string          `json:"contextId,omitempty"`
	Status     json.RawMessage `json:"status,omitempty"`
	Artifacts  []A2AArtifact   `json:"artifacts,omitempty"`
	History    []A2AMessage    `json:"history,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	Extensions []string        `json:"extensions,omitempty"`
}

// A2APushNotificationConfig represents push notification configuration.
type A2APushNotificationConfig struct {
	URL            string          `json:"url,omitempty"`
	Token          string          `json:"token,omitempty"`
	Authentication json.RawMessage `json:"authentication,omitempty"` // AuthenticationInfo or variant
}

// --- Agent Card Semantic Hash ---

// HashAgentCard computes a deterministic hash of the semantic content of an
// Agent Card, excluding signatures (re-signing is not drift), provider
// (metadata), and version (version bumps are expected).
//
// Every variable-length field is LENGTH-PREFIXED rather than separated by a
// delimiter. A delimiter only frames fields unambiguously when it cannot occur
// inside one, and these fields carry attacker-controlled JSON strings that may
// contain any byte including NUL: with NUL separators the field pair
// ("a\x00b", "") and the pair ("a", "b\x00") produce identical hash input, so
// two materially different cards collide. That matters because
// cardStructuralDigest reuses this encoding to decide whether an endpoint or
// interface CHANGED, and a collision there reads as "structure unchanged" and
// downgrades a blocking structural change into an adopted descriptive one.
// Length prefixes remove the class rather than escaping one byte of it.
//
// The digest is an in-process TOFU baseline only; it is not persisted, signed,
// or carried on any wire or receipt surface, so changing the framing needs no
// migration and no format version.
func HashAgentCard(card A2AAgentCard) string {
	h := sha256.New()

	// Identity
	writeFramed(h, []byte(card.Name))
	writeFramed(h, []byte(card.Description))
	writeFramed(h, []byte(card.URL))

	// Skills (semantically sorted for determinism)
	skills := make([]A2ASkill, len(card.Skills))
	copy(skills, card.Skills)
	sort.Slice(skills, func(i, j int) bool { return lessA2ASkill(skills[i], skills[j]) })
	for _, s := range skills {
		writeFramed(h, []byte(s.ID))
		writeFramed(h, []byte(s.Name))
		writeFramed(h, []byte(s.Description))
		writeFramed(h, canonicalizeJSON(s.InputSchema))
		writeFramed(h, canonicalizeJSON(s.OutputSchema))
	}

	// Supported interfaces (sorted by URL)
	ifaces := make([]A2AInterface, len(card.SupportedInterfaces))
	copy(ifaces, card.SupportedInterfaces)
	sort.Slice(ifaces, func(i, j int) bool {
		if ifaces[i].URL != ifaces[j].URL {
			return ifaces[i].URL < ifaces[j].URL
		}
		return ifaces[i].ProtocolBinding < ifaces[j].ProtocolBinding // tie-breaker
	})
	for _, iface := range ifaces {
		writeFramed(h, []byte(iface.URL))
		writeFramed(h, []byte(iface.ProtocolBinding))
		writeFramed(h, []byte(iface.Tenant))
		writeFramed(h, []byte(iface.ProtocolVersion))
	}

	// Capabilities
	writeBool(h, card.Capabilities.Streaming)
	writeBool(h, card.Capabilities.PushNotifications)
	writeBool(h, card.Capabilities.ExtendedAgentCard)

	// Capability extensions (sorted by URI)
	exts := make([]A2AExtension, len(card.Capabilities.Extensions))
	copy(exts, card.Capabilities.Extensions)
	sort.Slice(exts, func(i, j int) bool {
		if exts[i].URI != exts[j].URI {
			return exts[i].URI < exts[j].URI
		}
		return exts[i].Description < exts[j].Description // tie-breaker
	})
	for _, ext := range exts {
		writeFramed(h, []byte(ext.URI))
		writeFramed(h, []byte(ext.Description))
		if ext.Required {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
		writeFramed(h, canonicalizeJSON(ext.Params))
	}

	// Security schemes and requirements - canonicalize JSON so
	// semantically identical objects with different key order or
	// whitespace produce the same hash.
	writeFramed(h, canonicalizeJSON(card.SecuritySchemes))
	writeFramed(h, canonicalizeJSON(card.SecurityRequirements))

	// Default modes (sorted)
	inputModes := make([]string, len(card.DefaultInputModes))
	copy(inputModes, card.DefaultInputModes)
	sort.Strings(inputModes)
	for _, m := range inputModes {
		writeFramed(h, []byte(m))
	}
	outputModes := make([]string, len(card.DefaultOutputModes))
	copy(outputModes, card.DefaultOutputModes)
	sort.Strings(outputModes)
	for _, m := range outputModes {
		writeFramed(h, []byte(m))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// writeFramed writes a length-prefixed field into the hash. The 8-byte
// big-endian length makes the field boundary independent of the field's own
// bytes, so no value can forge a boundary the way a delimiter allows.
func writeFramed(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// canonicalizeJSON parses JSON and re-serializes with sorted keys.
// Returns the original bytes if parsing fails (preserves fail-closed: hash
// still changes if the raw bytes change, which is conservative).
func canonicalizeJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw // unparseable: hash raw bytes (conservative)
	}
	// json.Marshal sorts map keys deterministically in Go.
	canonical, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return canonical
}

// writeBool writes a capability boolean to the hash. nil = 0, false = 1, true = 2.
// Distinguishes nil (unset) from false (explicitly disabled).
func writeBool(h interface{ Write([]byte) (int, error) }, v *bool) {
	if v == nil {
		_, _ = h.Write([]byte{0})
	} else if *v {
		_, _ = h.Write([]byte{2})
	} else {
		_, _ = h.Write([]byte{1})
	}
}

// lessA2ASkill imposes a total semantic ordering on skills. IDs and names are
// normally sufficient, but a malformed card can contain empty or duplicate
// IDs. The extra non-descriptive tie-breakers keep its digest independent of
// source-array order. This matters after a structural view blanks names and
// descriptions: otherwise two distinct empty-ID skills compare equal and a
// harmless reorder appears to be a structural change.
func lessA2ASkill(a, b A2ASkill) bool {
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Description != b.Description {
		return a.Description < b.Description
	}
	if cmp := bytes.Compare(canonicalizeJSON(a.InputSchema), canonicalizeJSON(b.InputSchema)); cmp != 0 {
		return cmp < 0
	}
	return bytes.Compare(canonicalizeJSON(a.OutputSchema), canonicalizeJSON(b.OutputSchema)) < 0
}

// --- Agent Card drift discrimination ---
//
// An Agent Card carries endpoints and auth by construction (url, provider.url,
// documentationUrl, securitySchemes), so blocking on the bare fact of a change
// blocks every legitimate description edit. Drift discrimination splits the card
// into two views: DESCRIPTIVE free text scanned for introduced cue classes, and
// a STRUCTURAL/ENDPOINT digest whose change always blocks. Only a change confined
// to descriptive text that introduces no cue class is adopted as the new
// baseline. This mirrors the MCP tool-drift discriminator in internal/mcp/tools.

// cardDescriptiveText returns the card's free-text fields - name, description,
// and each skill's name and description - as one normalized string for cue
// comparison. Skills use the same semantic ordering as HashAgentCard, so a
// reorder is not read as a change. Endpoint and structural fields (url,
// provider, auth, capabilities, schemas, modes, version) are deliberately absent:
// they belong to the structural digest, not the cue-scanned text, so a URL that a
// card carries by construction never registers as an egress cue.
func cardDescriptiveText(card A2AAgentCard) string {
	skills := make([]A2ASkill, len(card.Skills))
	copy(skills, card.Skills)
	sort.Slice(skills, func(i, j int) bool { return lessA2ASkill(skills[i], skills[j]) })
	var b strings.Builder
	b.WriteString(card.Name)
	b.WriteByte('\n')
	b.WriteString(card.Description)
	for _, s := range skills {
		b.WriteByte('\n')
		b.WriteString(s.Name)
		b.WriteByte('\n')
		b.WriteString(s.Description)
	}
	return b.String()
}

// cardStructuralDigest hashes everything HashAgentCard covers EXCEPT the
// descriptive free text, so a description-only edit leaves it stable and any
// endpoint/structural change (url, skill ids/schemas, interfaces, capabilities,
// security schemes/requirements, default modes) moves it. It is computed by
// blanking the descriptive fields on a copy and reusing HashAgentCard, so the
// digest cannot drift from the semantic hash's field set and coverage. Version
// is excluded (HashAgentCard already omits it), matching the rule that a bare
// version bump is descriptive for drift purposes.
//
// Fail direction: any structural field a change touches moves this digest, and a
// caller treats a moved digest as a block. Fields HashAgentCard does not cover
// (provider, documentationUrl, iconUrl) are outside this digest exactly as they
// are outside today's drift hash; widening drift to them is a separate change.
func cardStructuralDigest(card A2AAgentCard) string {
	card.Name = ""
	card.Description = ""
	blanked := make([]A2ASkill, len(card.Skills))
	for i, s := range card.Skills {
		s.Name = ""
		s.Description = ""
		blanked[i] = s
	}
	card.Skills = blanked
	return HashAgentCard(card)
}

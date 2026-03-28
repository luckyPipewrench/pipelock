// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
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
	// FieldBudgetExceeded signals the walker hit its node budget. Caller should
	// fail closed — the payload is too wide for classified scanning.
	FieldBudgetExceeded
)

const (
	// maxWalkDepth bounds recursion depth to prevent stack overflow.
	maxWalkDepth = 20
	// maxWalkNodes bounds total leaves visited to prevent CPU exhaustion
	// on wide payloads. When exceeded, walker emits FieldBudgetExceeded.
	maxWalkNodes = 10000
)

// urlFieldNames maps camelCase JSON field names that carry URLs.
// Values at any nesting depth under these keys go through the SSRF scanner.
var urlFieldNames = map[string]bool{
	// A2A core
	"url": true, "uri": true,
	"documentationUrl": true, "iconUrl": true,
	// OAuth2 / security schemes
	"authorizationUrl":       true,
	"tokenUrl":               true,
	"refreshUrl":             true,
	"deviceAuthorizationUrl": true,
	"openIdConnectUrl":       true,
	"oauth2MetadataUrl":      true,
}

// textFieldNames maps fields that carry human-readable text content.
// Values go through injection + DLP scanning.
var textFieldNames = map[string]bool{
	"text":        true,
	"description": true,
	"name":        true,
}

// secretFieldNames maps fields that carry authentication material.
// Values go through DLP scanning with high severity.
var secretFieldNames = map[string]bool{
	"credentials": true,
	"token":       true,
	"secret":      true,
	"apiKey":      true,
	"password":    true,
}

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

// snakeURLFieldNames maps snake_case variants of URL field names so
// proto-style payloads using snake_case are also recognized.
var snakeURLFieldNames = map[string]bool{
	"documentation_url":        true,
	"icon_url":                 true,
	"authorization_url":        true,
	"token_url":                true,
	"refresh_url":              true,
	"device_authorization_url": true,
	"open_id_connect_url":      true,
	"oauth2_metadata_url":      true,
}

// snakeSecretFieldNames maps snake_case variants of secret field names.
var snakeSecretFieldNames = map[string]bool{
	"api_key": true,
}

// classifyFieldName returns the FieldClass for a known field name.
// Checks both camelCase (standard proto3 JSON) and snake_case (proto-style) variants.
// Returns -1 if the name is not in any known set.
func classifyFieldName(name string) FieldClass {
	if urlFieldNames[name] || snakeURLFieldNames[name] {
		return FieldURL
	}
	if textFieldNames[name] {
		return FieldText
	}
	if secretFieldNames[name] || snakeSecretFieldNames[name] {
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

			// Emit the key itself as a leaf — keys can be URLs or secrets.
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
		// JSON null — nothing to scan.
	}
}

// classifyLeafValue classifies a string value based on its parent field name
// and the value's content (URI heuristic).
func classifyLeafValue(parentKey, value string) FieldClass {
	// Known field name takes priority. classifyFieldName checks both
	// camelCase and snake_case variants, so no separate normalization needed.
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
	// Don't emit boring keys — only emit keys that look like URIs or secrets.
	// Regular field names are structural, not attacker content.
	if secretFieldNames[key] {
		return FieldSecret
	}
	return -1
}

// --- A2A Detection ---

// a2aMethods is the set of JSON-RPC method names used by A2A.
var a2aMethods = map[string]bool{
	"SendMessage":                      true,
	"SendStreamingMessage":             true,
	"GetTask":                          true,
	"ListTasks":                        true,
	"CancelTask":                       true,
	"SubscribeToTask":                  true,
	"CreateTaskPushNotificationConfig": true,
	"GetTaskPushNotificationConfig":    true,
	"ListTaskPushNotificationConfigs":  true,
	"DeleteTaskPushNotificationConfig": true,
	"GetExtendedAgentCard":             true,
}

// IsA2AMethod returns true if the JSON-RPC method name is an A2A method.
func IsA2AMethod(method string) bool {
	return a2aMethods[method]
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
	if strings.Contains(contentType, a2aContentType) {
		return true
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
		// /vN with no trailing content — treat as bare version path
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
func HashAgentCard(card A2AAgentCard) string {
	h := sha256.New()

	// Identity
	_, _ = h.Write([]byte(card.Name))
	h.Write([]byte{0})
	_, _ = h.Write([]byte(card.Description))
	h.Write([]byte{0})

	// Skills (sorted by ID for determinism)
	skills := make([]A2ASkill, len(card.Skills))
	copy(skills, card.Skills)
	sort.Slice(skills, func(i, j int) bool {
		if skills[i].ID != skills[j].ID {
			return skills[i].ID < skills[j].ID
		}
		return skills[i].Name < skills[j].Name // tie-breaker for empty/duplicate IDs
	})
	for _, s := range skills {
		_, _ = h.Write([]byte(s.ID))
		h.Write([]byte{0})
		_, _ = h.Write([]byte(s.Name))
		h.Write([]byte{0})
		_, _ = h.Write([]byte(s.Description))
		h.Write([]byte{0})
		_, _ = h.Write(canonicalizeJSON(s.InputSchema))
		h.Write([]byte{0})
		_, _ = h.Write(canonicalizeJSON(s.OutputSchema))
		h.Write([]byte{0})
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
		_, _ = h.Write([]byte(iface.URL))
		h.Write([]byte{0})
		_, _ = h.Write([]byte(iface.ProtocolBinding))
		h.Write([]byte{0})
		_, _ = h.Write([]byte(iface.Tenant))
		h.Write([]byte{0})
		_, _ = h.Write([]byte(iface.ProtocolVersion))
		h.Write([]byte{0})
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
		_, _ = h.Write([]byte(ext.URI))
		h.Write([]byte{0})
		_, _ = h.Write([]byte(ext.Description))
		h.Write([]byte{0})
		if ext.Required {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
		_, _ = h.Write(canonicalizeJSON(ext.Params))
		h.Write([]byte{0})
	}

	// Security schemes and requirements — canonicalize JSON so
	// semantically identical objects with different key order or
	// whitespace produce the same hash.
	_, _ = h.Write(canonicalizeJSON(card.SecuritySchemes))
	h.Write([]byte{0})
	_, _ = h.Write(canonicalizeJSON(card.SecurityRequirements))
	h.Write([]byte{0})

	// Default modes (sorted)
	inputModes := make([]string, len(card.DefaultInputModes))
	copy(inputModes, card.DefaultInputModes)
	sort.Strings(inputModes)
	for _, m := range inputModes {
		_, _ = h.Write([]byte(m))
		h.Write([]byte{0})
	}
	outputModes := make([]string, len(card.DefaultOutputModes))
	copy(outputModes, card.DefaultOutputModes)
	sort.Strings(outputModes)
	for _, m := range outputModes {
		_, _ = h.Write([]byte(m))
		h.Write([]byte{0})
	}

	return hex.EncodeToString(h.Sum(nil))
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

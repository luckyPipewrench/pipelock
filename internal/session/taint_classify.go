// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"maps"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ClassificationOptions controls fail-safe action classification.
type ClassificationOptions struct {
	FailSafe bool
}

// ActionClassification carries an action class plus whether classification
// came from a concrete method/tool/path signal instead of a low-confidence
// fallback.
type ActionClassification struct {
	Class        ActionClass
	Sensitivity  ActionSensitivity
	ActionRef    string
	OverrideRefs []string
	Confident    bool
}

// ClassifyURLSource maps a URL to a taint level using host-based trust rules.
func ClassifyURLSource(rawURL string, allowlistedDomains []string) TaintLevel {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return TaintExternalUntrusted
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return TaintExternalUntrusted
	}
	if isTrustedLocalhost(host) {
		return TaintTrusted
	}
	for _, pattern := range allowlistedDomains {
		if scanner.MatchDomain(host, pattern) {
			return TaintAllowlistedReference
		}
	}
	return TaintExternalUntrusted
}

// ClassifyHTTPResponseObservation converts an HTTP response source into a taint
// observation suitable for attaching to a session.
func ClassifyHTTPResponseObservation(rawURL, contentType string, allowlistedDomains []string, promptHit bool) RiskObservation {
	level := ClassifyURLSource(rawURL, allowlistedDomains)
	return RiskObservation{
		Source: TaintSourceRef{
			URL:   rawURL,
			Kind:  "http_response",
			Level: level,
		},
		MediaSeen: IsMediaContentType(contentType) && level >= TaintAllowlistedReference,
		PromptHit: promptHit,
	}
}

// ClassifyMCPResponseObservation converts MCP tool/server output into a taint observation.
func ClassifyMCPResponseObservation(kind string, external bool, promptHit bool) RiskObservation {
	level := TaintInternalGenerated
	if external {
		level = TaintExternalUntrusted
	}
	return RiskObservation{
		Source: TaintSourceRef{
			Kind:  kind,
			Level: level,
		},
		PromptHit: promptHit,
	}
}

// IsMediaContentType reports whether a response content type is image/audio/video.
func IsMediaContentType(contentType string) bool {
	base := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return strings.HasPrefix(base, "image/") ||
		strings.HasPrefix(base, "audio/") ||
		strings.HasPrefix(base, "video/")
}

// ClassifyPathSensitivity returns the configured sensitivity for a path.
func ClassifyPathSensitivity(targetPath string, protectedPatterns, elevatedPatterns []string) ActionSensitivity {
	return ClassifyPathSensitivityWithConfidence(targetPath, protectedPatterns, elevatedPatterns, ClassificationOptions{}).Sensitivity
}

// ClassifyPathSensitivityWithConfidence returns path sensitivity plus whether
// the target path was concrete enough to classify.
func ClassifyPathSensitivityWithConfidence(targetPath string, protectedPatterns, elevatedPatterns []string, opts ClassificationOptions) ActionClassification {
	normalized := toSlash(targetPath)
	confident := strings.TrimSpace(normalized) != ""
	for _, pattern := range protectedPatterns {
		if matchPathPattern(normalized, pattern) {
			return ActionClassification{Sensitivity: SensitivityProtected, Confident: true}
		}
	}
	for _, pattern := range elevatedPatterns {
		if matchPathPattern(normalized, pattern) {
			return ActionClassification{Sensitivity: SensitivityElevated, Confident: true}
		}
	}
	if opts.FailSafe && !confident {
		return ActionClassification{Sensitivity: SensitivityProtected, Confident: false}
	}
	return ActionClassification{Sensitivity: SensitivityNormal, Confident: confident}
}

// failSafeSensitivity elevates an otherwise-normal read/browse action to
// Protected when fail-safe classification is enabled and the target could not be
// confidently classified. Centralizes the fail-safe read-path downgrade so the
// stdio/HTTP read branches do not repeat it.
func failSafeSensitivity(opts ClassificationOptions, confident bool) ActionSensitivity {
	if opts.FailSafe && !confident {
		return SensitivityProtected
	}
	return SensitivityNormal
}

// methodQuery is the HTTP QUERY method (draft-ietf-httpbis-safe-method-w-body),
// a safe method that carries a request body. Go's net/http has no constant.
const methodQuery = "QUERY"

// ClassifyHTTPAction returns the taint policy action class for an HTTP request.
func ClassifyHTTPAction(method, targetPath string, protectedPatterns, elevatedPatterns []string) (ActionClass, ActionSensitivity) {
	classified := ClassifyHTTPActionWithOptions(method, targetPath, protectedPatterns, elevatedPatterns, ClassificationOptions{})
	return classified.Class, classified.Sensitivity
}

// ClassifyHTTPActionWithOptions returns the taint policy action class for an
// HTTP request plus a confidence flag.
func ClassifyHTTPActionWithOptions(method, targetPath string, protectedPatterns, elevatedPatterns []string, opts ClassificationOptions) ActionClassification {
	pathClass := ClassifyPathSensitivityWithConfidence(targetPath, protectedPatterns, elevatedPatterns, opts)
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return ActionClassification{Class: ActionClassRead, Sensitivity: failSafeSensitivity(opts, pathClass.Confident), Confident: pathClass.Confident}
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, methodQuery:
		// The HTTP QUERY method (draft-ietf-httpbis-safe-method-w-body) carries a
		// request body; classify it with the body-bearing write methods so an
		// agent cannot move a body to an upstream at lower taint risk than POST.
		return ActionClassification{Class: ActionClassPublish, Sensitivity: pathClass.Sensitivity, Confident: pathClass.Confident}
	default:
		return ActionClassification{Class: ActionClassNetwork, Sensitivity: pathClass.Sensitivity, Confident: false}
	}
}

// ClassifyMCPToolCall returns the taint policy action class for an MCP tools/call request.
func ClassifyMCPToolCall(toolName, argsJSON string, protectedPatterns, elevatedPatterns []string) (ActionClass, ActionSensitivity, string) {
	classified := ClassifyMCPToolCallWithOptions(toolName, argsJSON, protectedPatterns, elevatedPatterns, ClassificationOptions{})
	return classified.Class, classified.Sensitivity, classified.ActionRef
}

// ClassifyMCPToolCallWithOptions returns the taint policy action class for an
// MCP tools/call request plus a confidence flag.
func ClassifyMCPToolCallWithOptions(toolName, argsJSON string, protectedPatterns, elevatedPatterns []string, opts ClassificationOptions) ActionClassification {
	name := strings.ToLower(toolName)
	args := flattenJSONStrings(argsJSON)
	legacyPath := firstPathLikeValue(args)
	legacyURL := firstURLLikeValue(args)
	targets, parsed := extractMCPActionTargets(argsJSON)
	if !parsed {
		// Malformed arguments have no trustworthy key/value structure. Keep the
		// legacy first-match behavior rather than guessing roles from raw text.
		targets.refs = compactNonEmpty(legacyPath)
		if !looksLikeURL(legacyPath) {
			targets.paths = compactNonEmpty(legacyPath)
		}
		targets.urls = compactNonEmpty(legacyURL)
	}
	pathClass := classifyMCPPathTargets(targets.refs, legacyPath, protectedPatterns, elevatedPatterns, opts)
	targetPath := pathClass.ActionRef
	targetURL := compatibleFirstTarget(targets.urls, legacyURL)
	category := chains.ClassifyTool(toolName, argsJSON, nil)

	secretTargets := secretPaths(targets.paths)
	if secretPath := compatibleFirstTarget(secretTargets, firstSecretPath(args)); secretPath != "" {
		return ActionClassification{Class: ActionClassSecret, Sensitivity: SensitivityProtected, ActionRef: secretPath, OverrideRefs: secretTargets, Confident: true}
	}

	if looksLikeShellTool(name) || category == "exec" {
		if command := firstMutatingMCPCommand(argsJSON); command != "" {
			return ActionClassification{Class: ActionClassExec, Sensitivity: classifyShellSensitivity(command, targetPath, protectedPatterns, elevatedPatterns), ActionRef: targetPath, OverrideRefs: targets.refs, Confident: true}
		}
		return ActionClassification{Class: ActionClassExec, Sensitivity: SensitivityProtected, ActionRef: targetPath, OverrideRefs: targets.refs, Confident: true}
	}

	if category == "persist" {
		return ActionClassification{Class: ActionClassExec, Sensitivity: SensitivityProtected, ActionRef: targetPath, OverrideRefs: targets.refs, Confident: true}
	}

	if looksLikeWriteTool(name) || category == "write" || hasWriteIntent(argsJSON) {
		return ActionClassification{Class: ActionClassWrite, Sensitivity: pathClass.Sensitivity, ActionRef: pathClass.ActionRef, OverrideRefs: pathClass.OverrideRefs, Confident: pathClass.Confident}
	}

	if looksLikePublishTool(name, argsJSON) || hasMutatingNetworkIntent(argsJSON) {
		return ActionClassification{Class: ActionClassPublish, Sensitivity: SensitivityElevated, ActionRef: targetURL, OverrideRefs: targets.urls, Confident: true}
	}

	if looksLikeBrowseTool(name) || category == "network" {
		if hasMutatingNetworkIntent(argsJSON) {
			return ActionClassification{Class: ActionClassPublish, Sensitivity: SensitivityElevated, ActionRef: targetURL, OverrideRefs: targets.urls, Confident: true}
		}
		return ActionClassification{Class: ActionClassBrowse, Sensitivity: SensitivityNormal, ActionRef: targetURL, OverrideRefs: targets.urls, Confident: true}
	}

	if looksLikeReadTool(name) || category == "read" || category == "list" {
		return ActionClassification{Class: ActionClassRead, Sensitivity: failSafeSensitivity(opts, pathClass.Confident), ActionRef: targetPath, OverrideRefs: pathClass.OverrideRefs, Confident: pathClass.Confident}
	}

	if hasExecIntent(argsJSON) {
		if command := firstMutatingMCPCommand(argsJSON); command != "" {
			return ActionClassification{Class: ActionClassExec, Sensitivity: classifyShellSensitivity(command, targetPath, protectedPatterns, elevatedPatterns), ActionRef: targetPath, OverrideRefs: targets.refs, Confident: true}
		}
		return ActionClassification{Class: ActionClassExec, Sensitivity: SensitivityProtected, ActionRef: targetPath, OverrideRefs: targets.refs, Confident: true}
	}

	sensitivity := SensitivityNormal
	if opts.FailSafe {
		sensitivity = SensitivityProtected
	}
	return ActionClassification{Class: ActionClassRead, Sensitivity: sensitivity, ActionRef: targetPath, OverrideRefs: pathClass.OverrideRefs, Confident: false}
}

// firstMutatingMCPCommand scans only declared command-bearing fields. It keeps
// each vector separate, so values from unrelated fields cannot manufacture a
// shell pattern merely by landing next to each other in a flattened string.
func firstMutatingMCPCommand(raw string) string {
	for _, command := range extractMCPCommands(raw) {
		if isMutatingShellCommand(command) {
			return command
		}
	}
	return ""
}

// extractMCPCommands returns one synthetic command line for each declared
// command vector. Object keys are used only to recognize a field's role; they
// never become command text. A command/cmd/script/shell field is combined with
// sibling args/argv vectors, which preserves the argument-vector boundary while
// recognizing commands that split their executable and arguments across fields.
func extractMCPCommands(raw string) []string {
	decoded, ok := decodeJSONValue(raw)
	if !ok {
		return nil
	}

	var commands []string
	var walk func(any)
	walk = func(value any) {
		switch tv := value.(type) {
		case []any:
			for _, item := range tv {
				walk(item)
			}
		case map[string]any:
			var bases, vectors []string
			for _, key := range slices.Sorted(maps.Keys(tv)) {
				role := mcpCommandFieldRole(key)
				if role != mcpCommandNone {
					// A recognized field can still hold a nested container,
					// for example {"command":{"cmd":"git","argv":[...]}}.
					// commandFieldVectors only collects strings, so without
					// this the whole subtree would go unscanned and a real
					// command would never reach the matcher.
					walk(tv[key])
				}
				switch role {
				case mcpCommandBase:
					bases = append(bases, commandFieldVectors(tv[key])...)
				case mcpCommandArgs:
					vectors = append(vectors, commandFieldVectors(tv[key])...)
				default:
					walk(tv[key])
				}
			}
			for _, base := range bases {
				commands = append(commands, base)
				for _, vector := range vectors {
					commands = append(commands, strings.TrimSpace(base+" "+vector))
				}
			}
			commands = append(commands, vectors...)
		}
	}
	walk(decoded)
	return commands
}

type mcpCommandRole uint8

const (
	mcpCommandNone mcpCommandRole = iota
	mcpCommandBase
	mcpCommandArgs
)

func mcpCommandFieldRole(key string) mcpCommandRole {
	for _, token := range splitArgumentKey(key) {
		switch token {
		// Keep this set aligned with hasExecIntent. A field that marks a call
		// as an exec but is not recognized here would have its command go
		// unscanned, which is how "program" was missed.
		case "command", "cmd", "script", "shell", "program":
			return mcpCommandBase
		case "args", "argv":
			return mcpCommandArgs
		}
	}
	return mcpCommandNone
}

func commandFieldVectors(value any) []string {
	var values []string
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case string:
			values = append(values, typed)
		case []any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(value)
	if len(values) == 0 {
		return nil
	}
	return []string{strings.Join(values, " ")}
}

type mcpActionTargets struct {
	refs  []string
	paths []string
	urls  []string
}

type mcpArgumentRole uint8

const (
	mcpArgumentUnknown mcpArgumentRole = iota
	mcpArgumentTarget
)

// extractMCPActionTargets keeps argument roles attached while walking JSON.
// Target-like keys admit path values containing spaces. Unknown keys admit
// only standalone path/URL values so an attacker cannot evade classification
// merely by renaming a parameter. Keys can expand recognition, never suppress
// it, because the calling agent controls them.
func extractMCPActionTargets(raw string) (mcpActionTargets, bool) {
	decoded, ok := decodeJSONValue(raw)
	if !ok {
		return mcpActionTargets{}, false
	}

	var targets mcpActionTargets
	var walk func(any, mcpArgumentRole)
	walk = func(value any, inheritedRole mcpArgumentRole) {
		switch tv := value.(type) {
		case string:
			if looksLikeURL(tv) {
				if inheritedRole == mcpArgumentTarget || isStandaloneArgumentValue(tv) {
					targets.refs = append(targets.refs, tv)
					targets.urls = append(targets.urls, tv)
				}
				return
			}
			if looksLikePath(tv) && (inheritedRole == mcpArgumentTarget || isStandaloneArgumentValue(tv)) {
				targets.refs = append(targets.refs, tv)
				targets.paths = append(targets.paths, tv)
			}
		case []any:
			for _, item := range tv {
				walk(item, inheritedRole)
			}
		case map[string]any:
			for _, key := range slices.Sorted(maps.Keys(tv)) {
				role := mcpArgumentRoleForKey(key)
				if role == mcpArgumentUnknown {
					role = inheritedRole
				}
				walk(tv[key], role)
			}
		}
	}
	walk(decoded, mcpArgumentUnknown)
	return targets, true
}

func mcpArgumentRoleForKey(key string) mcpArgumentRole {
	tokens := splitArgumentKey(key)
	for _, token := range tokens {
		switch token {
		case "path", "paths", "file", "files", "filename", "filenames", "filepath", "filepaths",
			"target", "targets", "dest", "destination", "src", "source", "uri", "uris", "url", "urls":
			return mcpArgumentTarget
		}
	}
	return mcpArgumentUnknown
}

func splitArgumentKey(key string) []string {
	var words []string
	var word []rune
	flush := func() {
		if len(word) == 0 {
			return
		}
		words = append(words, strings.ToLower(string(word)))
		word = word[:0]
	}
	var previous rune
	for _, current := range key {
		if !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			flush()
			previous = 0
			continue
		}
		if len(word) > 0 && unicode.IsUpper(current) && (unicode.IsLower(previous) || unicode.IsDigit(previous)) {
			flush()
		}
		word = append(word, current)
		previous = current
	}
	flush()
	return words
}

func isStandaloneArgumentValue(value string) bool {
	if strings.TrimSpace(value) != value {
		return false
	}
	if len(strings.Fields(value)) == 1 {
		return true
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "../") || strings.HasPrefix(value, "~/") ||
		strings.HasPrefix(value, `\\`) {
		return true
	}
	return len(value) >= 3 && unicode.IsLetter(rune(value[0])) && value[1] == ':' && (value[2] == '/' || value[2] == '\\')
}

func looksLikeURL(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func compactNonEmpty(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func secretPaths(paths []string) []string {
	var secrets []string
	for _, targetPath := range paths {
		if looksLikeSecretPath(targetPath) {
			secrets = append(secrets, targetPath)
		}
	}
	return secrets
}

func compatibleFirstTarget(candidates []string, legacy string) string {
	for _, candidate := range candidates {
		if candidate == legacy {
			return legacy
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func classifyMCPPathTargets(candidates []string, legacy string, protectedPatterns, elevatedPatterns []string, opts ClassificationOptions) ActionClassification {
	if len(candidates) == 0 {
		classified := ClassifyPathSensitivityWithConfidence("", protectedPatterns, elevatedPatterns, opts)
		classified.ActionRef = ""
		return classified
	}

	mostSensitive := SensitivityNormal
	for _, candidate := range candidates {
		sensitivity := ClassifyPathSensitivity(candidate, protectedPatterns, elevatedPatterns)
		if sensitivity > mostSensitive {
			mostSensitive = sensitivity
		}
	}

	if legacy != "" && ClassifyPathSensitivity(legacy, protectedPatterns, elevatedPatterns) == mostSensitive {
		for _, candidate := range candidates {
			if candidate == legacy {
				return ActionClassification{Sensitivity: mostSensitive, ActionRef: legacy, OverrideRefs: targetsWithSensitivity(candidates, mostSensitive, protectedPatterns, elevatedPatterns), Confident: true}
			}
		}
	}
	for _, candidate := range candidates {
		if ClassifyPathSensitivity(candidate, protectedPatterns, elevatedPatterns) == mostSensitive {
			return ActionClassification{Sensitivity: mostSensitive, ActionRef: candidate, OverrideRefs: targetsWithSensitivity(candidates, mostSensitive, protectedPatterns, elevatedPatterns), Confident: true}
		}
	}
	return ActionClassification{Sensitivity: mostSensitive, Confident: true}
}

func targetsWithSensitivity(candidates []string, sensitivity ActionSensitivity, protectedPatterns, elevatedPatterns []string) []string {
	var matches []string
	for _, candidate := range candidates {
		if ClassifyPathSensitivity(candidate, protectedPatterns, elevatedPatterns) == sensitivity {
			matches = append(matches, candidate)
		}
	}
	return matches
}

func classifyShellSensitivity(command, targetPath string, protectedPatterns, elevatedPatterns []string) ActionSensitivity {
	if targetPath != "" {
		return ClassifyPathSensitivity(targetPath, protectedPatterns, elevatedPatterns)
	}
	lower := strings.ToLower(command)
	if strings.Contains(lower, "git push") || strings.Contains(lower, "gh pr create") {
		return SensitivityElevated
	}
	return SensitivityProtected
}

func isTrustedLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func matchPathPattern(target, pattern string) bool {
	if target == "" || pattern == "" {
		return false
	}
	target = toSlash(target)
	pattern = toSlash(pattern)
	candidates := []string{target}
	for _, trimmed := range []string{
		strings.TrimPrefix(target, "/"),
		strings.TrimPrefix(target, "./"),
		strings.TrimPrefix(strings.TrimPrefix(target, "/"), "./"),
	} {
		if trimmed != "" && trimmed != target {
			candidates = append(candidates, trimmed)
		}
	}
	patterns := []string{pattern}
	if trimmedPattern := strings.TrimPrefix(pattern, "*/"); trimmedPattern != pattern {
		patterns = append(patterns, trimmedPattern)
	}
	for _, candidate := range candidates {
		for _, candidatePattern := range patterns {
			if matched, _ := path.Match(candidatePattern, candidate); matched {
				return true
			}
		}
	}
	for _, candidate := range candidates {
		if matched, _ := path.Match(pattern, "/"+strings.TrimPrefix(candidate, "/")); matched {
			return true
		}
	}
	suffix := strings.TrimPrefix(pattern, "*/")
	for _, candidate := range candidates {
		if strings.HasSuffix(candidate, "/"+suffix) || candidate == suffix {
			return true
		}
	}
	return false
}

func toSlash(value string) string {
	return strings.ReplaceAll(value, "\\", "/")
}

func flattenJSONStrings(raw string) []string {
	if raw == "" {
		return nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return []string{raw}
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch tv := v.(type) {
		case string:
			out = append(out, tv)
		case []any:
			for _, item := range tv {
				walk(item)
			}
		case map[string]any:
			// Sorted, not map order. Callers take the FIRST path-like,
			// URL-like or secret-like entry out of this slice and use it
			// as the action reference, which an operator's trust override
			// is then matched against. Go does not specify map iteration
			// order, so ranging tv directly can make the selection vary
			// between runs when a tool call carries distinct candidates,
			// causing the same call to match an override on one run and
			// miss it on the next.
			for _, key := range slices.Sorted(maps.Keys(tv)) {
				out = append(out, key)
				walk(tv[key])
			}
		}
	}
	walk(decoded)
	return out
}

func firstPathLikeValue(values []string) string {
	for _, value := range values {
		if looksLikePath(value) {
			return value
		}
	}
	return ""
}

func firstURLLikeValue(values []string) string {
	for _, value := range values {
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			return value
		}
	}
	return ""
}

func firstSecretPath(values []string) string {
	for _, value := range values {
		if looksLikeSecretPath(value) {
			return value
		}
	}
	return ""
}

func looksLikeShellTool(name string) bool {
	return containsAny(name, "bash", "shell", "exec", "command", "terminal", "run")
}

func looksLikeWriteTool(name string) bool {
	return containsAny(name, "write", "edit", "update", "create", "delete", "remove", "rename", "move", "patch")
}

func looksLikeReadTool(name string) bool {
	return containsAny(name, "read", "cat", "open", "list", "search", "find", "get")
}

func looksLikeBrowseTool(name string) bool {
	return containsAny(name, "browse", "fetch", "scrape", "crawl")
}

func looksLikePublishTool(name, argsJSON string) bool {
	return containsAny(name, "http", "request", "post", "put", "patch", "publish", "send", "webhook") ||
		hasMutatingNetworkMethod(argsJSON)
}

func looksLikePath(value string) bool {
	return strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "../") ||
		strings.Contains(value, "/") ||
		strings.Contains(value, `\`)
}

func looksLikeSecretPath(value string) bool {
	lower := strings.ToLower(toSlash(value))
	return strings.Contains(lower, "/.env") ||
		strings.Contains(lower, "/secrets") ||
		strings.Contains(lower, "/.ssh/") ||
		strings.Contains(lower, "/.aws/") ||
		strings.Contains(lower, "/id_rsa") ||
		strings.Contains(lower, "/id_ed25519") ||
		strings.Contains(lower, "/kubeconfig") ||
		strings.Contains(lower, "/etc/shadow") ||
		strings.Contains(lower, "/etc/passwd")
}

func isMutatingShellCommand(command string) bool {
	lower := strings.ToLower(command)
	return containsAny(lower,
		"rm ", " mv ", "mv ", "cp ", "chmod ", "chown ", "git push", "git commit",
		"apply_patch", "sed -i", "tee ", "cat >", "curl -x post", "curl -x put", "curl -x patch",
		"curl -d", "wget --post", "gh pr create", "gh pr merge", "npm publish")
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func hasWriteIntent(argsJSON string) bool {
	decoded, ok := decodeJSONValue(argsJSON)
	if ok {
		return jsonHasAnyKey(decoded, "path", "file_path", "filepath", "target_path", "destination_path", "new_path", "old_path") &&
			jsonHasAnyKey(decoded, "content", "contents", "text", "diff", "patch", "replacement", "edits", "changes")
	}
	lower := normalizeIntentJSON(argsJSON)
	return containsAny(lower,
		`"path"`, `"file_path"`, `"filepath"`, `"target_path"`, `"destination_path"`, `"new_path"`, `"old_path"`) &&
		containsAny(lower,
			`"content"`, `"contents"`, `"text"`, `"diff"`, `"patch"`, `"replacement"`, `"edits"`, `"changes"`)
}

func hasExecIntent(argsJSON string) bool {
	lower := normalizeIntentJSON(argsJSON)
	return containsAny(lower, `"command"`, `"cmd"`, `"script"`, `"shell"`, `"program"`, `"argv"`)
}

func hasMutatingNetworkIntent(argsJSON string) bool {
	decoded, ok := decodeJSONValue(argsJSON)
	if ok {
		return hasMutatingNetworkMethod(argsJSON) ||
			jsonHasAnyKey(decoded, "webhook", "endpoint", "payload", "request_body", "form_data", "upload")
	}
	lower := normalizeIntentJSON(argsJSON)
	return containsAny(lower,
		`"method":"post"`, `"method":"put"`, `"method":"patch"`, `"method":"delete"`, `"method":"query"`,
		`"webhook"`, `"endpoint"`, `"payload"`, `"request_body"`, `"form_data"`, `"upload"`)
}

func decodeJSONValue(raw string) (any, bool) {
	if raw == "" {
		return nil, false
	}
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, false
	}
	return decoded, true
}

func jsonHasAnyKey(v any, keys ...string) bool {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[strings.ToLower(key)] = struct{}{}
	}
	return jsonWalk(v, func(key string, _ any) bool {
		_, ok := allowed[strings.ToLower(key)]
		return ok
	})
}

func hasMutatingNetworkMethod(argsJSON string) bool {
	decoded, ok := decodeJSONValue(argsJSON)
	if !ok {
		lower := normalizeIntentJSON(argsJSON)
		return containsAny(lower,
			`"method":"post"`, `"method":"put"`, `"method":"patch"`, `"method":"delete"`, `"method":"query"`)
	}
	return jsonWalk(decoded, func(key string, value any) bool {
		if !strings.EqualFold(key, "method") {
			return false
		}
		method, ok := value.(string)
		if !ok {
			return false
		}
		switch strings.ToUpper(strings.TrimSpace(method)) {
		case "POST", "PUT", "PATCH", "DELETE", methodQuery:
			return true
		default:
			return false
		}
	})
}

func jsonWalk(v any, visit func(key string, value any) bool) bool {
	switch tv := v.(type) {
	case []any:
		for _, item := range tv {
			if jsonWalk(item, visit) {
				return true
			}
		}
	case map[string]any:
		for key, value := range tv {
			if visit(key, value) || jsonWalk(value, visit) {
				return true
			}
		}
	}
	return false
}

func normalizeIntentJSON(raw string) string {
	lower := strings.ToLower(raw)
	replacer := strings.NewReplacer(" ", "", "\n", "", "\r", "", "\t", "")
	return replacer.Replace(lower)
}

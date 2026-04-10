// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

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
	normalized := toSlash(targetPath)
	for _, pattern := range protectedPatterns {
		if matchPathPattern(normalized, pattern) {
			return SensitivityProtected
		}
	}
	for _, pattern := range elevatedPatterns {
		if matchPathPattern(normalized, pattern) {
			return SensitivityElevated
		}
	}
	return SensitivityNormal
}

// ClassifyHTTPAction returns the taint policy action class for an HTTP request.
func ClassifyHTTPAction(method, targetPath string, protectedPatterns, elevatedPatterns []string) (ActionClass, ActionSensitivity) {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return ActionClassRead, SensitivityNormal
	case "POST", "PUT", "PATCH", "DELETE":
		return ActionClassPublish, ClassifyPathSensitivity(targetPath, protectedPatterns, elevatedPatterns)
	default:
		return ActionClassNetwork, ClassifyPathSensitivity(targetPath, protectedPatterns, elevatedPatterns)
	}
}

// ClassifyMCPToolCall returns the taint policy action class for an MCP tools/call request.
func ClassifyMCPToolCall(toolName, argsJSON string, protectedPatterns, elevatedPatterns []string) (ActionClass, ActionSensitivity, string) {
	name := strings.ToLower(toolName)
	args := flattenJSONStrings(argsJSON)
	targetPath := firstPathLikeValue(args)
	category := chains.ClassifyTool(toolName, argsJSON, nil)

	if secretPath := firstSecretPath(args); secretPath != "" {
		return ActionClassSecret, SensitivityProtected, secretPath
	}

	if looksLikeShellTool(name) || category == "exec" {
		command := strings.Join(args, " ")
		if isMutatingShellCommand(command) {
			return ActionClassExec, classifyShellSensitivity(command, targetPath, protectedPatterns, elevatedPatterns), targetPath
		}
		return ActionClassRead, SensitivityNormal, targetPath
	}

	if category == "persist" {
		return ActionClassExec, SensitivityProtected, targetPath
	}

	if looksLikeWriteTool(name) || category == "write" || hasWriteIntent(argsJSON) {
		return ActionClassWrite, ClassifyPathSensitivity(targetPath, protectedPatterns, elevatedPatterns), targetPath
	}

	if looksLikePublishTool(name, argsJSON) || hasMutatingNetworkIntent(argsJSON) {
		return ActionClassPublish, SensitivityElevated, firstURLLikeValue(args)
	}

	if looksLikeBrowseTool(name) || category == "network" {
		if hasMutatingNetworkIntent(argsJSON) {
			return ActionClassPublish, SensitivityElevated, firstURLLikeValue(args)
		}
		return ActionClassBrowse, SensitivityNormal, firstURLLikeValue(args)
	}

	if looksLikeReadTool(name) || category == "read" || category == "list" {
		return ActionClassRead, SensitivityNormal, targetPath
	}

	if hasExecIntent(argsJSON) {
		command := strings.Join(args, " ")
		if isMutatingShellCommand(command) {
			return ActionClassExec, classifyShellSensitivity(command, targetPath, protectedPatterns, elevatedPatterns), targetPath
		}
		return ActionClassExec, SensitivityProtected, targetPath
	}

	return ActionClassRead, SensitivityNormal, targetPath
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
	trimmed := strings.TrimPrefix(target, "/")
	if trimmed != target {
		candidates = append(candidates, trimmed)
	}
	for _, candidate := range candidates {
		if matched, _ := path.Match(pattern, candidate); matched {
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
			for key, value := range tv {
				out = append(out, key)
				walk(value)
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
	lowerArgs := strings.ToLower(argsJSON)
	return containsAny(name, "http", "request", "post", "put", "patch", "publish", "send", "webhook") ||
		strings.Contains(lowerArgs, `"method":"post"`) ||
		strings.Contains(lowerArgs, `"method":"put"`) ||
		strings.Contains(lowerArgs, `"method":"patch"`)
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
	lower := strings.ToLower(argsJSON)
	return containsAny(lower,
		`"path"`, `"file_path"`, `"filepath"`, `"target_path"`, `"destination_path"`, `"new_path"`, `"old_path"`) &&
		containsAny(lower,
			`"content"`, `"contents"`, `"text"`, `"diff"`, `"patch"`, `"replacement"`, `"edits"`, `"changes"`)
}

func hasExecIntent(argsJSON string) bool {
	lower := strings.ToLower(argsJSON)
	return containsAny(lower, `"command"`, `"cmd"`, `"script"`, `"shell"`, `"program"`, `"argv"`)
}

func hasMutatingNetworkIntent(argsJSON string) bool {
	lower := strings.ToLower(argsJSON)
	return containsAny(lower,
		`"method":"post"`, `"method":"put"`, `"method":"patch"`, `"method":"delete"`,
		`"webhook"`, `"endpoint"`, `"payload"`, `"request_body"`, `"form_data"`, `"upload"`)
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"strings"
	"unicode"
)

// Risk-keyword constants. Shared with test fixtures so adding a keyword
// in one place doesn't drift from the other.
const (
	kwFilesystem = "filesystem"
	kwPostgres   = "postgres"
	kwMemory     = "memory"
)

// highRiskKeywords indicate servers with dangerous capabilities.
var highRiskKeywords = []string{
	"exec", "shell", "terminal", "bash", "run", "command",
	kwFilesystem, "fs", "file", "write", "git",
	kwPostgres, "mysql", "sqlite", "database", "db", "redis", "mongo",
	"fetch", TransportHTTP, "network", "browser", "puppeteer", "playwright",
	"slack", "email", "discord", "telegram", "send", "notify",
	"everything",
}

// mediumRiskKeywords indicate servers with moderate capabilities.
var mediumRiskKeywords = []string{
	kwMemory, "search", "context", "knowledge", "read",
	"brave", "tavily",
}

// classifyRisk determines risk level based on server name, command, and args.
// Protected servers always get low risk. Unprotected servers are ranked by
// keyword matching against known capability categories.
func classifyRisk(s MCPServer) (RiskLevel, string) {
	if s.Protection == ProtectedPipelock || s.Protection == ProtectedOther {
		return RiskLow, "wrapped by security proxy"
	}
	if s.Protection == Unknown {
		return RiskLow, "unknown protection state"
	}

	// Tokenize all identifying fields into whole words for matching.
	// This avoids false positives like "trunk" matching "run" or "debug" matching "db".
	tokens := tokenize(s.ServerName, s.Command, s.Args)

	for _, kw := range highRiskKeywords {
		if tokens[kw] {
			return RiskHigh, "matches high-risk keyword: " + kw
		}
	}
	for _, kw := range mediumRiskKeywords {
		if tokens[kw] {
			return RiskMedium, "matches medium-risk keyword: " + kw
		}
	}

	// Default for unprotected but unrecognized
	return RiskMedium, "unrecognized server, unprotected"
}

// tokenize splits the server name, command, and args into lowercase word tokens.
// Words are split on non-alphanumeric boundaries (hyphens, underscores, slashes, dots, etc.).
func tokenize(name, command string, args []string) map[string]bool {
	tokens := make(map[string]bool)
	for _, s := range append([]string{name, command}, args...) {
		for _, word := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			tokens[word] = true
		}
	}
	return tokens
}

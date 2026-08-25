// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

var coreResponsePatternNames = []string{
	"Prompt Injection",
	"System Override",
	"External Data Transfer Directive",
	"Role Override",
	"Hidden Instruction",
	"Credential Solicitation",
	"Markdown Link Credential Exfiltration",
	"Markdown Link Credential Value Exfiltration",
	"Markdown Link Credential Follow Exfiltration",
	"System Prompt Disclosure",
	"Credential Path Directive",
	"Covert Action Directive",
	"Instruction Boundary",
}

// CoreResponsePatternNames returns the immutable response floor's pattern
// names. The returned slice is safe for the caller to modify.
func CoreResponsePatternNames() []string {
	return append([]string(nil), coreResponsePatternNames...)
}

// IsCoreResponsePatternName reports whether name belongs to the immutable
// response-scanning safety floor.
func IsCoreResponsePatternName(name string) bool {
	for _, coreName := range coreResponsePatternNames {
		if strings.EqualFold(name, coreName) {
			return true
		}
	}
	return false
}

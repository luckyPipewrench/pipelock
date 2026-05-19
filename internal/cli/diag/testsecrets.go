// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import "strings"

func syntheticSecret(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p)
	}
	return b.String()
}

func syntheticRepeatedSecret(prefix string, fill byte, n int) string {
	var b strings.Builder
	b.WriteString(prefix)
	for range n {
		b.WriteByte(fill)
	}
	return b.String()
}

func syntheticAnthropicKey() string {
	return syntheticRepeatedSecret(syntheticSecret("sk-ant-", "api03-"), 'X', 28)
}

func syntheticAWSAccessKey() string {
	return syntheticRepeatedSecret("AKIA", 'A', 16)
}

func syntheticGitHubToken() string {
	return syntheticRepeatedSecret("ghp_", 'A', 36)
}

func syntheticOpenAIKey() string {
	return syntheticRepeatedSecret(syntheticSecret("sk-", "proj-"), 'A', 30)
}

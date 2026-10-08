// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

// mcpBindingInputs are the effective operator-configured parts of an MCP
// server's transport identity. Headers and child-environment overrides can
// select a different tenant, principal, or endpoint behind the same URL or
// command, so a credential-request acknowledgment binds them too. The values
// must be the ones the transport actually uses, computed once.
type mcpBindingInputs struct {
	UpstreamURL string
	Command     []string
	// Headers are the parsed upstream headers sent with every request.
	Headers http.Header
	// ChildEnv is the child-environment override list passed to the
	// subprocess, already resolved (bare --env KEY looked up once).
	ChildEnv []string
}

// mcpServerBinding returns the transport binding digest an acknowledgment
// must name. Only the digest is ever printed. Environment the operator did
// not name explicitly is inherited and is not part of the binding.
func mcpServerBinding(in mcpBindingInputs) string {
	var base string
	if in.UpstreamURL != "" {
		base = tools.UpstreamBindingDigest(in.UpstreamURL)
	} else {
		base = tools.ServerBindingDigest("subprocess", in.Command...)
	}
	parts := []string{base, "headers"}
	names := make([]string, 0, len(in.Headers))
	for name := range in.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// Values keep their order: repeated headers are sent in sequence.
		parts = append(parts, "header:"+name)
		for _, v := range in.Headers[name] {
			parts = append(parts, "value:"+v)
		}
	}
	parts = append(parts, "env")
	parts = append(parts, mcp.ChildEnvOverrideIdentity(in.ChildEnv)...)
	return tools.ServerBindingDigest("transport-v2", parts...)
}

// buildChildExtraEnv resolves the child-environment overrides once: the
// carrier-resolved entries, then each --env entry, with a bare KEY taking the
// host value through lookup. The same list is bound and passed to the child.
func buildChildExtraEnv(resolvedEnv, envVars []string, lookup func(string) (string, bool)) ([]string, error) {
	extraEnv := append([]string(nil), resolvedEnv...)
	for _, e := range envVars {
		key, _, hasValue := strings.Cut(e, "=")
		if key == "" {
			return nil, errors.New("--env requires a non-empty variable name")
		}
		if mcp.IsSafeEnvKey(key) {
			return nil, fmt.Errorf("--env %s is already set by pipelock and cannot be overridden", key)
		}
		if mcp.IsDangerousEnvKey(key) {
			return nil, fmt.Errorf("--env %s is blocked: this variable can inject code or redirect traffic in the child process", key)
		}
		if hasValue {
			extraEnv = append(extraEnv, e)
		} else if val, found := lookup(e); found {
			extraEnv = append(extraEnv, e+"="+val)
		}
	}
	return extraEnv, nil
}

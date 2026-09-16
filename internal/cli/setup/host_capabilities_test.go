// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// mcpWrappingHostRegistry is derived from HostCommands, the list the root
// command actually registers, minus the commands that deliberately carry no
// MCP wrapping contract. Deriving it rather than restating it is the point:
// a new setup command reaches the binary and this table together, and one
// that is neither declared in hostCapabilities nor listed as non-wrapping
// fails TestHostCapabilities_EnumeratedFromRegistry instead of shipping an
// undeclared installer.
func mcpWrappingHostRegistryFromCommands() []string {
	var hosts []string
	for _, c := range HostCommands() {
		name := c.Name()
		if _, skip := nonWrappingHostCommands[name]; skip {
			continue
		}
		hosts = append(hosts, name)
	}
	return hosts
}

var mcpWrappingHostRegistry = mcpWrappingHostRegistryFromCommands()

// TestHostCapabilities_EnumeratedFromRegistry proves the failure direction
// required here: a host present in the registry but missing from the
// declaration table must fail loudly, not pass silently. It is invoked both
// for the real registry (must pass) and, via
// TestHostCapabilities_FakeHostFailsClosed below, for a registry entry with
// no declaration (must fail).
func checkHostCapabilitiesRegistryParity(registry []string, declared map[string]hostCapability) []string {
	var problems []string
	for _, host := range registry {
		if _, ok := declared[host]; !ok {
			problems = append(problems, fmt.Sprintf("host %q is in mcpWrappingHostRegistry with no entry in hostCapabilities", host))
		}
	}
	for host := range declared {
		if !slices.Contains(registry, host) {
			problems = append(problems, fmt.Sprintf("host %q is declared in hostCapabilities but not in mcpWrappingHostRegistry", host))
		}
	}
	return problems
}

func TestHostCapabilities_EnumeratedFromRegistry(t *testing.T) {
	if problems := checkHostCapabilitiesRegistryParity(mcpWrappingHostRegistry, hostCapabilities); len(problems) > 0 {
		for _, p := range problems {
			t.Error(p)
		}
	}
}

// TestHostCapabilities_NonWrappingListIsPinned closes the bypass in the
// enumeration above. mcpWrappingHostRegistryFromCommands subtracts
// nonWrappingHostCommands before checking parity, so that exclusion list is
// the one place a real MCP-wrapping installer can be hidden: add it there and
// it needs no capability declaration, gets no behavioral parity test, and
// every other test in this file still passes.
//
// Pinning the set converts that silent bypass into a failing test. Growing the
// list is then a deliberate act that updates this literal, which is where a
// reviewer sees the claim "this command does not wrap MCP servers" and can
// check it. Shrinking it fails too, because a command that starts wrapping
// must gain a declaration in the same change.
func TestHostCapabilities_NonWrappingListIsPinned(t *testing.T) {
	want := []string{"claude", "cursor", "init", "pi"}
	var got []string
	for name := range nonWrappingHostCommands {
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("nonWrappingHostCommands = %v, want %v.\n"+
			"A command listed here is excluded from the capability contract entirely. "+
			"If this change adds one, confirm it does not wrap an MCP server config, then update this pin.", got, want)
	}
}

// undeclaredTestHost is a command name no installer will ever register. It
// exists only to drive the parity check's failure direction.
const undeclaredTestHost = "fakehost-not-a-real-installer"

// TestHostCapabilities_FakeHostFailsClosed is the failure-direction proof
// required here: enumerating hosts from a registry that has grown a new
// entry, with no matching declaration, must fail the parity check rather
// than pass silently.
func TestHostCapabilities_FakeHostFailsClosed(t *testing.T) {
	fakeRegistry := append(append([]string{}, mcpWrappingHostRegistry...), undeclaredTestHost)
	problems := checkHostCapabilitiesRegistryParity(fakeRegistry, hostCapabilities)
	if len(problems) == 0 {
		t.Fatal("expected the parity check to fail for an undeclared host, got no problems")
	}
	found := false
	for _, p := range problems {
		if p != "" && strings.Contains(p, undeclaredTestHost) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a problem naming the undeclared host, got: %v", problems)
	}
}

// observedHostBehavior is what TestHostCapabilities_MatchRealWrapFunctions
// derives from actually running each host's wrap function, as opposed to
// what host_capabilities.go declares.
type observedHostBehavior struct {
	headers headerCapability
	env     envCapability
	// selfWrapSkip: re-running the wrap over a server this same binary
	// already wrapped returned the identical entry, so nothing nested.
	selfWrapSkip bool
	// foreignRefusal: a wrapper this binary cannot normalize (a header-file
	// credential sidecar, an unrecognized proxy argument) was refused with
	// mcpwrap.ErrCannotNormalize rather than passed through or nested.
	foreignRefusal bool
}

// unrecoverableForeignWrapper is a command/args entry that looks like a proxy
// invocation from some OTHER pipelock binary and cannot be recovered back to
// its child, because the upstream credential lives in a header sidecar file
// the command alone does not carry. Every wrapping host must refuse it.
// It is shape-aware on purpose. OpenCode carries the whole invocation in a
// single command ARRAY and reads the wrapping binary from element zero, so a
// command/args-shaped fixture is never classified as foreign there at all. A
// fixture the host cannot even recognize produces "observed no refusal",
// which is indistinguishable from a host that genuinely fails to refuse.
func unrecoverableForeignWrapper(host string) map[string]interface{} {
	const foreignExe = "/opt/other-pipelock/pipelock"
	proxyArgs := []string{
		"mcp", "proxy", "--header-file", "/tmp/does-not-matter",
		"--upstream", "https://api.vendor.example/mcp",
	}
	if host == "opencode" {
		command := make([]interface{}, 0, len(proxyArgs)+1)
		command = append(command, foreignExe)
		for _, a := range proxyArgs {
			command = append(command, a)
		}
		return map[string]interface{}{
			mcpFieldType:    opencodeTypeRemote,
			mcpFieldCommand: command,
		}
	}
	args := make([]interface{}, 0, len(proxyArgs))
	for _, a := range proxyArgs {
		args = append(args, a)
	}
	return map[string]interface{}{
		mcpFieldType:    mcpHTTPWrapType,
		mcpFieldCommand: foreignExe,
		mcpFieldArgs:    args,
	}
}

// deriveVscodeFamilyBehavior exercises wrapVscodeServer directly (the real
// production function cline.go and zed.go delegate to via
// wrapClineServer/wrapVscodeServer) against a synthetic remote server
// carrying a header and a synthetic stdio server carrying an env var, and
// reports what actually happened to each field.
func deriveVscodeFamilyBehavior(t *testing.T, host string, wrap func(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *pipelockMeta, *sidecarOp, error)) observedHostBehavior {
	t.Helper()
	targetPath := t.TempDir() + "/mcp.json"

	remoteType := mcpHTTPWrapType
	if host == "opencode" {
		remoteType = opencodeTypeRemote
	}
	remote := map[string]interface{}{
		mcpFieldType: remoteType,
		mcpFieldURL:  "https://api.vendor.example/mcp",
		mcpFieldHeaders: map[string]interface{}{
			"Authorization": "Bearer test-only-value",
		},
	}
	result, _, plan, err := wrap(remote, "/usr/bin/pipelock", "", targetPath, "example")
	var headerObs headerCapability
	switch {
	case err != nil:
		headerObs = headerCapabilityRejected
	case plan != nil:
		if _, stillHasHeaders := result[mcpFieldHeaders]; stillHasHeaders {
			t.Fatalf("wrap produced BOTH a header sidecar plan AND left headers in the rewritten config: %v", result)
		}
		headerObs = headerCapabilitySidecar
	case result != nil:
		if _, stillHasHeaders := result[mcpFieldHeaders]; stillHasHeaders {
			headerObs = headerCapabilityUnconsumedPassthrough
		} else {
			t.Fatalf("wrap dropped the headers field with no sidecar and no error: %v", result)
		}
	default:
		t.Fatalf("wrap returned nil result and nil error")
	}

	stdio := map[string]interface{}{
		mcpFieldCommand: "/usr/bin/node",
		"env":           map[string]interface{}{"API_KEY": "test-only-value"},
	}
	if host == "opencode" {
		stdio = map[string]interface{}{
			mcpFieldCommand: []interface{}{"/usr/bin/node"},
			"environment":   map[string]interface{}{"API_KEY": "test-only-value"},
		}
	}
	result2, _, _, err2 := wrap(stdio, "/usr/bin/pipelock", "", targetPath, "example2")
	if err2 != nil {
		t.Fatalf("stdio wrap failed: %v", err2)
	}
	envObs := deriveEnvCapabilityFromArgs(t, result2)

	// Self re-wrap: feeding a wrapped entry back through the SAME binary
	// must be a no-op. A regression here nests one proxy inside another,
	// which is why the table declares it rather than assuming it.
	rewrapped, _, _, selfErr := wrap(result2, "/usr/bin/pipelock", "", targetPath, "example2")
	selfSkip := selfErr == nil && fmt.Sprint(rewrapped) == fmt.Sprint(result2)

	// Foreign wrapper this binary cannot normalize: must be refused.
	_, _, _, foreignErr := wrap(unrecoverableForeignWrapper(host), "/usr/bin/pipelock", "", targetPath, "example3")
	foreignRefused := isNormalizationFailure(foreignErr)

	return observedHostBehavior{
		headers:        headerObs,
		env:            envObs,
		selfWrapSkip:   selfSkip,
		foreignRefusal: foreignRefused,
	}
}

// deriveEnvCapabilityFromArgs inspects a wrapped server's args (or, for
// codex, a differently-shaped invocation) for how an env var crossed over:
// "--env KEY" (name only, envCapabilityKeyOnly) vs "--env KEY=VALUE"
// (literal value, envCapabilityKeyValue). Fails the test if the value
// leaked into argv when the declared capability says it should not have.
func deriveEnvCapabilityFromArgs(t *testing.T, result map[string]interface{}) envCapability {
	t.Helper()
	argsRaw, ok := result[mcpFieldArgs]
	if !ok {
		// OpenCode's "local" shape carries the whole wrapped invocation
		// (proxy binary, flags, and original command) as a single
		// "command" array rather than splitting command/args.
		argsRaw, ok = result[mcpFieldCommand]
		if !ok {
			t.Fatalf("wrapped server has no args or command to inspect: %v", result)
		}
	}
	var args []string
	switch v := argsRaw.(type) {
	case []string:
		args = v
	default:
		args = interfaceSliceToStrings(argsRaw)
	}
	for i, a := range args {
		if a == "--env" && i+1 < len(args) {
			next := args[i+1]
			if next == "API_KEY" {
				return envCapabilityKeyOnly
			}
			if next == "API_KEY=test-only-value" {
				return envCapabilityKeyValue
			}
			t.Fatalf("unexpected --env value shape: %q", next)
		}
	}
	t.Fatalf("did not find --env in wrapped args: %v", args)
	return ""
}

// TestHostCapabilities_MatchRealWrapFunctions is the non-vacuity-bearing
// parity test: for every host whose wrap function this test knows how to
// drive directly, it derives the observed header/env behavior from the real
// production function and compares it against host_capabilities.go. A
// mismatch fails naming the host and the capability.
func TestHostCapabilities_MatchRealWrapFunctions(t *testing.T) {
	cases := []struct {
		host string
		fn   func(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *pipelockMeta, *sidecarOp, error)
	}{
		{"vscode", wrapVscodeServer},
		{"opencode", wrapOpenCodeServer},
		{"cline", func(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *pipelockMeta, *sidecarOp, error) {
			return wrapClineServer(server, exe, configFile, targetConfigPath, serverName)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			observed := deriveVscodeFamilyBehavior(t, tc.host, tc.fn)
			declared, ok := hostCapabilities[tc.host]
			if !ok {
				t.Fatalf("no declaration for host %q", tc.host)
			}
			if observed.headers != declared.Headers {
				t.Errorf("host %q: declared header capability %q, observed %q", tc.host, declared.Headers, observed.headers)
			}
			if observed.env != declared.Env {
				t.Errorf("host %q: declared env capability %q, observed %q", tc.host, declared.Env, observed.env)
			}
			if observed.selfWrapSkip != declared.SelfWrapSkip {
				t.Errorf("host %q: declared SelfWrapSkip %v, observed %v", tc.host, declared.SelfWrapSkip, observed.selfWrapSkip)
			}
			if observed.foreignRefusal != declared.ForeignRefusal {
				t.Errorf("host %q: declared ForeignRefusal %v, observed %v", tc.host, declared.ForeignRefusal, observed.foreignRefusal)
			}
		})
	}

	t.Run("zed", func(t *testing.T) {
		// Zed delegates to wrapClineServer only for stdio/URL-with-no-type
		// servers; an operator-supplied "type" field routes straight to
		// wrapVscodeServer (see wrapClineServer's dispatch). The header
		// fixture below sets an explicit http type, exercising that branch,
		// which is the same function VS Code, Cline, and Zed ultimately
		// share.
		observed := deriveVscodeFamilyBehavior(t, "zed", func(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *pipelockMeta, *sidecarOp, error) {
			return wrapClineServer(server, exe, configFile, targetConfigPath, serverName)
		})
		declared := hostCapabilities["zed"]
		if observed.headers != declared.Headers {
			t.Errorf("host %q: declared header capability %q, observed %q", "zed", declared.Headers, observed.headers)
		}
		if observed.env != declared.Env {
			t.Errorf("host %q: declared env capability %q, observed %q", "zed", declared.Env, observed.env)
		}
		if observed.selfWrapSkip != declared.SelfWrapSkip {
			t.Errorf("host %q: declared SelfWrapSkip %v, observed %v", "zed", declared.SelfWrapSkip, observed.selfWrapSkip)
		}
		if observed.foreignRefusal != declared.ForeignRefusal {
			t.Errorf("host %q: declared ForeignRefusal %v, observed %v", "zed", declared.ForeignRefusal, observed.foreignRefusal)
		}
	})

	t.Run("jetbrains", func(t *testing.T) {
		remote := map[string]interface{}{
			mcpFieldType:    mcpHTTPWrapType,
			mcpFieldURL:     "https://api.vendor.example/mcp",
			mcpFieldHeaders: map[string]interface{}{"Authorization": "Bearer test-only-value"},
		}
		_, _, err := wrapMCPServer(remote, "/usr/bin/pipelock", "", false, "")
		declared := hostCapabilities["jetbrains"]
		observedHeaders := headerCapabilitySidecar
		if err != nil {
			observedHeaders = headerCapabilityRejected
		}
		if observedHeaders != declared.Headers {
			t.Errorf("host %q: declared header capability %q, observed %q (err=%v)", "jetbrains", declared.Headers, observedHeaders, err)
		}

		stdio := map[string]interface{}{
			mcpFieldCommand: "/usr/bin/node",
			"env":           map[string]interface{}{"API_KEY": "test-only-value"},
		}
		result, _, err2 := wrapMCPServer(stdio, "/usr/bin/pipelock", "", false, "")
		if err2 != nil {
			t.Fatalf("jetbrains stdio wrap failed: %v", err2)
		}
		observedEnv := deriveEnvCapabilityFromArgs(t, result)
		if observedEnv != declared.Env {
			t.Errorf("host %q: declared env capability %q, observed %q", "jetbrains", declared.Env, observedEnv)
		}

		rewrapped, _, selfErr := wrapMCPServer(result, "/usr/bin/pipelock", "", false, "")
		observedSelfSkip := selfErr == nil && fmt.Sprint(rewrapped) == fmt.Sprint(result)
		if observedSelfSkip != declared.SelfWrapSkip {
			t.Errorf("host %q: declared SelfWrapSkip %v, observed %v (err=%v)", "jetbrains", declared.SelfWrapSkip, observedSelfSkip, selfErr)
		}
		_, _, foreignErr := wrapMCPServer(unrecoverableForeignWrapper("jetbrains"), "/usr/bin/pipelock", "", false, "")
		if observedForeign := isNormalizationFailure(foreignErr); observedForeign != declared.ForeignRefusal {
			t.Errorf("host %q: declared ForeignRefusal %v, observed %v (err=%v)", "jetbrains", declared.ForeignRefusal, observedForeign, foreignErr)
		}
	})

	t.Run("continue", func(t *testing.T) {
		remote := map[string]interface{}{
			mcpFieldURL:     "https://api.vendor.example/mcp",
			mcpFieldHeaders: map[string]interface{}{"Authorization": "Bearer test-only-value"},
		}
		result, err := wrapContinueServer(remote, "/usr/bin/pipelock", "")
		declared := hostCapabilities["continue"]
		if err == nil || result != nil || !strings.Contains(err.Error(), "headers") || !strings.Contains(err.Error(), "--header-file") {
			t.Fatalf("continue must refuse remote headers with an actionable error: result=%v err=%v", result, err)
		}
		observedHeaders := headerCapabilityRejected
		if observedHeaders != declared.Headers {
			t.Errorf("host %q: declared header capability %q, observed %q", "continue", declared.Headers, observedHeaders)
		}
		delete(remote, mcpFieldHeaders)
		withoutHeaders, err := wrapContinueServer(remote, "/usr/bin/pipelock", "")
		if err != nil || !hasSubsequence(commandArgStrings(withoutHeaders[mcpFieldArgs]), []string{"--upstream", "https://api.vendor.example/mcp"}) {
			t.Fatalf("continue refused or changed the headerless positive control: result=%v err=%v", withoutHeaders, err)
		}

		stdio := map[string]interface{}{
			mcpFieldCommand: "/usr/bin/node",
			"env":           map[string]interface{}{"API_KEY": "test-only-value"},
		}
		result2, err2 := wrapContinueServer(stdio, "/usr/bin/pipelock", "")
		if err2 != nil {
			t.Fatalf("continue stdio wrap failed: %v", err2)
		}
		observedEnv := deriveEnvCapabilityFromArgs(t, result2)
		if observedEnv != declared.Env {
			t.Errorf("host %q: declared env capability %q, observed %q", "continue", declared.Env, observedEnv)
		}

		rewrapped, selfErr := wrapContinueServer(result2, "/usr/bin/pipelock", "")
		observedSelfSkip := selfErr == nil && fmt.Sprint(rewrapped) == fmt.Sprint(result2)
		if observedSelfSkip != declared.SelfWrapSkip {
			t.Errorf("host %q: declared SelfWrapSkip %v, observed %v (err=%v)", "continue", declared.SelfWrapSkip, observedSelfSkip, selfErr)
		}
		_, foreignErr := wrapContinueServer(unrecoverableForeignWrapper("continue"), "/usr/bin/pipelock", "")
		if observedForeign := isNormalizationFailure(foreignErr); observedForeign != declared.ForeignRefusal {
			t.Errorf("host %q: declared ForeignRefusal %v, observed %v (err=%v)", "continue", declared.ForeignRefusal, observedForeign, foreignErr)
		}
	})

	t.Run("codex", func(t *testing.T) {
		declared := hostCapabilities["codex"]

		headerServer := codexMCPServer{
			Name: "remote",
			Transport: codexMCPTransport{
				Type:        "streamable_http",
				URL:         "https://api.vendor.example/mcp",
				HTTPHeaders: json.RawMessage(`{"Authorization":"Bearer test-only-value"}`),
			},
		}
		reason := unsupportedCodexInstallReason(headerServer)
		observedHeaders := headerCapabilitySidecar
		if reason != "" {
			observedHeaders = headerCapabilityRejected
		}
		if observedHeaders != declared.Headers {
			t.Errorf("host %q: declared header capability %q, observed %q (reason=%q)", "codex", declared.Headers, observedHeaders, reason)
		}

		// buildCodexAddArgs is what actually runs as `codex mcp add ...`:
		// codex's own storage is not a file pipelock rewrites, it is codex's
		// live config reached only through this CLI invocation, so the
		// literal env value has to be embedded in this argv for codex to
		// persist it at all.
		addArgs := buildCodexAddArgs("example", "/usr/bin/node", nil, map[string]string{"API_KEY": "test-only-value"})
		observedEnv := envCapabilityKeyOnly
		for i, a := range addArgs {
			if a == "--env" && i+1 < len(addArgs) {
				switch addArgs[i+1] {
				case "API_KEY=test-only-value":
					observedEnv = envCapabilityKeyValue
				case "API_KEY":
					observedEnv = envCapabilityKeyOnly
				default:
					t.Fatalf("unexpected --env value shape in codex add args: %q", addArgs[i+1])
				}
			}
		}
		if observedEnv != declared.Env {
			t.Errorf("host %q: declared env capability %q, observed %q", "codex", declared.Env, observedEnv)
		}
	})
}

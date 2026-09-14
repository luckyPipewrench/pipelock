// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"slices"
	"strings"
	"testing"
)

func TestWrapServerForVSCodeCarriesEnvironmentAndDynamicHeader(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	source := map[string]interface{}{
		FieldType: "http", FieldURL: "https://api.vendor.example/mcp",
		FieldEnv:     map[string]interface{}{"SETTING": "${input:value}", "REMOVE": nil},
		FieldEnvFile: "${workspaceFolder}/server.env",
		FieldHeaders: map[string]interface{}{"Authorization": "Bearer ${input:value}", "X-Literal": "fixed"},
	}
	wrapped, meta, op, err := WrapServerForVSCode(source, "/usr/bin/pipelock", "", "/workspace/.vscode/mcp.json", "remote")
	if err != nil {
		t.Fatal(err)
	}
	if meta.SchemaVersion != 2 || meta.OriginalEnvFile != "${workspaceFolder}/server.env" || !meta.EnvFilePresent {
		t.Fatalf("metadata = %+v", meta)
	}
	args, _ := stringArgs(wrapped[FieldArgs])
	joined := strings.Join(args, " ")
	for _, want := range []string{"--header-carrier Authorization=PIPELOCK_VSCODE_HEADER_"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	for _, unwanted := range []string{"--env-carrier", "--env-unset", "--env-file-carrier"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("HTTP args %q contain irrelevant %q", joined, unwanted)
		}
	}
	if op == nil || string(op.Body()) != "X-Literal: fixed\n" {
		t.Fatalf("literal sidecar = %v", op)
	}
	carriers, ok := wrapped[FieldEnv].(map[string]interface{})
	if !ok || len(carriers) != 1 {
		t.Fatalf("carrier env = %#v", wrapped[FieldEnv])
	}
	for key := range carriers {
		if !strings.HasPrefix(key, "PIPELOCK_VSCODE_") {
			t.Fatalf("non-carrier key %q", key)
		}
	}
	headerCarrier := flagValue(args, flagHeaderCarrier)
	_, headerCarrierName, _ := strings.Cut(headerCarrier, "=")
	if carriers[headerCarrierName] != "Bearer ${input:value}" {
		t.Fatalf("header carrier %q = %#v", headerCarrierName, carriers[headerCarrierName])
	}
	restored, _, err := UnwrapServer(withMeta(wrapped, meta), "/workspace/.vscode/mcp.json", "remote")
	if err != nil {
		t.Fatal(err)
	}
	if restored[FieldEnvFile] != source[FieldEnvFile] {
		t.Fatalf("envFile round trip = %#v", restored)
	}
	if !slices.Equal(sortedKeys(restored[FieldEnv].(map[string]interface{})), []string{"REMOVE", "SETTING"}) {
		t.Fatalf("env round trip = %#v", restored[FieldEnv])
	}
}

func TestWrapServerForVSCodeCarriesStdioEnvironment(t *testing.T) {
	source := map[string]interface{}{FieldType: TypeStdio, FieldCommand: "node", FieldEnv: map[string]interface{}{"SETTING": "${input:value}", "REMOVE": nil}, FieldEnvFile: "${workspaceFolder}/server.env"}
	wrapped, meta, _, err := WrapServerForVSCode(source, "/pipelock", "", "/workspace/.vscode/mcp.json", "local")
	if err != nil {
		t.Fatal(err)
	}
	args, _ := stringArgs(wrapped[FieldArgs])
	joined := strings.Join(args, " ")
	for _, want := range []string{"--env-carrier SETTING=", "--env-unset REMOVE", "--env-file-carrier PIPELOCK_VSCODE_ENVFILE_"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	if meta.OriginalEnvFile != source[FieldEnvFile] {
		t.Fatalf("metadata = %+v", meta)
	}
	carriers := wrapped[FieldEnv].(map[string]interface{})
	_, envCarrierName, _ := strings.Cut(flagValue(args, flagEnvCarrier), "=")
	if carriers[envCarrierName] != "${input:value}" {
		t.Fatalf("env carrier %q = %#v", envCarrierName, carriers[envCarrierName])
	}
	envFileCarrierName := flagValue(args, flagEnvFileCarrier)
	if carriers[envFileCarrierName] != "${workspaceFolder}/server.env" {
		t.Fatalf("envFile carrier %q = %#v", envFileCarrierName, carriers[envFileCarrierName])
	}
}

func TestWrapServerForVSCodePreservesEmptyEnv(t *testing.T) {
	source := map[string]interface{}{FieldType: TypeStdio, FieldCommand: "node", FieldEnv: map[string]interface{}{}}
	wrapped, meta, _, err := WrapServerForVSCode(source, "/pipelock", "", "/mcp.json", "s")
	if err != nil {
		t.Fatal(err)
	}
	restored, _, err := UnwrapServer(withMeta(wrapped, meta), "/mcp.json", "s")
	if err != nil {
		t.Fatal(err)
	}
	env, present := restored[FieldEnv].(map[string]interface{})
	if !present || len(env) != 0 {
		t.Fatalf("restored env = %#v", restored[FieldEnv])
	}
}

func TestWrapServerForVSCodeRejectsInvalidEnvShapes(t *testing.T) {
	for _, env := range []interface{}{"not-an-object", map[string]interface{}{"SETTING": true}} {
		_, _, _, err := WrapServerForVSCode(map[string]interface{}{FieldType: TypeStdio, FieldCommand: "node", FieldEnv: env}, "/pipelock", "", "/mcp.json", "s")
		if err == nil {
			t.Fatalf("env %#v accepted", env)
		}
	}
}

func flagValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func TestWrapServerForVSCodeRejectsInvalidEnvFile(t *testing.T) {
	_, _, _, err := WrapServerForVSCode(map[string]interface{}{FieldType: TypeStdio, FieldCommand: "node", FieldEnvFile: 7}, "/pipelock", "", "/mcp.json", "s")
	if err == nil || !strings.Contains(err.Error(), "non-string") {
		t.Fatalf("error = %v", err)
	}
}

func TestWrapServerForVSCodeRejectsInvalidEnvTargetAtInstall(t *testing.T) {
	_, _, _, err := WrapServerForVSCode(map[string]interface{}{FieldType: TypeStdio, FieldCommand: "node", FieldEnv: map[string]interface{}{"BAD=KEY": "value"}}, "/pipelock", "", "/mcp.json", "s")
	if err == nil || !strings.Contains(err.Error(), "valid child environment") {
		t.Fatalf("error = %v", err)
	}
}

func withMeta(server map[string]interface{}, meta *Meta) map[string]interface{} {
	server[FieldPipelock] = meta
	return server
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

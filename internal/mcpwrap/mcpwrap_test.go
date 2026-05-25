// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const fakeExe = "/usr/bin/pipelock"

// argsOf returns the wrapped server's args as []string. WrapServer builds args
// as a []string, so a direct assertion is sufficient in unit tests (no YAML/JSON
// round-trip).
func argsOf(t *testing.T, server map[string]interface{}) []string {
	t.Helper()
	raw, ok := server[FieldArgs].([]string)
	if !ok {
		t.Fatalf("args is %T, want []string", server[FieldArgs])
	}
	return raw
}

func joinArgs(t *testing.T, server map[string]interface{}) string {
	return strings.Join(argsOf(t, server), " ")
}

func TestWrapServer_Stdio(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		FieldCommand: "npx",
		FieldArgs:    []interface{}{"-y", "server-github"},
		"env":        map[string]interface{}{"TOKEN": "x"},
		"timeout":    30, // unknown-to-wrap field must be preserved
	}
	out, meta, op, err := WrapServer(server, fakeExe, "/etc/pl.yaml", "/cfg/config.yaml", "github")
	if err != nil {
		t.Fatalf("WrapServer: %v", err)
	}
	if op != nil {
		t.Fatalf("stdio server should produce no sidecar op, got %+v", op)
	}
	if out[FieldCommand] != fakeExe {
		t.Errorf("command = %v, want %v", out[FieldCommand], fakeExe)
	}
	if _, hasType := out[FieldType]; hasType {
		t.Errorf("type-omitted stdio server gained a type field: %v", out[FieldType])
	}
	if out["timeout"] != 30 {
		t.Errorf("unknown field 'timeout' not preserved: %v", out["timeout"])
	}
	joined := joinArgs(t, out)
	for _, want := range []string{"mcp proxy", "--config /etc/pl.yaml", "--env TOKEN", "-- npx -y server-github"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	if meta.OriginalCommand != "npx" || !meta.ArgsPresent || !meta.TypeOmitted {
		t.Errorf("meta = %+v, want command=npx ArgsPresent TypeOmitted", meta)
	}
}

func TestWrapServer_StdioNoConfigNoEnv(t *testing.T) {
	t.Parallel()

	out, _, _, err := WrapServer(map[string]interface{}{FieldCommand: "mytool"}, fakeExe, "", "/cfg.yaml", "s")
	if err != nil {
		t.Fatalf("WrapServer: %v", err)
	}
	joined := joinArgs(t, out)
	if strings.Contains(joined, "--config") || strings.Contains(joined, "--env") {
		t.Errorf("args should have no --config/--env: %q", joined)
	}
	if !strings.HasSuffix(joined, "-- mytool") {
		t.Errorf("args = %q, want suffix '-- mytool'", joined)
	}
}

func TestWrapServer_ExplicitStdioTypeKept(t *testing.T) {
	t.Parallel()

	out, meta, _, err := WrapServer(map[string]interface{}{
		FieldType: TypeStdio, FieldCommand: "x",
	}, fakeExe, "", "/c.yaml", "s")
	if err != nil {
		t.Fatalf("WrapServer: %v", err)
	}
	if out[FieldType] != TypeStdio {
		t.Errorf("explicit type should be preserved as stdio, got %v", out[FieldType])
	}
	if meta.TypeOmitted {
		t.Error("meta.TypeOmitted should be false for explicit type")
	}
}

func TestWrapServer_HTTPInferredNoType(t *testing.T) {
	t.Parallel()

	out, meta, op, err := WrapServer(map[string]interface{}{
		FieldURL: "https://up.example/mcp",
	}, fakeExe, "", "/c.yaml", "remote")
	if err != nil {
		t.Fatalf("WrapServer: %v", err)
	}
	if op != nil {
		t.Fatalf("no headers -> no sidecar op, got %+v", op)
	}
	if _, hasType := out[FieldType]; hasType {
		t.Errorf("type-less http server gained a type field: %v", out[FieldType])
	}
	if !strings.Contains(joinArgs(t, out), "--upstream https://up.example/mcp") {
		t.Errorf("args missing --upstream: %q", joinArgs(t, out))
	}
	if meta.OriginalType != "http" || !meta.TypeOmitted || meta.OriginalURL != "https://up.example/mcp" {
		t.Errorf("meta = %+v, want OriginalType=http TypeOmitted url set", meta)
	}
}

func TestWrapServer_ExplicitHTTPTypeBecomesStdio(t *testing.T) {
	t.Parallel()

	out, meta, _, err := WrapServer(map[string]interface{}{
		FieldType: "sse", FieldURL: "https://u/mcp",
	}, fakeExe, "", "/c.yaml", "s")
	if err != nil {
		t.Fatalf("WrapServer: %v", err)
	}
	// VS Code-style explicit type: the wrapped subprocess form must be marked
	// stdio so the host launches it, and unwrap restores the original type.
	if out[FieldType] != TypeStdio {
		t.Errorf("wrapped explicit-http entry type = %v, want stdio", out[FieldType])
	}
	if meta.OriginalType != "sse" || meta.TypeOmitted {
		t.Errorf("meta = %+v, want OriginalType=sse !TypeOmitted", meta)
	}
}

func TestWrapServer_HTTPWithHeadersSidecar(t *testing.T) {
	t.Parallel()

	out, meta, op, err := WrapServer(map[string]interface{}{
		FieldURL:     "https://u/mcp",
		FieldHeaders: map[string]interface{}{"Authorization": "Bearer sk-xyz", "X-Tenant": "acme"},
	}, fakeExe, "", "/c.yaml", "remote")
	if err != nil {
		t.Fatalf("WrapServer: %v", err)
	}
	if op == nil || !op.IsWrite() {
		t.Fatal("expected a sidecar write op")
	}
	if meta.HeaderSidecarPath == "" || meta.HeaderSidecarPath != op.Path() {
		t.Errorf("meta sidecar path %q != op path %q", meta.HeaderSidecarPath, op.Path())
	}
	// The credential value must NOT appear in the wrapped argv.
	joined := joinArgs(t, out)
	if strings.Contains(joined, "sk-xyz") || strings.Contains(joined, "Bearer") {
		t.Fatalf("credential leaked into argv: %q", joined)
	}
	if !strings.Contains(joined, "--header-file "+op.Path()) {
		t.Errorf("args missing --header-file: %q", joined)
	}
	// Sidecar body has both headers, sorted, one per line.
	body := string(op.Body())
	wantBody := "Authorization: Bearer sk-xyz\nX-Tenant: acme\n"
	if body != wantBody {
		t.Errorf("sidecar body = %q, want %q", body, wantBody)
	}
	if meta.OriginalHeaders["Authorization"] != "Bearer sk-xyz" {
		t.Errorf("meta.OriginalHeaders not captured: %+v", meta.OriginalHeaders)
	}
}

func TestWrapServer_Errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		server map[string]interface{}
		want   string
	}{
		{"stdio missing command", map[string]interface{}{FieldType: TypeStdio}, "missing command"},
		{"http missing url", map[string]interface{}{FieldType: "http"}, "missing url"},
		{"type-less ambiguous command and url", map[string]interface{}{FieldCommand: "tool", FieldURL: "https://u"}, "both command and url"},
		{"non-string header", map[string]interface{}{FieldURL: "https://u", FieldHeaders: map[string]interface{}{"X": 1}}, "non-string"},
		{"reserved header", map[string]interface{}{FieldURL: "https://u", FieldHeaders: map[string]interface{}{"Content-Type": "x"}}, "managed by the MCP HTTP transport"},
		{"invalid header name", map[string]interface{}{FieldURL: "https://u", FieldHeaders: map[string]interface{}{"Bad Header": "x"}}, "invalid characters"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := WrapServer(tc.server, fakeExe, "", "/c.yaml", "s")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestUnwrapServer_RoundTrips(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		server map[string]interface{}
	}{
		{"stdio type-less", map[string]interface{}{FieldCommand: "npx", FieldArgs: []interface{}{"-y", "s"}, "env": map[string]interface{}{"K": "v"}}},
		{"stdio explicit type", map[string]interface{}{FieldType: TypeStdio, FieldCommand: "tool"}},
		{"stdio empty args", map[string]interface{}{FieldCommand: "tool", FieldArgs: []interface{}{}}},
		{"http type-less", map[string]interface{}{FieldURL: "https://u/mcp"}},
		{"http explicit sse", map[string]interface{}{FieldType: "sse", FieldURL: "https://u/mcp"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Snapshot original (deep enough for these shapes).
			orig := cloneServer(tc.server)
			wrapped, meta, _, err := WrapServer(tc.server, fakeExe, "", "/c.yaml", "s")
			if err != nil {
				t.Fatalf("WrapServer: %v", err)
			}
			wrapped[FieldPipelock] = roundTripMeta(t, meta)
			if !IsWrapped(wrapped) {
				t.Fatal("wrapped entry not detected as wrapped")
			}
			restored, _, err := UnwrapServer(wrapped)
			if err != nil {
				t.Fatalf("UnwrapServer: %v", err)
			}
			if !reflect.DeepEqual(normalize(restored), normalize(orig)) {
				t.Fatalf("round-trip mismatch:\n got  %#v\n want %#v", normalize(restored), normalize(orig))
			}
		})
	}
}

func TestUnwrapServer_NotWrapped(t *testing.T) {
	t.Parallel()

	in := map[string]interface{}{FieldCommand: "x"}
	out, op, err := UnwrapServer(in)
	if err != nil || op != nil {
		t.Fatalf("unexpected err=%v op=%v", err, op)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("non-wrapped entry should pass through unchanged")
	}
}

func TestUnwrapServer_InvalidMeta(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		meta map[string]interface{}
		want string
	}{
		{"missing command", map[string]interface{}{"original_type": "stdio"}, "missing original_command"},
		{"missing type", map[string]interface{}{"type_omitted": true}, "missing original_type"},
		{"http missing url", map[string]interface{}{"original_type": "http"}, "missing original_url"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := UnwrapServer(map[string]interface{}{FieldPipelock: tc.meta})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestParseMeta(t *testing.T) {
	t.Parallel()

	if _, ok, err := ParseMeta(map[string]interface{}{}); ok || err != nil {
		t.Fatalf("unwrapped: ok=%v err=%v", ok, err)
	}
	meta, ok, err := ParseMeta(map[string]interface{}{
		FieldPipelock: map[string]interface{}{"original_type": "stdio", "original_command": "x"},
	})
	if err != nil || !ok {
		t.Fatalf("ParseMeta: ok=%v err=%v", ok, err)
	}
	if meta.OriginalCommand != "x" {
		t.Errorf("OriginalCommand = %q, want x", meta.OriginalCommand)
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()

	if !IsHTTPType("http") || !IsHTTPType("sse") || IsHTTPType("stdio") || IsHTTPType("") {
		t.Error("IsHTTPType classification wrong")
	}
	if got := BuildEnvFlags(map[string]interface{}{"env": map[string]interface{}{"B": "2", "A": "1"}}); !reflect.DeepEqual(got, []string{"--env", "A", "--env", "B"}) {
		t.Errorf("BuildEnvFlags = %v", got)
	}
	if got := BuildEnvFlags(map[string]interface{}{}); got != nil {
		t.Errorf("BuildEnvFlags(no env) = %v, want nil", got)
	}
	if got := InterfaceSliceToStrings([]interface{}{"a", 2, "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("InterfaceSliceToStrings dropped/kept wrong: %v", got)
	}
	if got := InterfaceSliceToStrings([]string{"a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("InterfaceSliceToStrings([]string) = %v", got)
	}
	if got := InterfaceSliceToStrings("not a slice"); got != nil {
		t.Errorf("InterfaceSliceToStrings(non-slice) = %v, want nil", got)
	}
}

// --- test helpers ---

func cloneServer(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case []interface{}:
			cp := make([]interface{}, len(t))
			copy(cp, t)
			out[k] = cp
		case map[string]interface{}:
			out[k] = cloneServer(t)
		default:
			out[k] = v
		}
	}
	return out
}

// roundTripMeta serializes meta the way the installers do (JSON tags) so unwrap
// reads it back through the same path it would after a config round-trip.
func roundTripMeta(t *testing.T, meta *Meta) interface{} {
	t.Helper()
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	return out
}

// normalize coerces []string vs []interface{} arg shapes and empty maps so
// round-trip comparison ignores representation-only differences.
func normalize(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case []string:
			s := make([]interface{}, len(t))
			for i, e := range t {
				s[i] = e
			}
			out[k] = s
		case []interface{}:
			out[k] = append([]interface{}{}, t...)
		default:
			out[k] = v
		}
	}
	return out
}

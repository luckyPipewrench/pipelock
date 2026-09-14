// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestResolveHeaderCarriers(t *testing.T) {
	t.Setenv("PIPELOCK_VSCODE_TEST_HEADER", "Bearer resolved")
	got, err := resolveHeaderCarriers([]string{"Authorization=PIPELOCK_VSCODE_TEST_HEADER"})
	if err != nil || !slices.Equal(got, []string{"Authorization: Bearer resolved"}) {
		t.Fatalf("resolveHeaderCarriers() = %v, %v", got, err)
	}
	if _, err := resolveHeaderCarriers([]string{"Authorization=PIPELOCK_VSCODE_MISSING"}); err == nil || !strings.Contains(err.Error(), "unset") {
		t.Fatalf("missing carrier error = %v", err)
	}
}

func TestResolvedHeaderUsesSharedDuplicateAndReservedValidation(t *testing.T) {
	t.Setenv("PIPELOCK_VSCODE_DYNAMIC_HEADER", "second")
	resolved, err := resolveHeaderCarriers([]string{"Authorization=PIPELOCK_VSCODE_DYNAMIC_HEADER"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseHeaderFlags(append([]string{"Authorization: first"}, resolved...)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
	resolved, err = resolveHeaderCarriers([]string{"Host=PIPELOCK_VSCODE_DYNAMIC_HEADER"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseHeaderFlags(resolved); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("reserved error = %v", err)
	}
}

func TestMCPProxyCarrierEnvironmentReachesRealChild(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("shell child fixture requires Unix")
	}
	path := filepath.Join(t.TempDir(), "child.env")
	if err := os.WriteFile(path, []byte("FROM_FILE=file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIPELOCK_VSCODE_FILE_CARRIER", path)
	t.Setenv("PIPELOCK_VSCODE_INLINE_CARRIER", "inline-value")
	script := `printf '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"%s/%s"}]}}\n' "$FROM_FILE" "$FROM_INLINE"`
	stdout, stderr, err := runMCPProxyCommandWithArgs(t, []string{"proxy", "--env-file-carrier", "PIPELOCK_VSCODE_FILE_CARRIER", "--env-carrier", "FROM_INLINE=PIPELOCK_VSCODE_INLINE_CARRIER", "--", "sh", "-c", script})
	if err != nil {
		t.Fatalf("proxy failed: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "file-value/inline-value") {
		t.Fatalf("child output = %q", stdout)
	}
}

func TestResolveChildEnvironmentFilePrecedenceAndUnset(t *testing.T) {
	t.Setenv("PATH", "/base")
	t.Setenv("PIPELOCK_VSCODE_CARRIER_PATH", "/inline")
	t.Setenv("PIPELOCK_VSCODE_CARRIER_TOKEN", "inline")
	t.Setenv("PIPELOCK_VSCODE_CARRIER_FILE", filepath.Join(t.TempDir(), "server.env"))
	path := os.Getenv("PIPELOCK_VSCODE_CARRIER_FILE")
	if err := os.WriteFile(path, []byte("TOKEN=file # comment\nPATH=/file\nREMOVE=present\nQUOTED='two\\nwords'\nDOUBLE=\"two\\nlines\"\nBACKTICK=`a:b#c`\nIGNORED LINE\nCOLON: yes\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveChildEnvironment("PIPELOCK_VSCODE_CARRIER_FILE", []string{"PATH=PIPELOCK_VSCODE_CARRIER_PATH", "TOKEN=PIPELOCK_VSCODE_CARRIER_TOKEN"}, []string{"REMOVE", "HOME"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"BACKTICK=a:b#c", "COLON=yes", "DOUBLE=two\nlines", "PATH=/file" + string(os.PathListSeparator) + "/inline", "QUOTED=two\\nwords", "TOKEN=inline", "HOME", "REMOVE"}
	if !slices.Equal(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
}

func TestResolveChildEnvironmentWindowsKeysAreCaseInsensitive(t *testing.T) {
	t.Setenv("PATH", "C:\\base")
	t.Setenv("PIPELOCK_VSCODE_CARRIER_PATH", "C:\\tools")
	envFile := filepath.Join(t.TempDir(), "server.env")
	if err := os.WriteFile(envFile, []byte("Path=C:\\file\nHome=present\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIPELOCK_VSCODE_CARRIER_FILE", envFile)
	got, err := resolveChildEnvironmentForOS("PIPELOCK_VSCODE_CARRIER_FILE", []string{"Path=PIPELOCK_VSCODE_CARRIER_PATH"}, []string{"home"}, osWindows)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATH=C:\\file;C:\\tools", "HOME"}
	if !slices.Equal(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
}

func TestResolveChildEnvironmentPathFallsBackToProcess(t *testing.T) {
	t.Setenv("PATH", "/base")
	t.Setenv("PIPELOCK_VSCODE_PATH", "/tools")
	got, err := resolveChildEnvironment("", []string{"PATH=PIPELOCK_VSCODE_PATH"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATH=/base" + string(os.PathListSeparator) + "/tools"}
	if !slices.Equal(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
}

func TestResolveChildEnvironmentFailsClosed(t *testing.T) {
	t.Setenv("PIPELOCK_VSCODE_BAD_FILE", filepath.Join(t.TempDir(), "missing.env"))
	t.Setenv("PIPELOCK_VSCODE_C", "x")
	dangerousPath := filepath.Join(t.TempDir(), "dangerous.env")
	if err := os.WriteFile(dangerousPath, []byte("node_options=--require ./hook.js\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIPELOCK_VSCODE_DANGEROUS_FILE", dangerousPath)
	oversizedPath := filepath.Join(t.TempDir(), "oversized.env")
	if err := os.WriteFile(oversizedPath, []byte(strings.Repeat("A", maxVSCodeEnvFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIPELOCK_VSCODE_OVERSIZED_FILE", oversizedPath)
	directoryPath := t.TempDir()
	t.Setenv("PIPELOCK_VSCODE_DIRECTORY", directoryPath)
	for _, tc := range []struct {
		name            string
		file            string
		mappings, unset []string
		want            string
	}{
		{"missing file", "PIPELOCK_VSCODE_BAD_FILE", nil, nil, "reading VS Code envFile"},
		{"dangerous envFile key", "PIPELOCK_VSCODE_DANGEROUS_FILE", nil, nil, "blocked"},
		{"oversized envFile", "PIPELOCK_VSCODE_OVERSIZED_FILE", nil, nil, "exceeds"},
		{"directory envFile", "PIPELOCK_VSCODE_DIRECTORY", nil, nil, "regular"},
		{"missing carrier", "", []string{"TOKEN=PIPELOCK_VSCODE_ABSENT_CARRIER"}, nil, "unset"},
		{"dangerous target", "", []string{"NODE_OPTIONS=PIPELOCK_VSCODE_C"}, nil, "blocked"},
		{"malformed mapping", "", []string{"TOKEN"}, nil, "TARGET=CARRIER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveChildEnvironment(tc.file, tc.mappings, tc.unset)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCarrierValidationErrorBranches(t *testing.T) {
	t.Setenv("PIPELOCK_VSCODE_INLINE", "value")
	cases := []struct {
		name string
		fn   func() error
		want string
	}{
		{"malformed header mapping", func() error { _, err := resolveHeaderCarriers([]string{"HeaderOnly"}); return err }, "TARGET=CARRIER"},
		{"missing envFile carrier", func() error {
			_, err := resolveChildEnvironment("PIPELOCK_VSCODE_MISSING_ENVFILE_CARRIER", nil, nil)
			return err
		}, "required carrier"},
		{"arbitrary envFile carrier namespace", func() error {
			_, err := resolveChildEnvironment("SECRET_FILE", nil, nil)
			return err
		}, "namespace"},
		{"invalid unset target", func() error { _, err := resolveChildEnvironment("", nil, []string{"BAD=KEY"}); return err }, "invalid environment"},
		{"invalid carrier name", func() error { _, err := resolveChildEnvironment("", []string{"VALUE=1BAD"}, nil); return err }, "invalid carrier"},
		{"invalid carrier punctuation", func() error {
			_, err := resolveChildEnvironment("", []string{"VALUE=PIPELOCK_VSCODE_BAD-NAME"}, nil)
			return err
		}, "invalid carrier"},
		{"arbitrary carrier namespace", func() error { _, err := resolveChildEnvironment("", []string{"VALUE=SECRET"}, nil); return err }, "namespace"},
		{"invalid mapped target", func() error {
			_, err := resolveChildEnvironment("", []string{"BAD\x00KEY=PIPELOCK_VSCODE_INLINE"}, nil)
			return err
		}, "invalid environment"},
		{"missing mapped carrier", func() error {
			_, err := resolveChildEnvironment("", []string{"VALUE=PIPELOCK_VSCODE_MISSING_VALUE_CARRIER"}, nil)
			return err
		}, "required carrier"},
		{"unopenable envFile parent", func() error { _, err := readVSCodeEnvFile("/path/that/does/not/exist/file.env"); return err }, "reading VS Code envFile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

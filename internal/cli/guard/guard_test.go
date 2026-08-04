// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const testGuardConfig = `guard:
  profiles:
    - name: worker
      manifests: [workspace, credentials]
    - name: reader
      manifests: [workspace]
  manifests:
    - name: workspace
      read_only:
        - /opt/app/config.yaml
      read_only_directories:
        - /opt/app/assets
      read_write:
        - /var/lib/app/data.db
      read_write_directories:
        - /var/lib/app/cache
    - name: credentials
      read_only:
        - /home/someoperator/.ssh/id_ed25519
      read_only_directories:
        - /home/someoperator/.aws
      read_write:
        - /usr/bin/helper
      read_write_directories:
        - /etc/systemd/system
    - name: orphan
      read_only:
        - /opt/app/orphan.txt
`

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("writer failed")
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func runCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestExplainHumanCompiledFloorHonesty(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, testGuardConfig)
	out, err := runCommand(t, "--config", configPath, "explain", "/home/someoperator/.ssh/id_ed25519")
	if err != nil {
		t.Fatalf("guard explain: %v", err)
	}
	for _, want := range []string{
		"WARNING: Guard is not enforced in this build",
		"READ: WOULD BE REFUSED BY COMPILED FLOOR",
		"WRITE: WOULD BE REFUSED BY COMPILED FLOOR",
		"Rule: forbidden_component",
		"Matched: \".ssh\"",
		"cannot be configured away",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestExplainJSONOperatorGrantsAndNoInference(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, testGuardConfig)
	tests := []struct {
		name          string
		path          string
		wantRead      bool
		wantWrite     bool
		wantReadRule  string
		wantWriteRule string
	}{
		{name: "read_only_exact_file", path: "/opt/app/config.yaml", wantRead: true, wantReadRule: "exact_file_grant", wantWriteRule: "default_no_grant"},
		{name: "read_write_exact_file", path: "/var/lib/app/data.db", wantRead: true, wantWrite: true, wantReadRule: "exact_file_grant", wantWriteRule: "exact_file_grant"},
		{name: "read_only_directory_root", path: "/opt/app/assets", wantRead: true, wantReadRule: "directory_subtree_grant", wantWriteRule: "default_no_grant"},
		{name: "read_only_directory_descendant", path: "/opt/app/assets/logo.svg", wantRead: true, wantReadRule: "directory_subtree_grant", wantWriteRule: "default_no_grant"},
		{name: "read_write_directory_descendant", path: "/var/lib/app/cache/item", wantRead: true, wantWrite: true, wantReadRule: "directory_subtree_grant", wantWriteRule: "directory_subtree_grant"},
		{name: "directory_prefix_is_not_subtree", path: "/opt/app/assets-old/logo.svg", wantReadRule: "default_no_grant", wantWriteRule: "default_no_grant"},
		{name: "no_subtree_inference", path: "/opt/app/config.yaml/child", wantReadRule: "default_no_grant", wantWriteRule: "default_no_grant"},
		{name: "unselected_manifest", path: "/opt/app/orphan.txt", wantReadRule: "default_no_grant", wantWriteRule: "default_no_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := runCommand(t, "explain", tt.path, "--config", configPath, "--json")
			if err != nil {
				t.Fatalf("guard explain: %v", err)
			}
			var report explainReport
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("decode JSON: %v\n%s", err, out)
			}
			if report.SchemaVersion != reportSchemaVersion || report.Command != "explain" || report.Enforced {
				t.Fatalf("bad stable header: %+v", report.reportHeader)
			}
			if report.Read.WouldBeAllowed != tt.wantRead || report.Write.WouldBeAllowed != tt.wantWrite {
				t.Fatalf("allow decisions read=%t write=%t", report.Read.WouldBeAllowed, report.Write.WouldBeAllowed)
			}
			if report.Read.Rule != tt.wantReadRule || report.Write.Rule != tt.wantWriteRule {
				t.Fatalf("rules read=%q write=%q", report.Read.Rule, report.Write.Rule)
			}
			if report.Read.Grants == nil || report.Write.Grants == nil {
				t.Fatal("stable JSON arrays must encode as [] rather than null")
			}
			for _, grant := range append(append([]grantMatch{}, report.Read.Grants...), report.Write.Grants...) {
				if grant.Profiles == nil {
					t.Fatalf("grant profiles must encode as [] rather than null: %+v", grant)
				}
			}
		})
	}
}

func TestExplainFloorOverridesSelectedGrant(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, testGuardConfig)
	out, err := runCommand(t, "explain", "/usr/bin/helper", "--config", configPath, "--json")
	if err != nil {
		t.Fatalf("guard explain: %v", err)
	}
	var report explainReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if !report.Read.WouldBeAllowed || report.Read.Source != "operator_declared" {
		t.Fatalf("read decision = %+v", report.Read)
	}
	if report.Write.WouldBeAllowed || report.Write.Source != "compiled_floor" || report.Write.Configurable {
		t.Fatalf("write decision = %+v", report.Write)
	}
	if len(report.Write.Grants) != 1 || !report.Write.Grants[0].Effective {
		t.Fatalf("floor report should retain overridden grant: %+v", report.Write.Grants)
	}
}

func TestExplainUnselectedGrantHuman(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, testGuardConfig)
	out, err := runCommand(t, "explain", "/opt/app/orphan.txt", "--config", configPath)
	if err != nil {
		t.Fatalf("guard explain: %v", err)
	}
	if !strings.Contains(out, "Unselected declaration: \"orphan\".read_only") || !strings.Contains(out, "no profile selects this manifest") {
		t.Fatalf("unselected grant not explained:\n%s", out)
	}
}

func TestExplainDirectoryGrantHuman(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, testGuardConfig)
	out, err := runCommand(t, "explain", "/opt/app/assets/logo.svg", "--config", configPath)
	if err != nil {
		t.Fatalf("guard explain: %v", err)
	}
	if !strings.Contains(out, "\"workspace\".read_only_directories directory subtree \"/opt/app/assets\"") {
		t.Fatalf("directory type and subtree scope not explained:\n%s", out)
	}
}

func TestShowJSONResolvedProfileAndFloorRefusals(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, testGuardConfig)
	out, err := runCommand(t, "show", "worker", "--config", configPath, "--json")
	if err != nil {
		t.Fatalf("guard show: %v", err)
	}
	var report showReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, out)
	}
	if report.Command != "show" || report.Profile != "worker" || report.Enforced {
		t.Fatalf("bad report header/profile: %+v", report)
	}
	if len(report.Manifests) != 2 || report.Manifests[0].Name != "workspace" || report.Manifests[1].Name != "credentials" {
		t.Fatalf("resolved manifests = %+v", report.Manifests)
	}
	credentials := report.Manifests[1]
	if len(credentials.Grants) != 4 {
		t.Fatalf("credential grants = %+v", credentials.Grants)
	}
	if got := credentials.Grants[0].Refusals; credentials.Grants[0].GrantType != "read_only" || credentials.Grants[0].Scope != "file" || len(got) != 1 || got[0].Operation != "read" || got[0].Rule != "forbidden_component" {
		t.Fatalf("read-only floor refusals = %+v", got)
	}
	if got := credentials.Grants[1].Refusals; credentials.Grants[1].GrantType != "read_only_directories" || credentials.Grants[1].Scope != "directory" || len(got) != 1 || got[0].Rule != "forbidden_component" {
		t.Fatalf("read-only directory floor refusals = %+v", got)
	}
	if got := credentials.Grants[2].Refusals; credentials.Grants[2].GrantType != "read_write" || credentials.Grants[2].Scope != "file" || len(got) != 1 || got[0].Operation != "write" || got[0].Rule != "dangerous_write_root" {
		t.Fatalf("read-write floor refusals = %+v", got)
	}
	if got := credentials.Grants[3].Refusals; credentials.Grants[3].GrantType != "read_write_directories" || credentials.Grants[3].Scope != "directory" || len(got) != 1 || got[0].Operation != "write" || got[0].Rule != "dangerous_write_root" {
		t.Fatalf("read-write directory floor refusals = %+v", got)
	}
	if report.Manifests[0].Grants[0].Refusals == nil {
		t.Fatal("stable floor_refusals array must not be null")
	}
}

func TestShowHumanEmptyAndRefusedGrants(t *testing.T) {
	t.Parallel()
	body := strings.Replace(testGuardConfig, "  manifests:\n", "    - name: empty\n      manifests: []\n  manifests:\n", 1)
	configPath := writeConfig(t, body)
	out, err := runCommand(t, "show", "worker", "--config", configPath)
	if err != nil {
		t.Fatalf("guard show worker: %v", err)
	}
	for _, want := range []string{"WARNING: Guard is not enforced", "Manifest: \"workspace\"", "compiled floor: no refusal", "COMPILED FLOOR REFUSAL", "cannot be configured away"} {
		if !strings.Contains(out, want) {
			t.Errorf("worker output missing %q:\n%s", want, out)
		}
	}

	out, err = runCommand(t, "show", "empty", "--config", configPath)
	if err != nil {
		t.Fatalf("guard show empty: %v", err)
	}
	if !strings.Contains(out, "Manifests: none") {
		t.Fatalf("empty profile output:\n%s", out)
	}
}

func TestShowManifestWithNoGrants(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, "guard:\n  profiles:\n    - name: worker\n      manifests: [empty]\n  manifests:\n    - name: empty\n")
	out, err := runCommand(t, "show", "worker", "--config", configPath)
	if err != nil {
		t.Fatalf("guard show: %v", err)
	}
	if !strings.Contains(out, "Grants: none") {
		t.Fatalf("empty manifest output:\n%s", out)
	}
}

func TestCommandErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config string
		args   []string
		want   string
	}{
		{name: "relative_explain_path", config: testGuardConfig, args: []string{"explain", "relative/path"}, want: "absolute"},
		{name: "unknown_profile", config: testGuardConfig, args: []string{"show", "missing"}, want: "not found"},
		{name: "unknown_manifest", config: "guard:\n  profiles:\n    - name: worker\n      manifests: [missing]\n", args: []string{"show", "worker"}, want: "unknown manifest"},
		{name: "relative_grant", config: "guard:\n  manifests:\n    - name: bad\n      read_only: [relative/path]\n", args: []string{"explain", "/opt/app"}, want: "must be absolute"},
		{name: "file_directory_conflict_case_folded", config: "guard:\n  manifests:\n    - name: bad\n      read_only: [/opt/app/Config]\n      read_only_directories: [/opt/app/config/]\n", args: []string{"explain", "/opt/app/config"}, want: "conflicts"},
		{name: "unknown_yaml_field", config: "guard:\n  unknown: true\n", args: []string{"explain", "/opt/app"}, want: "field unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			configPath := writeConfig(t, tt.config)
			args := append(append([]string(nil), tt.args...), "--config", configPath)
			_, err := runCommand(t, args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
	_, err := runCommand(t, "explain", "/opt/app", "--config", filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "loading config") {
		t.Fatalf("missing config error = %v", err)
	}
}

func TestDefaultConfigAndArgumentValidation(t *testing.T) {
	t.Parallel()
	help, err := runCommand(t)
	if err != nil || !strings.Contains(help, "Inspect unenforced guard declarations") {
		t.Fatalf("guard parent help: err=%v output=%q", err, help)
	}
	out, err := runCommand(t, "explain", "/opt/app", "--json")
	if err != nil {
		t.Fatalf("default explain: %v", err)
	}
	if !strings.Contains(out, `"config_file": "(built-in defaults)"`) {
		t.Fatalf("default config label missing:\n%s", out)
	}
	for _, args := range [][]string{{"guard-extra"}, {"explain"}, {"show"}, {"explain", "/opt/app", "/opt/extra"}} {
		if _, err := runCommand(t, args...); err == nil {
			t.Fatalf("args %v should fail", args)
		}
	}
}

func TestCommandsDoNotModifyConfigOrDirectory(t *testing.T) {
	t.Parallel()

	configPath := writeConfig(t, testGuardConfig)
	before, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatalf("read config before commands: %v", err)
	}
	beforeInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config before commands: %v", err)
	}
	beforeEntries, err := os.ReadDir(filepath.Dir(configPath))
	if err != nil {
		t.Fatalf("read config directory before commands: %v", err)
	}

	for _, args := range [][]string{
		{"explain", "/opt/app/config.yaml", "--config", configPath},
		{"explain", "/opt/app/config.yaml", "--config", configPath, "--json"},
		{"show", "worker", "--config", configPath},
		{"show", "worker", "--config", configPath, "--json"},
	} {
		if _, err := runCommand(t, args...); err != nil {
			t.Fatalf("args %v: %v", args, err)
		}
	}

	after, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatalf("read config after commands: %v", err)
	}
	afterInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config after commands: %v", err)
	}
	afterEntries, err := os.ReadDir(filepath.Dir(configPath))
	if err != nil {
		t.Fatalf("read config directory after commands: %v", err)
	}
	if !bytes.Equal(before, after) || beforeInfo.Mode() != afterInfo.Mode() || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("guard inspection modified the config file")
	}
	if len(beforeEntries) != len(afterEntries) {
		t.Fatalf("guard inspection changed directory entries: before=%d after=%d", len(beforeEntries), len(afterEntries))
	}
	for i := range beforeEntries {
		if beforeEntries[i].Name() != afterEntries[i].Name() {
			t.Fatalf("guard inspection changed directory entry %d: before=%q after=%q", i, beforeEntries[i].Name(), afterEntries[i].Name())
		}
	}
}

func TestOutputErrors(t *testing.T) {
	t.Parallel()
	configPath := writeConfig(t, testGuardConfig)
	for _, args := range [][]string{
		{"explain", "/opt/app/config.yaml", "--config", configPath},
		{"show", "worker", "--config", configPath},
		{"explain", "/opt/app/config.yaml", "--config", configPath, "--json"},
		{"show", "worker", "--config", configPath, "--json"},
	} {
		cmd := Cmd()
		cmd.SetOut(failingWriter{})
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "writer failed") {
			t.Fatalf("args %v error = %v", args, err)
		}
	}
}

func TestBuildGrantReportRejectsRelativePath(t *testing.T) {
	t.Parallel()
	if _, err := buildGrantReport("read_only", "file", "relative/path"); err == nil {
		t.Fatal("relative grant report should fail")
	}
}

func TestPathWithinDirectoryRootAndBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		directory string
		want      bool
	}{
		{name: "root_covers_absolute", path: "/opt/app", directory: "/", want: true},
		{name: "directory_itself", path: "/opt/app", directory: "/opt/app", want: true},
		{name: "descendant", path: "/opt/app/state/file", directory: "/opt/app", want: true},
		{name: "textual_prefix_only", path: "/opt/application", directory: "/opt/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathWithinDirectory(tt.path, tt.directory); got != tt.want {
				t.Fatalf("pathWithinDirectory(%q, %q) = %t, want %t", tt.path, tt.directory, got, tt.want)
			}
		})
	}
}

func TestManifestProfilesPreservesSelectors(t *testing.T) {
	t.Parallel()
	profiles := manifestProfiles(config.Guard{Profiles: []config.GuardProfile{
		{Name: "worker", Manifests: []string{"state"}},
		{Name: "reader", Manifests: []string{"state"}},
	}})
	if got := strings.Join(profiles["state"], ","); got != "worker,reader" {
		t.Fatalf("selectors = %q", got)
	}
}

// TestExplainHumanOutputNeutralisesTerminalControls is the honesty guard for
// the human report.
//
// Every report is required to carry the "not enforced" warning, because an
// operator reading a clean explain must never conclude a workload is
// constrained when nothing constrains it yet. Human output interpolates
// operator-supplied paths, so a path carrying a newline can forge an extra
// report line and one carrying an escape sequence can reposition or recolour
// the terminal well enough to hide that warning in a transcript kept as
// evidence. Neither may survive into the rendered output.
func TestExplainHumanOutputNeutralisesTerminalControls(t *testing.T) {
	t.Parallel()

	configPath := writeConfig(t, testGuardConfig)
	hostile := "/opt/app/\x1b[2Jforged\nREAD: ALLOWED\x07"

	out, err := runCommand(t, "explain", hostile, "--config", configPath)
	if err != nil {
		t.Fatalf("guard explain: %v", err)
	}

	for _, control := range []string{"\x1b", "\x07"} {
		if strings.Contains(out, control) {
			t.Errorf("rendered output still carries the control byte %q, so a crafted path can rewrite the terminal:\n%q", control, out)
		}
	}
	// The forged line must not appear as its own line. It may appear inside a
	// quoted value, which is the point of quoting.
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "READ: ALLOWED" {
			t.Errorf("a crafted path forged a standalone verdict line:\n%q", out)
		}
	}
	if !strings.Contains(out, "WARNING:") {
		t.Errorf("the not-enforced warning must survive a hostile path:\n%q", out)
	}
}

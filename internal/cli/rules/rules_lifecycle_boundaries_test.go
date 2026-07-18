// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

type rulesErrorWriter struct {
	writes int
}

func (w *rulesErrorWriter) Write(_ []byte) (int, error) {
	w.writes++
	return 0, errors.New("output unavailable")
}

type rulesRoundTripper func(*http.Request) (*http.Response, error)

func (fn rulesRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type rulesFailingBody struct{}

func (rulesFailingBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (rulesFailingBody) Close() error             { return nil }

func TestRulesCommands_RejectRulesPathThatIsAFileWithoutSuccessOutput(t *testing.T) {
	commands := []struct {
		name string
		args []string
	}{
		{name: "install", args: []string{"rules", "install", "--path", "missing", "--allow-unsigned"}},
		{name: "update", args: []string{"rules", "update"}},
		{name: "remove", args: []string{"rules", "remove", "bundle"}},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			rulesPath := filepath.Join(root, "rules")
			original := []byte("operator-owned")
			if err := os.WriteFile(rulesPath, original, 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := testRootCmd()
			cmd.SilenceUsage = true
			var stdout strings.Builder
			cmd.SetOut(&stdout)
			args := append(append([]string{}, tc.args...), "--rules-dir", rulesPath)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "creating rules directory") {
				t.Fatalf("error = %v, want rules-directory rejection", err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("failure emitted success output: %q", stdout.String())
			}
			assertRulesFile(t, rulesPath, original)
		})
	}
}

func TestRulesReadCommands_RejectRulesPathThatIsAFile(t *testing.T) {
	commands := []struct {
		name string
		args []string
		want string
	}{
		{name: "list", args: []string{"rules", "list"}, want: "reading rules directory"},
		{name: "verify", args: []string{"rules", "verify"}, want: "reading rules directory"},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			rulesPath := filepath.Join(t.TempDir(), "rules")
			if err := os.WriteFile(rulesPath, []byte("not a directory"), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := testRootCmd()
			cmd.SilenceUsage = true
			var stdout strings.Builder
			cmd.SetOut(&stdout)
			cmd.SetArgs(append(tc.args, "--rules-dir", rulesPath))
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("failure emitted output: %q", stdout.String())
			}
		})
	}
}

func TestRulesList_SkipsMalformedAndUnmanagedEntries(t *testing.T) {
	rulesDir := t.TempDir()
	for _, dir := range []string{".hidden", "old.bak", "missing-lock", "bad-lock"} {
		if err := os.Mkdir(filepath.Join(rulesDir, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "ordinary-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "bad-lock", "bundle.lock"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := testRootCmd()
	var stdout strings.Builder
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"rules", "list", "--rules-dir", rulesDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list malformed entries: %v", err)
	}
	if stdout.String() != "No bundles installed.\n" {
		t.Fatalf("unmanaged entries were reported as installed: %q", stdout.String())
	}
}

func TestRulesStatusAndList_PropagateOutputFailure(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "status", args: []string{"rules", "status", "--json"}},
		{name: "list", args: []string{"rules", "list", "--json"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writer := &rulesErrorWriter{}
			cmd := testRootCmd()
			cmd.SilenceUsage = true
			cmd.SetOut(writer)
			args := append([]string{}, tc.args...)
			if tc.name == "list" {
				rulesDir := t.TempDir()
				setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))
				args = append(args, "--rules-dir", rulesDir)
			}
			cmd.SetArgs(args)
			if err := cmd.Execute(); err == nil {
				t.Fatal("output failure was swallowed")
			}
			if writer.writes == 0 {
				t.Fatal("command did not attempt output")
			}
		})
	}
}

func TestRulesConfigFailureStopsBeforeReadingOrMutatingBundles(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("rules: [broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := t.TempDir()
	marker := filepath.Join(rulesDir, "marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "status", args: []string{"rules", "status", "--config", configPath}},
		{name: "update", args: []string{"rules", "update", "--config", configPath, "--rules-dir", rulesDir}},
		{name: "verify", args: []string{"rules", "verify", "--config", configPath, "--rules-dir", rulesDir}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := testRootCmd()
			cmd.SilenceUsage = true
			var stdout strings.Builder
			cmd.SetOut(&stdout)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "loading config") {
				t.Fatalf("error = %v, want config rejection", err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("config failure emitted success output: %q", stdout.String())
			}
			assertRulesFile(t, marker, []byte("unchanged"))
		})
	}
}

func TestInstallLocal_MalformedInputsLeaveRulesDirectoryEmpty(t *testing.T) {
	oversized := bytes.Repeat([]byte("x"), domrules.MaxBundleFileSize+1)
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "missing manifest", want: "reading local bundle"},
		{name: "oversized manifest", body: oversized, want: "exceeds maximum size"},
		{name: "malformed manifest", body: []byte("rules: [broken\n"), want: "parsing bundle"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			sourceDir := t.TempDir()
			if tc.body != nil {
				if err := os.WriteFile(filepath.Join(sourceDir, "bundle.yaml"), tc.body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout strings.Builder
			err := installLocal(&stdout, rulesDir, sourceDir, true)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("rejected install emitted output: %q", stdout.String())
			}
			entries, readErr := os.ReadDir(rulesDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("rejected install left partial entries: %v", entries)
			}
		})
	}
}

func TestStageBundle_StagingCreationFailureLeavesExistingBundle(t *testing.T) {
	rulesDir := t.TempDir()
	destDir := filepath.Join(rulesDir, "stable")
	if err := os.Mkdir(destDir, 0o750); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(destDir, "bundle.yaml")
	if err := os.WriteFile(oldPath, []byte("last known good"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := stageBundle(rulesDir, "nested/name", []byte("replacement"), nil, &domrules.LockFile{})
	if err == nil || !strings.Contains(err.Error(), "creating staging directory") {
		t.Fatalf("error = %v, want staging creation failure", err)
	}
	assertRulesFile(t, oldPath, []byte("last known good"))
	entries, readErr := os.ReadDir(rulesDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != "stable" {
		t.Fatalf("failed staging left partial entries: %v", entries)
	}
}

func TestValidateBundlePath_ResolutionFailuresFailClosed(t *testing.T) {
	missingRulesDir := filepath.Join(t.TempDir(), "missing")
	if _, err := validateBundlePath(missingRulesDir, "bundle"); err == nil ||
		!strings.Contains(err.Error(), "resolving rules directory") {
		t.Fatalf("missing rules directory error = %v", err)
	}

	rulesDir := t.TempDir()
	loop := filepath.Join(rulesDir, "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	if _, err := validateBundlePath(rulesDir, "loop"); err == nil ||
		!strings.Contains(err.Error(), "resolving bundle directory") {
		t.Fatalf("symlink loop error = %v", err)
	}
}

func TestHTTPBundleReads_RejectMalformedRequestAndBodyFailure(t *testing.T) {
	if _, err := httpGet(context.Background(), "https://host.example/\ninvalid"); err == nil ||
		!strings.Contains(err.Error(), "creating request") {
		t.Fatalf("malformed URL error = %v", err)
	}

	original := httpsOnlyClient
	httpsOnlyClient = &http.Client{
		Transport: rulesRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       rulesFailingBody{},
				Header:     make(http.Header),
			}, nil
		}),
		CheckRedirect: original.CheckRedirect,
	}
	t.Cleanup(func() { httpsOnlyClient = original })

	if _, err := httpGet(context.Background(), "https://host.example/bundle.yaml"); err == nil ||
		!strings.Contains(err.Error(), "reading response body") {
		t.Fatalf("body failure error = %v", err)
	}
}

func TestFetchRemoteBundle_SignatureFailureReturnsNoBundle(t *testing.T) {
	original := httpsOnlyClient
	httpsOnlyClient = &http.Client{
		Transport: rulesRoundTripper(func(req *http.Request) (*http.Response, error) {
			status := http.StatusOK
			body := "bundle"
			if strings.HasSuffix(req.URL.Path, ".sig") {
				status = http.StatusBadGateway
				body = "upstream failed"
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
		CheckRedirect: original.CheckRedirect,
	}
	t.Cleanup(func() { httpsOnlyClient = original })

	bundle, sig, err := fetchRemoteBundle(context.Background(), "https://host.example/bundle.yaml")
	if err == nil || !strings.Contains(err.Error(), "fetching signature") {
		t.Fatalf("error = %v, want signature fetch failure", err)
	}
	if bundle != nil || sig != nil {
		t.Fatalf("partial remote result escaped: bundle=%q sig=%q", bundle, sig)
	}
}

func TestRulesDiff_MalformedInstalledStateStopsBeforeNetwork(t *testing.T) {
	tests := []struct {
		name       string
		bundleBody []byte
		asDir      bool
		want       string
	}{
		{name: "bundle path is directory", asDir: true, want: "reading installed bundle"},
		{name: "malformed bundle", bundleBody: []byte("rules: [broken\n"), want: "parsing installed bundle"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			bundleDir := filepath.Join(rulesDir, testBundleName)
			if err := os.Mkdir(bundleDir, 0o750); err != nil {
				t.Fatal(err)
			}
			if tc.asDir {
				if err := os.Mkdir(filepath.Join(bundleDir, "bundle.yaml"), 0o750); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), tc.bundleBody, 0o600); err != nil {
				t.Fatal(err)
			}
			lf := &domrules.LockFile{
				InstalledVersion: testBundleVersion,
				Source:           "https://host.example/bundle.yaml",
			}
			if err := domrules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
				t.Fatal(err)
			}

			cmd := testRootCmd()
			cmd.SilenceUsage = true
			var stdout strings.Builder
			cmd.SetOut(&stdout)
			cmd.SetArgs([]string{"rules", "diff", testBundleName, "--rules-dir", rulesDir})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("malformed installed state emitted diff output: %q", stdout.String())
			}
		})
	}
}

func TestRulesMutationCommands_RejectTraversalBeforeFilesystemChange(t *testing.T) {
	rulesDir := t.TempDir()
	marker := filepath.Join(rulesDir, "marker")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "update", args: []string{"rules", "update", "../escape", "--rules-dir", rulesDir}},
		{name: "remove", args: []string{"rules", "remove", "../escape", "--rules-dir", rulesDir}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := testRootCmd()
			cmd.SilenceUsage = true
			var stdout strings.Builder
			cmd.SetOut(&stdout)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "invalid bundle name") {
				t.Fatalf("error = %v, want traversal rejection", err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("traversal rejection emitted output: %q", stdout.String())
			}
			assertRulesFile(t, marker, []byte("keep"))
		})
	}
}

func TestRulesRemove_RegularFileIsNotAnInstalledBundle(t *testing.T) {
	rulesDir := t.TempDir()
	bundlePath := filepath.Join(rulesDir, testBundleName)
	original := []byte("not a bundle directory")
	if err := os.WriteFile(bundlePath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := testRootCmd()
	cmd.SilenceUsage = true
	var stdout strings.Builder
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"rules", "remove", testBundleName, "--rules-dir", rulesDir})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "is not installed") {
		t.Fatalf("error = %v, want regular-file rejection", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("rejected removal emitted output: %q", stdout.String())
	}
	assertRulesFile(t, bundlePath, original)
}

func assertRulesFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s changed: got %q, want %q", path, got, want)
	}
}

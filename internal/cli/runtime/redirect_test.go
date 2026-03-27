// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const redirectStatusError = "error"

func TestBuildID_ReturnsNonEmpty(t *testing.T) {
	t.Parallel()

	id := buildID()
	if id == "" {
		t.Error("buildID() returned empty string")
	}
	// In test binaries, there's no vcs.revision, so it should fall back
	// to info.Main.Version (e.g., "(devel)" for test builds).
}

func TestBinaryHash_ReturnsNonEmpty(t *testing.T) {
	t.Parallel()

	hash := binaryHash()
	if hash == "" {
		t.Error("binaryHash() returned empty string")
	}
	// On Linux with /proc/self/exe, should return a hex string.
	// On other platforms, returns "unavailable".
}

func TestInternalRedirect_FetchProxy_NoEndpoint(t *testing.T) {
	manifest := RedirectManifest{
		Profile:    redirectProfileFetchProxy,
		Command:    []string{"curl", "https://example.com"},
		Reason:     "test redirect",
		PolicyRule: "test-rule",
		// No FetchEndpoint -- handler fails closed.
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{redirectProfileFetchProxy})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing fetch endpoint")
	}

	var result RedirectResult
	if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr != nil {
		t.Fatalf("invalid JSON output: %v\n%s", jsonErr, out.String())
	}
	if result.Status != redirectStatusError {
		t.Errorf("status = %q, want error", result.Status)
	}
	if result.Profile != redirectProfileFetchProxy {
		t.Errorf("profile = %q, want %s", result.Profile, redirectProfileFetchProxy)
	}
	if !strings.Contains(result.Error, "no fetch_endpoint") {
		t.Errorf("expected 'no fetch_endpoint' error, got %q", result.Error)
	}
	if result.BuildID == "" {
		t.Error("expected non-empty build_id for attestation")
	}
}

func TestInternalRedirect_MissingManifest(t *testing.T) {
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", "")

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{redirectProfileFetchProxy})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}

	// Should still emit JSON error result.
	var result RedirectResult
	if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr != nil {
		t.Fatalf("expected valid JSON error result, got unmarshal error: %v (output: %s)", jsonErr, out.String())
	}
	if result.Status != redirectStatusError {
		t.Errorf("status = %q, want error", result.Status)
	}
}

func TestInternalRedirect_QuarantineWrite(t *testing.T) {
	dir := t.TempDir()

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Command:       []string{"write", "/tmp/test"},
		Reason:        "policy block",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result RedirectResult
	if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr != nil {
		t.Fatalf("invalid JSON: %v\n%s", jsonErr, out.String())
	}
	if result.Status != "ok" {
		t.Errorf("status = %q, want ok: %s", result.Status, result.Error)
	}
	if result.Profile != redirectProfileQuarantineWrite {
		t.Errorf("profile = %q", result.Profile)
	}
}

func TestInternalRedirect_UnknownProfile(t *testing.T) {
	manifest := RedirectManifest{Profile: "nonexistent"}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"nonexistent"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if !strings.Contains(out.String(), "unknown redirect profile") {
		t.Errorf("expected unknown profile error, got: %s", out.String())
	}
}

func TestInternalRedirect_AcceptsPayloadArgs(t *testing.T) {
	// Set up a mock fetch endpoint so the handler can proceed past validation.
	fetchProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":"payload accepted","blocked":false}`))
	}))
	defer fetchProxy.Close()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Command:       []string{"/proc/self/exe", "internal-redirect", redirectProfileFetchProxy},
		Reason:        "test",
		FetchEndpoint: fetchProxy.URL,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://example.com"}`})
	err := cmd.Execute()
	// Should succeed, NOT fail with "accepts 1 arg(s), received 2".
	if err != nil {
		var result RedirectResult
		if jsonErr := json.Unmarshal(buf.Bytes(), &result); jsonErr == nil {
			if strings.Contains(result.Error, "accepts") {
				t.Error("Cobra arg validation rejected payload -- MinimumNArgs not applied")
			}
		}
	}
}

func TestInternalRedirect_Attestation(t *testing.T) {
	manifest := RedirectManifest{
		Profile: redirectProfileAppendOnlyLog,
		Command: []string{"echo", "test"},
		Reason:  "attestation test",
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{redirectProfileAppendOnlyLog})

	// Handler fails closed (not yet implemented), but should still emit JSON with attestation.
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error (handler not yet implemented)")
	}

	var result RedirectResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.BuildID == "" {
		t.Error("expected non-empty build_id")
	}
	if result.BinaryHash == "" {
		t.Error("expected non-empty binary_hash")
	}
}

func TestExecuteFetchProxy_Success(t *testing.T) {
	// Mock pipelock fetch endpoint.
	fetchProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		resp := map[string]any{
			"url":     targetURL,
			"content": "Hello from upstream",
			"blocked": false,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer fetchProxy.Close()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test redirect",
		FetchEndpoint: fetchProxy.URL,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://example.com"}`})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result RedirectResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected status ok, got %q: %s", result.Status, result.Error)
	}
	if !strings.Contains(result.Detail, "Hello from upstream") {
		t.Errorf("expected content in detail, got %q", result.Detail)
	}
}

func TestExecuteFetchProxy_NoURL(t *testing.T) {
	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test",
		FetchEndpoint: "http://127.0.0.1:9999",
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"echo hello"}`})
	_ = cmd.Execute()

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "no http/https URL") {
		t.Errorf("expected 'no http/https URL' error, got %q", result.Error)
	}
}

func TestExecuteFetchProxy_Blocked(t *testing.T) {
	fetchProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"blocked":      true,
			"block_reason": "domain on blocklist",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer fetchProxy.Close()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test",
		FetchEndpoint: fetchProxy.URL,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://evil.com"}`})
	_ = cmd.Execute()

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "domain on blocklist") {
		t.Errorf("expected block reason in error, got %q", result.Error)
	}
}

func TestExecuteFetchProxy_FetchError(t *testing.T) {
	fetchProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"error":   "upstream connection refused",
			"blocked": false,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer fetchProxy.Close()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test",
		FetchEndpoint: fetchProxy.URL,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://unreachable.test"}`})
	_ = cmd.Execute()

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "upstream connection refused") {
		t.Errorf("expected fetch error message, got %q", result.Error)
	}
}

func TestExecuteFetchProxy_InvalidJSON(t *testing.T) {
	fetchProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("not json"))
	}))
	defer fetchProxy.Close()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test",
		FetchEndpoint: fetchProxy.URL,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://example.com"}`})
	_ = cmd.Execute()

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "decoding fetch response") {
		t.Errorf("expected decode error, got %q", result.Error)
	}
}

func TestExecuteFetchProxy_ConnectionRefused(t *testing.T) {
	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test",
		FetchEndpoint: "http://127.0.0.1:1", // port 1 -- nothing listens here
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://example.com"}`})
	_ = cmd.Execute()

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error for connection refused, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "fetch request failed") {
		t.Errorf("expected 'fetch request failed' error, got %q", result.Error)
	}
}

func TestExtractURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple https", "curl https://example.com", "https://example.com"},
		{"simple http", "curl http://example.com/path", "http://example.com/path"},
		{"json embedded", `{"command":"curl https://api.example.com/v1"}`, "https://api.example.com/v1"},
		{"no url", "echo hello world", ""},
		{"multiple urls", "curl https://first.com http://second.com", "https://first.com"},
		{"with query", `curl "https://example.com/search?q=test"`, "https://example.com/search?q=test"},
		{"empty string", "", ""},
		{"prefix only", "https://", "https://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := extractURL(tt.input)
			if got != tt.want {
				t.Errorf("extractURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExecuteQuarantineWrite_Success(t *testing.T) {
	dir := t.TempDir()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test quarantine",
		PolicyRule:    "write_file",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"path":"/etc/passwd","content":"malicious"}`})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result RedirectResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected status ok, got %q: %s", result.Status, result.Error)
	}

	// Verify quarantine file was written.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read quarantine dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 quarantine file, got %d", len(entries))
	}

	// Verify file content.
	qFilePath := filepath.Clean(filepath.Join(dir, entries[0].Name()))
	data, err := os.ReadFile(qFilePath)
	if err != nil {
		t.Fatalf("failed to read quarantine file: %v", err)
	}
	var entry map[string]string
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("quarantine file is not valid JSON: %v", err)
	}
	if entry["policy_rule"] != "write_file" {
		t.Errorf("expected policy_rule=write_file, got %q", entry["policy_rule"])
	}

	// Verify file permissions.
	info, err := os.Stat(qFilePath)
	if err != nil {
		t.Fatalf("failed to stat quarantine file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected 0o600 perms, got %o", info.Mode().Perm())
	}
}

func TestExecuteQuarantineWrite_DirFull(t *testing.T) {
	dir := t.TempDir()

	for i := range 1001 {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d.json", i)), []byte("{}"), 0o600)
	}

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})
	_ = cmd.Execute()

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
}

func TestExecuteQuarantineWrite_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nonexistent")

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})
	_ = cmd.Execute()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("quarantine dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("expected 0o750 perms, got %o", info.Mode().Perm())
	}
}

func TestExecuteQuarantineWrite_NoDir(t *testing.T) {
	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile: redirectProfileQuarantineWrite,
		Reason:  "test",
		// No QuarantineDir
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})
	_ = cmd.Execute()

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error for missing dir, got %q", result.Status)
	}
}

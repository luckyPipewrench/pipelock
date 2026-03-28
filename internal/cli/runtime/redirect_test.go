// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	// Success path writes raw text to stdout (not JSON envelope).
	const wantMsg = "Operation completed (quarantined by pipelock). Payload logged for operator review."
	if got := out.String(); got != wantMsg {
		t.Errorf("expected raw message %q, got %q", wantMsg, got)
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
	cmd.SetErr(&bytes.Buffer{})

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
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	// Success path writes raw content to stdout (not JSON envelope).
	if got := buf.String(); got != "payload accepted" {
		t.Errorf("expected raw content %q, got %q", "payload accepted", got)
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
		if targetURL == "" {
			t.Error("fetch proxy did not receive url query parameter")
		}
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

	// Success path writes raw content to stdout (not JSON envelope).
	got := buf.String()
	if got != "Hello from upstream" {
		t.Errorf("expected raw content %q, got %q", "Hello from upstream", got)
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
	// Reserve an ephemeral port and close it so the subsequent request
	// is guaranteed to be refused (avoids assuming port 1 is unused).
	ctx := context.Background()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve closed port: %v", err)
	}
	endpoint := "http://" + ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test",
		FetchEndpoint: endpoint,
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
		{"http before https", "curl http://first.com https://second.com", "http://first.com"},
		{"https before http", "curl https://first.com http://second.com", "https://first.com"},
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

func TestExecuteFetchProxy_RedirectNotFollowed(t *testing.T) {
	// Server sends a 302 redirect. The client must NOT follow it (open-redirect defense).
	// CheckRedirect returns ErrUseLastResponse, so the redirect response is treated as final.
	fetchProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.com/exfil", http.StatusFound)
	}))
	defer fetchProxy.Close()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test redirect defense",
		FetchEndpoint: fetchProxy.URL,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://example.com"}`})
	err := cmd.Execute()

	// The redirect response body is HTML, not JSON, so JSON decode fails.
	if err == nil {
		t.Fatal("expected error from non-JSON redirect response")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "decoding fetch response") {
		t.Errorf("expected decode error, got %q", result.Error)
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

	// Success path writes raw text to stdout (not JSON envelope).
	const wantMsg = "Operation completed (quarantined by pipelock). Payload logged for operator review."
	if got := buf.String(); got != wantMsg {
		t.Errorf("expected raw message %q, got %q", wantMsg, got)
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

	// 1001 files: above the limit, always blocked regardless of > vs >=.
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

func TestExecuteQuarantineWrite_DirExactlyAtLimit(t *testing.T) {
	dir := t.TempDir()

	// Create exactly maxQuarantineFiles files.
	for i := range 1000 {
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
		t.Errorf("expected error at exactly %d files, got %q", maxQuarantineFiles, result.Status)
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
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	info, statErr := os.Stat(dir)
	if statErr != nil {
		t.Fatalf("quarantine dir not created: %v", statErr)
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

func TestExecuteQuarantineWrite_SymlinkDir(t *testing.T) {
	// Symlink to a real directory. EvalSymlinks resolves it successfully.
	realDir := t.TempDir()
	symlinkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Skip("symlinks not supported:", err)
	}

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: symlinkDir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected success with symlink to real dir, got: %v", err)
	}

	// Success path writes raw text to stdout.
	if !strings.Contains(buf.String(), "quarantined") {
		t.Errorf("expected success with symlink to real dir, got: %s", buf.String())
	}

	// Verify the quarantine file landed in the real directory (after symlink resolution).
	entries, err := os.ReadDir(realDir)
	if err != nil {
		t.Fatalf("failed to read real dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 quarantine file in resolved dir, got %d", len(entries))
	}
}

func TestExecuteQuarantineWrite_NotADirectory(t *testing.T) {
	// Create a regular file where the quarantine "dir" is expected.
	// MkdirAll fails because the path already exists as a file, not a dir.
	tmp := t.TempDir()
	fakePath := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(fakePath, []byte("I am a file"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: fakePath,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for non-directory quarantine path")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	// MkdirAll fails when the path is a regular file, hitting the
	// "creating quarantine dir" error branch.
	if !strings.Contains(result.Error, "creating quarantine dir") {
		t.Errorf("expected 'creating quarantine dir' error, got %q", result.Error)
	}
}

func TestExecuteQuarantineWrite_EmptyPayload(t *testing.T) {
	dir := t.TempDir()

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test empty",
		PolicyRule:    "test-rule",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	// No payload args -- should still succeed (empty string logged).
	cmd.SetArgs([]string{redirectProfileQuarantineWrite})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error with empty payload: %v", err)
	}

	if !strings.Contains(buf.String(), "quarantined") {
		t.Errorf("expected success with empty payload, got: %s", buf.String())
	}

	// Verify the quarantine file was written even with empty payload.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 quarantine file, got %d", len(entries))
	}

	// Verify the entry has empty tool_args.
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, entries[0].Name())))
	if err != nil {
		t.Fatalf("failed to read quarantine file: %v", err)
	}
	var entry map[string]string
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if entry["tool_args"] != "" {
		t.Errorf("expected empty tool_args, got %q", entry["tool_args"])
	}
	if entry["policy_rule"] != "test-rule" {
		t.Errorf("expected policy_rule=test-rule, got %q", entry["policy_rule"])
	}
}

func TestExecuteQuarantineWrite_UnreadableDir(t *testing.T) {
	// Remove read permission so ReadDir fails. Skip if running as root.
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	dir := t.TempDir()
	// Remove read+execute permission so ReadDir fails.
	if err := os.Chmod(dir, 0o200); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore for cleanup

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test unreadable",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unreadable quarantine dir")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "reading quarantine dir") {
		t.Errorf("expected 'reading quarantine dir' error, got %q", result.Error)
	}
}

func TestExecuteQuarantineWrite_InvalidManifestJSON(t *testing.T) {
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", "{invalid json")

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid manifest JSON")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "invalid manifest JSON") {
		t.Errorf("expected 'invalid manifest JSON' error, got %q", result.Error)
	}
}

func TestExecuteQuarantineWrite_DotDir(t *testing.T) {
	// filepath.Clean("") returns ".", so an empty QuarantineDir hits the
	// qDir == "." guard. Explicitly testing with "." as well.
	for _, dir := range []string{"", "."} {
		manifest := RedirectManifest{
			Profile:       redirectProfileQuarantineWrite,
			Reason:        "test",
			QuarantineDir: dir,
		}
		manifestJSON, _ := json.Marshal(manifest)
		t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

		cmd := InternalRedirectCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

		err := cmd.Execute()
		if err == nil {
			t.Errorf("QuarantineDir=%q: expected error for dot/empty dir", dir)
			continue
		}

		var result RedirectResult
		_ = json.Unmarshal(buf.Bytes(), &result)
		if result.Status != redirectStatusError {
			t.Errorf("QuarantineDir=%q: expected error status, got %q", dir, result.Status)
		}
		if !strings.Contains(result.Error, "no quarantine_dir") {
			t.Errorf("QuarantineDir=%q: expected 'no quarantine_dir' error, got %q", dir, result.Error)
		}
	}
}

func TestExecuteQuarantineWrite_MkdirAllFailure(t *testing.T) {
	// MkdirAll fails when the parent is read-only. Skip if running as root.
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	parent := t.TempDir()
	_ = os.Chmod(parent, 0o500)                       //nolint:gosec // intentionally restrictive for test
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) }) //nolint:gosec // restore for cleanup

	qDir := filepath.Join(parent, "quarantine")

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: qDir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when parent is read-only")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "creating quarantine dir") {
		t.Errorf("expected 'creating quarantine dir' error, got %q", result.Error)
	}
}

func TestExecuteQuarantineWrite_OpenFileFailure(t *testing.T) {
	// Make dir read+execute only (0o555) so ReadDir succeeds but file
	// creation fails (no write permission). Skip if running as root.
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	dir := t.TempDir()
	_ = os.Chmod(dir, 0o555)                       //nolint:gosec // intentionally restrictive for test
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore for cleanup

	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when dir is read-only (OpenFile should fail)")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "creating quarantine file") {
		t.Errorf("expected 'creating quarantine file' error, got %q", result.Error)
	}
}

func TestExecuteFetchProxy_InvalidEndpointURL(t *testing.T) {
	// A URL with no scheme causes NewRequestWithContext to fail.
	manifest := RedirectManifest{
		Profile:       redirectProfileFetchProxy,
		Reason:        "test",
		FetchEndpoint: "://invalid-url",
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileFetchProxy, `{"command":"curl https://example.com"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid endpoint URL")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "creating fetch request") {
		t.Errorf("expected 'creating fetch request' error, got %q", result.Error)
	}
}

// saveQuarantineFS saves the current quarantineFS state and returns a
// cleanup function that restores it. Tests that inject DI fakes must
// call this to prevent pollution across subtests.
func saveQuarantineFS(t *testing.T) {
	t.Helper()
	orig := quarantineFS
	t.Cleanup(func() { quarantineFS = orig })
}

func TestExecuteQuarantineWrite_EvalSymlinksFailure(t *testing.T) {
	// Inject a failing EvalSymlinks to cover the defense-in-depth error
	// path that is normally only reachable via a TOCTOU race.
	saveQuarantineFS(t)
	quarantineFS.EvalSymlinks = func(string) (string, error) {
		return "", fmt.Errorf("injected: too many levels of symlinks")
	}

	dir := t.TempDir()
	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from injected EvalSymlinks failure")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "resolving quarantine dir") {
		t.Errorf("expected 'resolving quarantine dir' error, got %q", result.Error)
	}
}

func TestExecuteQuarantineWrite_LstatFailure(t *testing.T) {
	// Inject a failing Lstat to cover the defense-in-depth error path
	// that is normally only reachable via a TOCTOU race after EvalSymlinks.
	saveQuarantineFS(t)
	quarantineFS.Lstat = func(string) (os.FileInfo, error) {
		return nil, fmt.Errorf("injected: permission denied")
	}

	dir := t.TempDir()
	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from injected Lstat failure")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "checking quarantine dir") {
		t.Errorf("expected 'checking quarantine dir' error, got %q", result.Error)
	}
}

// fakeFileInfo implements os.FileInfo for test injection.
type fakeFileInfo struct {
	name  string
	isDir bool
}

func (f fakeFileInfo) Name() string      { return f.name }
func (f fakeFileInfo) Size() int64       { return 0 }
func (f fakeFileInfo) Mode() os.FileMode { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time {
	return time.Time{}
}
func (f fakeFileInfo) IsDir() bool { return f.isDir }
func (f fakeFileInfo) Sys() any    { return nil }

func TestExecuteQuarantineWrite_NotADir_ViaLstat(t *testing.T) {
	// Inject Lstat returning a non-directory FileInfo to cover the
	// !info.IsDir() branch that is normally unreachable after MkdirAll.
	saveQuarantineFS(t)
	quarantineFS.Lstat = func(string) (os.FileInfo, error) {
		return fakeFileInfo{name: "quarantine", isDir: false}, nil
	}

	dir := t.TempDir()
	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-directory path")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "quarantine path is not a directory") {
		t.Errorf("expected 'not a directory' error, got %q", result.Error)
	}
}

func TestExecuteQuarantineWrite_MarshalJSONFailure(t *testing.T) {
	// Inject a failing MarshalJSON to cover the error path that is
	// practically unreachable with map[string]string inputs.
	saveQuarantineFS(t)
	quarantineFS.MarshalJSON = func(any) ([]byte, error) {
		return nil, fmt.Errorf("injected: marshal failure")
	}

	dir := t.TempDir()
	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from injected MarshalJSON failure")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "marshaling quarantine entry") {
		t.Errorf("expected 'marshaling quarantine entry' error, got %q", result.Error)
	}
}

// failWriter is a quarantineFileWriter that fails on Write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("injected: disk full") }
func (failWriter) Close() error              { return nil }

// failCloser is a quarantineFileWriter where Write succeeds but Close fails.
type failCloser struct {
	bytes.Buffer
}

func (*failCloser) Close() error { return fmt.Errorf("injected: close error") }

func TestExecuteQuarantineWrite_WriteFailure(t *testing.T) {
	// Inject OpenFile returning a writer that fails on Write.
	saveQuarantineFS(t)
	quarantineFS.OpenFile = func(string, int, os.FileMode) (quarantineFileWriter, error) {
		return failWriter{}, nil
	}

	dir := t.TempDir()
	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from write failure")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "writing quarantine file") {
		t.Errorf("expected 'writing quarantine file' error, got %q", result.Error)
	}
}

func TestExecuteQuarantineWrite_CloseFailure(t *testing.T) {
	// Inject OpenFile returning a writer where Write succeeds but Close fails.
	saveQuarantineFS(t)
	quarantineFS.OpenFile = func(string, int, os.FileMode) (quarantineFileWriter, error) {
		return &failCloser{}, nil
	}

	dir := t.TempDir()
	manifest := RedirectManifest{
		Profile:       redirectProfileQuarantineWrite,
		Reason:        "test",
		QuarantineDir: dir,
	}
	manifestJSON, _ := json.Marshal(manifest)
	t.Setenv("__PIPELOCK_REDIRECT_MANIFEST", string(manifestJSON))

	cmd := InternalRedirectCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{redirectProfileQuarantineWrite, `{"data":"test"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from close failure")
	}

	var result RedirectResult
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result.Status != redirectStatusError {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Error, "closing quarantine file") {
		t.Errorf("expected 'closing quarantine file' error, got %q", result.Error)
	}
}

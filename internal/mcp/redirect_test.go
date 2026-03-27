// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

const (
	profileTestProfile = "test-profile"
	profileFetchProxy  = "fetch-proxy"
	ruleBlockCurl      = "block-curl"
	ruleTestRule       = "test-rule"
)

func TestExecuteRedirect_Success(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	profile := config.RedirectProfile{
		Exec:   []string{"/bin/echo", "redirected output"},
		Reason: "test redirect",
	}
	requestID := json.RawMessage(`42`)
	result := executeRedirect(profile, profileTestProfile, requestID, `{"tool":"test"}`, ruleTestRule, nil)

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if result.LatencyMs < 0 {
		t.Error("latency should be non-negative")
	}

	// Verify the response is valid JSON-RPC with the correct ID.
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			Content []jsonrpc.ContentBlock `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.JSONRPC != jsonrpc.Version {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, jsonrpc.Version)
	}
	if string(resp.ID) != "42" {
		t.Errorf("id = %s, want 42", resp.ID)
	}
	if len(resp.Result.Content) != 1 {
		t.Fatalf("content blocks = %d, want 1", len(resp.Result.Content))
	}
	if resp.Result.Content[0].Type != "text" {
		t.Errorf("content type = %q, want text", resp.Result.Content[0].Type)
	}
	// echo adds a newline
	if resp.Result.Content[0].Text != "redirected output\n" {
		t.Errorf("content text = %q, want %q", resp.Result.Content[0].Text, "redirected output\n")
	}
}

func TestExecuteRedirect_PreserveArgv(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	profile := config.RedirectProfile{
		Exec:         []string{"/bin/echo"},
		Reason:       "test preserve argv",
		PreserveArgv: true,
	}
	requestID := json.RawMessage(`1`)
	origArgs := `{"command":"curl https://example.com"}`
	result := executeRedirect(profile, profileTestProfile, requestID, origArgs, ruleTestRule, nil)

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	var resp struct {
		Result struct {
			Content []jsonrpc.ContentBlock `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// When preserve_argv is true, original args are passed to the handler.
	// echo prints them back, so we should see the args in the output.
	if len(resp.Result.Content) == 0 {
		t.Fatal("expected content")
	}
	if resp.Result.Content[0].Text != origArgs+"\n" {
		t.Errorf("content = %q, want original args echoed back", resp.Result.Content[0].Text)
	}
}

func TestExecuteRedirect_Failure(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	profile := config.RedirectProfile{
		Exec:   []string{"/bin/false"},
		Reason: "test failure",
	}
	requestID := json.RawMessage(`99`)
	result := executeRedirect(profile, profileTestProfile, requestID, `{}`, "", nil)

	if result.Success {
		t.Error("expected failure for /bin/false")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
	if result.LatencyMs < 0 {
		t.Error("latency should be non-negative")
	}
}

func TestExecuteRedirect_NonexistentCommand(t *testing.T) {
	profile := config.RedirectProfile{
		Exec:   []string{"/nonexistent/command"},
		Reason: "test missing binary",
	}
	requestID := json.RawMessage(`1`)
	result := executeRedirect(profile, profileTestProfile, requestID, `{}`, "", nil)

	if result.Success {
		t.Error("expected failure for nonexistent command")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestExecuteRedirect_ManifestInjected(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	// Use printenv to capture the manifest env var from the child process.
	profile := config.RedirectProfile{
		Exec:   []string{"/bin/sh", "-c", "printenv __PIPELOCK_REDIRECT_MANIFEST"},
		Reason: "test manifest injection",
	}
	requestID := json.RawMessage(`1`)
	result := executeRedirect(profile, profileFetchProxy, requestID, `{}`, ruleBlockCurl, nil)

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	// Parse the response to extract the handler's stdout (= the manifest JSON).
	var resp struct {
		Result struct {
			Content []jsonrpc.ContentBlock `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(resp.Result.Content) == 0 {
		t.Fatal("expected content from printenv")
	}
	manifestStr := strings.TrimSpace(resp.Result.Content[0].Text)

	// Verify the manifest has the expected fields.
	var manifest redirectManifest
	if err := json.Unmarshal([]byte(manifestStr), &manifest); err != nil {
		t.Fatalf("invalid manifest JSON from child: %v\nraw: %s", err, manifestStr)
	}
	if manifest.Profile != profileFetchProxy {
		t.Errorf("manifest.Profile = %q, want fetch-proxy", manifest.Profile)
	}
	if manifest.Reason != "test manifest injection" {
		t.Errorf("manifest.Reason = %q, want 'test manifest injection'", manifest.Reason)
	}
	if manifest.PolicyRule != ruleBlockCurl {
		t.Errorf("manifest.PolicyRule = %q, want block-curl", manifest.PolicyRule)
	}
}

func TestArgsDigest(t *testing.T) {
	d := argsDigest(`{"command":"curl https://example.com"}`)
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", d)
	}
	if !strings.Contains(d, "len=") {
		t.Errorf("expected len= in digest, got %q", d)
	}
	// Deterministic: same input = same output.
	if d2 := argsDigest(`{"command":"curl https://example.com"}`); d != d2 {
		t.Errorf("digest not deterministic: %q != %q", d, d2)
	}
	// Different input = different digest.
	if d3 := argsDigest(`{"command":"wget"}`); d == d3 {
		t.Error("different inputs produced same digest")
	}
}

func TestExtractToolCallFields_Valid(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"command":"ls"}}}`)
	name, args := extractToolCallFields(line)
	if name != "bash" {
		t.Errorf("name = %q, want bash", name)
	}
	if args != `{"command":"ls"}` {
		t.Errorf("args = %q, want {\"command\":\"ls\"}", args)
	}
}

func TestExtractToolCallFields_InvalidJSON(t *testing.T) {
	name, args := extractToolCallFields([]byte(`not json`))
	if name != "" || args != "" {
		t.Errorf("expected empty on invalid JSON, got name=%q args=%q", name, args)
	}
}

func TestExtractToolCallFields_NullArguments(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test","arguments":null}}`)
	name, args := extractToolCallFields(line)
	if name != "test" {
		t.Errorf("name = %q, want test", name)
	}
	if args != "{}" {
		t.Errorf("args = %q, want {} for null arguments", args)
	}
}

func TestExecuteRedirect_ManifestIncludesRuntime(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	profile := config.RedirectProfile{
		Exec:   []string{"/bin/sh", "-c", "printenv __PIPELOCK_REDIRECT_MANIFEST"},
		Reason: "test manifest",
	}
	rt := &RedirectRuntime{
		FetchEndpoint: "http://127.0.0.1:8888/fetch",
		QuarantineDir: "/tmp/pipelock-quarantine",
	}
	requestID := json.RawMessage(`1`)
	result := executeRedirect(profile, profileTestProfile, requestID, `{}`, ruleTestRule, rt)

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	// Parse the manifest from the handler output.
	// The handler is "printenv __PIPELOCK_REDIRECT_MANIFEST" so stdout is the JSON.
	var rpc struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &rpc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(rpc.Result.Content) == 0 {
		t.Fatal("no content in response")
	}

	var manifest struct {
		FetchEndpoint string `json:"fetch_endpoint"`
		QuarantineDir string `json:"quarantine_dir"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(rpc.Result.Content[0].Text)), &manifest); err != nil {
		t.Fatalf("failed to parse manifest from handler output: %v", err)
	}
	if manifest.FetchEndpoint != "http://127.0.0.1:8888/fetch" {
		t.Errorf("expected FetchEndpoint in manifest, got %q", manifest.FetchEndpoint)
	}
	if manifest.QuarantineDir != "/tmp/pipelock-quarantine" {
		t.Errorf("expected QuarantineDir in manifest, got %q", manifest.QuarantineDir)
	}
}

func TestExtractToolCallFields_MissingArguments(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}`)
	name, args := extractToolCallFields(line)
	if name != "test" {
		t.Errorf("name = %q, want test", name)
	}
	if args != "{}" {
		t.Errorf("args = %q, want {} for missing arguments", args)
	}
}

func TestExecuteRedirect_FetchProxyEndToEnd(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	// Start a mock fetch endpoint that returns known content.
	fetchServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		resp := map[string]any{
			"url":     targetURL,
			"content": "Safe content from " + targetURL,
			"blocked": false,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer fetchServer.Close()

	// Use printenv to capture the manifest; verifies runtime fields are plumbed.
	profile := config.RedirectProfile{
		Exec:         []string{"/bin/sh", "-c", "printenv __PIPELOCK_REDIRECT_MANIFEST"},
		Reason:       "test fetch-proxy e2e",
		PreserveArgv: true,
	}
	rt := &RedirectRuntime{
		FetchEndpoint: fetchServer.URL,
		QuarantineDir: t.TempDir(),
	}
	requestID := json.RawMessage(`42`)
	toolArgs := `{"command":"curl https://example.com/api"}`

	result := executeRedirect(profile, profileFetchProxy, requestID, toolArgs, ruleBlockCurl, rt)
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	// Parse the synthetic JSON-RPC response to get the handler's stdout.
	var rpc struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &rpc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(rpc.Result.Content) == 0 {
		t.Fatal("no content in response")
	}

	// Parse the manifest from the handler's stdout.
	var manifest struct {
		Profile       string `json:"profile"`
		FetchEndpoint string `json:"fetch_endpoint"`
		QuarantineDir string `json:"quarantine_dir"`
		PolicyRule    string `json:"policy_rule"`
		Reason        string `json:"reason"`
	}
	manifestStr := strings.TrimSpace(rpc.Result.Content[0].Text)
	if err := json.Unmarshal([]byte(manifestStr), &manifest); err != nil {
		t.Fatalf("failed to parse manifest: %v\nraw: %s", err, manifestStr)
	}

	if manifest.FetchEndpoint != fetchServer.URL {
		t.Errorf("expected FetchEndpoint=%q, got %q", fetchServer.URL, manifest.FetchEndpoint)
	}
	if manifest.QuarantineDir == "" {
		t.Error("expected non-empty QuarantineDir in manifest")
	}
	if manifest.PolicyRule != ruleBlockCurl {
		t.Errorf("expected PolicyRule=%s, got %q", ruleBlockCurl, manifest.PolicyRule)
	}
	if manifest.Profile != profileFetchProxy {
		t.Errorf("expected Profile=%s, got %q", profileFetchProxy, manifest.Profile)
	}
}

func TestExecuteRedirect_QuarantineWriteEndToEnd(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	qDir := t.TempDir()

	// Use printenv to verify the manifest contains QuarantineDir.
	profile := config.RedirectProfile{
		Exec:         []string{"/bin/sh", "-c", "printenv __PIPELOCK_REDIRECT_MANIFEST"},
		Reason:       "test quarantine e2e",
		PreserveArgv: true,
	}
	rt := &RedirectRuntime{
		FetchEndpoint: "http://127.0.0.1:8888/fetch",
		QuarantineDir: qDir,
	}
	requestID := json.RawMessage(`99`)
	toolArgs := `{"path":"/etc/shadow","content":"secret"}`

	const ruleWriteFile = "write-file"
	const profileQuarantineWrite = "quarantine-write"
	result := executeRedirect(profile, profileQuarantineWrite, requestID, toolArgs, ruleWriteFile, rt)
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	// Verify manifest contains quarantine dir.
	var rpc struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &rpc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(rpc.Result.Content) == 0 {
		t.Fatal("no content in response")
	}

	var manifest struct {
		Profile       string `json:"profile"`
		QuarantineDir string `json:"quarantine_dir"`
		PolicyRule    string `json:"policy_rule"`
	}
	manifestStr := strings.TrimSpace(rpc.Result.Content[0].Text)
	if err := json.Unmarshal([]byte(manifestStr), &manifest); err != nil {
		t.Fatalf("failed to parse manifest: %v\nraw: %s", err, manifestStr)
	}

	if manifest.QuarantineDir != qDir {
		t.Errorf("expected QuarantineDir=%q, got %q", qDir, manifest.QuarantineDir)
	}
	if manifest.PolicyRule != ruleWriteFile {
		t.Errorf("expected PolicyRule=%s, got %q", ruleWriteFile, manifest.PolicyRule)
	}
	if manifest.Profile != profileQuarantineWrite {
		t.Errorf("expected Profile=%s, got %q", profileQuarantineWrite, manifest.Profile)
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

const (
	testClientIP   = "10.0.0.1"
	testReqID      = "req-7"
	testComponent  = "pipelock"
	testActionWarn = "warn"
	testConfigHash = "testhash"
	testVersion    = "0.1.0-dev"
	testAgentName  = "claude-code"
	testMethodGet  = "GET"
	mitreT1048     = "T1048"
	mitreT1053     = "T1053"
	mitreT1059     = "T1059"
)

// collectingSink records all emitted events for test assertions.
type collectingSink struct {
	mu     sync.Mutex
	events []emit.Event
}

func (c *collectingSink) Emit(_ context.Context, event emit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
	return nil
}

func (c *collectingSink) Close() error { return nil }

func (c *collectingSink) lastEvent() (emit.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return emit.Event{}, false
	}
	return c.events[len(c.events)-1], true
}

func TestNew_StdoutJSON(t *testing.T) {
	logger, err := New("json", "stdout", "", true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()
}

func TestNew_FileOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()

	// Verify file was created with correct permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected file permissions 0600, got %o", perm)
	}
}

func TestNew_FileOutputMissingPath(t *testing.T) {
	_, err := New("json", "file", "/nonexistent/dir/test.log", true, true)
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestNewNop(_ *testing.T) {
	logger := NewNop()
	// Should not panic
	logger.LogAllowed(LogContext{method: testMethodGet, url: "https://example.com", clientIP: "127.0.0.1", requestID: "req-1"}, 200, 1024, time.Second)
	logger.LogBlocked(LogContext{method: testMethodGet, url: "https://evil.com", clientIP: "127.0.0.1", requestID: "req-2"}, "blocklist", "domain blocked")
	logger.LogError(LogContext{method: testMethodGet, url: "https://fail.com", clientIP: "127.0.0.1", requestID: "req-3"}, os.ErrNotExist)
	logger.LogAnomaly(LogContext{method: testMethodGet, url: "https://sus.com", clientIP: "127.0.0.1", requestID: "req-4"}, "entropy", "high entropy", 0.9)
	logger.LogStartup(":8888", "balanced", testVersion, testConfigHash)
	logger.LogShutdown("test")
	logger.LogRedirect("https://a.com", "https://b.com", "127.0.0.1", "req-6", "", 1)
	logger.LogResponseScan(LogContext{url: "https://example.com", clientIP: "127.0.0.1", requestID: "req-8"}, testActionWarn, 2, []string{"Prompt Injection", "Jailbreak Attempt"}, nil)
	logger.Close()
}

func TestLogAllowed_Filtering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// includeAllowed=false should suppress allowed events
	logger, err := New("json", "file", path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAllowed(LogContext{method: testMethodGet, url: "https://example.com", clientIP: "127.0.0.1", requestID: "req-1"}, 200, 1024, time.Second)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if strings.Contains(string(data), "allowed") {
		t.Error("expected allowed event to be filtered out")
	}
}

func TestLogBlocked_Filtering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// includeBlocked=false should suppress blocked events
	logger, err := New("json", "file", path, true, false)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(LogContext{method: testMethodGet, url: "https://evil.com", clientIP: "127.0.0.1", requestID: "req-1"}, "blocklist", "domain blocked")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if strings.Contains(string(data), "blocked") {
		t.Error("expected blocked event to be filtered out")
	}
}

func TestLogAllowed_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAllowed(LogContext{method: testMethodGet, url: "https://example.com", clientIP: "10.0.0.5", requestID: "req-42"}, 200, 1024, time.Second)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one log line")
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("expected valid JSON, got error: %v\nline: %s", err, lines[0])
	}

	if entry["event"] != "allowed" {
		t.Errorf("expected event=allowed, got %v", entry["event"])
	}
	if entry["url"] != "https://example.com" {
		t.Errorf("expected url=https://example.com, got %v", entry["url"])
	}
	if entry["method"] != testMethodGet {
		t.Errorf("expected method=GET, got %v", entry["method"])
	}
	if entry["client_ip"] != "10.0.0.5" {
		t.Errorf("expected client_ip=10.0.0.5, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-42" {
		t.Errorf("expected request_id=req-42, got %v", entry["request_id"])
	}
}

func TestLogBlocked_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(LogContext{method: testMethodGet, url: "https://evil.com", clientIP: "192.168.1.1", requestID: testReqID}, "blocklist", "domain in blocklist")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "blocked" {
		t.Errorf("expected event=blocked, got %v", entry["event"])
	}
	if entry["scanner"] != "blocklist" {
		t.Errorf("expected scanner=blocklist, got %v", entry["scanner"])
	}
	if entry["reason"] != "domain in blocklist" {
		t.Errorf("expected reason='domain in blocklist', got %v", entry["reason"])
	}
	if entry["client_ip"] != "192.168.1.1" {
		t.Errorf("expected client_ip=192.168.1.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != testReqID {
		t.Errorf("expected request_id=req-7, got %v", entry["request_id"])
	}
}

func TestLogError_IncludesError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogError(LogContext{method: testMethodGet, url: "https://fail.com", clientIP: testClientIP, requestID: "req-9"}, os.ErrNotExist)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventError) {
		t.Errorf("expected event=error, got %v", entry["event"])
	}
	if entry[string(EventError)] == nil || entry[string(EventError)] == "" {
		t.Error("expected error field to be populated")
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
}

func TestLogger_DoubleClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	// Close twice — should not panic
	logger.Close()
	logger.Close()
}

func TestLogStartup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogStartup(":8888", "balanced", testVersion, testConfigHash)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "startup" {
		t.Errorf("expected event=startup, got %v", entry["event"])
	}
	if entry["mode"] != "balanced" {
		t.Errorf("expected mode=balanced, got %v", entry["mode"])
	}
	if entry["version"] != testVersion {
		t.Errorf("expected version=%s, got %v", testVersion, entry["version"])
	}
	if entry["config_hash"] != testConfigHash {
		t.Errorf("expected config_hash=%s, got %v", testConfigHash, entry["config_hash"])
	}
}

func TestLogShutdown_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogShutdown("test complete")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "shutdown" {
		t.Errorf("expected event=shutdown, got %v", entry["event"])
	}
	if entry["reason"] != "test complete" {
		t.Errorf("expected reason='test complete', got %v", entry["reason"])
	}
}

func TestLogAnomaly_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAnomaly(LogContext{method: testMethodGet, url: "https://sus.com/data", clientIP: testClientIP, requestID: "req-5"}, "entropy", "high entropy segment", 0.85)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "anomaly" {
		t.Errorf("expected event=anomaly, got %v", entry["event"])
	}
	if entry["url"] != "https://sus.com/data" {
		t.Errorf("expected url, got %v", entry["url"])
	}
	if entry["reason"] != "high entropy segment" {
		t.Errorf("expected reason, got %v", entry["reason"])
	}
	score, ok := entry["score"].(float64)
	if !ok || score < 0.84 || score > 0.86 {
		t.Errorf("expected score ~0.85, got %v", entry["score"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-5" {
		t.Errorf("expected request_id=req-5, got %v", entry["request_id"])
	}
	if entry["scanner"] != "entropy" {
		t.Errorf("expected scanner=entropy, got %v", entry["scanner"])
	}
	if entry["mitre_technique"] != mitreT1048 {
		t.Errorf("expected mitre_technique=T1048, got %v", entry["mitre_technique"])
	}
}

func TestLogResponseScanExempt_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogResponseScanExempt(LogContext{method: testMethodGet, url: "https://api.openai.com/v1/chat", clientIP: testClientIP, requestID: "req-exempt-3", agent: testAgentName}, "api.openai.com")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventResponseScanExempt) {
		t.Errorf("expected event=%s, got %v", EventResponseScanExempt, entry["event"])
	}
	if entry["hostname"] != "api.openai.com" {
		t.Errorf("expected hostname=api.openai.com, got %v", entry["hostname"])
	}
	if entry["enforcement_type"] != "response_scanning" {
		t.Errorf("expected enforcement_type=response_scanning, got %v", entry["enforcement_type"])
	}
	if entry["reason"] != "exempt_domains match" {
		t.Errorf("expected reason=exempt_domains match, got %v", entry["reason"])
	}
	if entry["agent"] != testAgentName {
		t.Errorf("expected agent=%s, got %v", testAgentName, entry["agent"])
	}
	if entry["level"] != "info" {
		t.Errorf("expected level=info, got %v", entry["level"])
	}
}

func TestNew_BothOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "both", path, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logger.LogStartup(":8888", "balanced", testVersion, testConfigHash)
	logger.Close()

	// Verify file was written
	data, _ := os.ReadFile(filepath.Clean(path))
	if len(data) == 0 {
		t.Error("expected log file to have content with 'both' output")
	}
}

func TestNew_TextFormat(t *testing.T) {
	// Text format with console writer — should not error
	logger, err := New("text", "stdout", "", true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()

	// Should not panic
	logger.LogStartup(":8888", "balanced", testVersion, testConfigHash)
}

func TestNew_DefaultsToStdout(t *testing.T) {
	// Empty writers list should default to stdout
	logger, err := New("json", "invalid_output", "", true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()
}

func TestLogAllowed_IncludesAllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAllowed(LogContext{method: testMethodGet, url: "https://example.com/page", clientIP: "10.0.0.5", requestID: "req-100"}, 200, 5000, 150*time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	checks := map[string]any{
		"event":      "allowed",
		"method":     testMethodGet,
		"url":        "https://example.com/page",
		"component":  "pipelock",
		"client_ip":  "10.0.0.5",
		"request_id": "req-100",
	}
	for key, want := range checks {
		if entry[key] != want {
			t.Errorf("expected %s=%v, got %v", key, want, entry[key])
		}
	}

	// Numeric fields — JSON unmarshals numbers as float64
	if statusCode, ok := entry["status_code"].(float64); !ok || statusCode != 200 {
		t.Errorf("expected status_code=200, got %v", entry["status_code"])
	}
	if sizeBytes, ok := entry["size_bytes"].(float64); !ok || sizeBytes != 5000 {
		t.Errorf("expected size_bytes=5000, got %v", entry["size_bytes"])
	}

	// Duration and timestamp should exist
	if entry["duration_ms"] == nil {
		t.Error("expected duration_ms field")
	}
	if entry["time"] == nil {
		t.Error("expected time field")
	}
}

func TestLogBlocked_IncludesAllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(LogContext{method: testMethodGet, url: "https://evil.com/exfil", clientIP: "192.168.1.1", requestID: "req-50"}, "blocklist", "domain in blocklist: evil.com")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	checks := map[string]any{
		"event":           "blocked",
		"method":          testMethodGet,
		"url":             "https://evil.com/exfil",
		"scanner":         "blocklist",
		"reason":          "domain in blocklist: evil.com",
		"component":       "pipelock",
		"client_ip":       "192.168.1.1",
		"request_id":      "req-50",
		"mitre_technique": "T1071.001",
	}
	for key, want := range checks {
		if entry[key] != want {
			t.Errorf("expected %s=%v, got %v", key, want, entry[key])
		}
	}
}

func TestLogError_IncludesAllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogError(LogContext{method: testMethodGet, url: "https://fail.com", clientIP: testClientIP, requestID: "req-77"}, os.ErrPermission)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventError) {
		t.Errorf("expected event=error, got %v", entry["event"])
	}
	if entry["component"] != testComponent {
		t.Errorf("expected component=pipelock, got %v", entry["component"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-77" {
		t.Errorf("expected request_id=req-77, got %v", entry["request_id"])
	}
}

func TestNewNop_CloseIsSafe(_ *testing.T) {
	logger := NewNop()
	// Multiple closes should be safe
	logger.Close()
	logger.Close()
	logger.Close()
}

func TestLogger_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogStartup(":8888", "test", testVersion, testConfigHash)
	logger.Close()

	info, _ := os.Stat(path)
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected log file permissions 0600, got %o", perm)
	}
}

func TestLogger_MultipleEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	logger.LogStartup(":8888", "balanced", testVersion, testConfigHash)
	logger.LogAllowed(LogContext{method: testMethodGet, url: "https://a.com", clientIP: testClientIP, requestID: "req-1"}, 200, 100, time.Millisecond)
	logger.LogBlocked(LogContext{method: testMethodGet, url: "https://b.com", clientIP: testClientIP, requestID: "req-2"}, ScannerDLP, "secret found")
	logger.LogError(LogContext{method: testMethodGet, url: "https://c.com", clientIP: testClientIP, requestID: "req-3"}, os.ErrNotExist)
	logger.LogAnomaly(LogContext{method: testMethodGet, url: "https://d.com", clientIP: testClientIP, requestID: "req-4"}, "", "weird", 0.5)
	logger.LogShutdown("done")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 6 {
		t.Errorf("expected 6 log lines, got %d", len(lines))
	}

	// Verify each line is valid JSON
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestLogResponseScan_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogResponseScan(LogContext{url: "https://example.com/page", clientIP: testClientIP, requestID: "req-10"}, testActionWarn, 2, []string{"Prompt Injection", "Jailbreak Attempt"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventResponseScan) {
		t.Errorf("expected event=response_scan, got %v", entry["event"])
	}
	if entry["url"] != "https://example.com/page" {
		t.Errorf("expected url, got %v", entry["url"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-10" {
		t.Errorf("expected request_id=req-10, got %v", entry["request_id"])
	}
	if entry["action"] != testActionWarn {
		t.Errorf("expected action=warn, got %v", entry["action"])
	}
	matchCount, ok := entry["match_count"].(float64)
	if !ok || matchCount != 2 {
		t.Errorf("expected match_count=2, got %v", entry["match_count"])
	}
	patterns, ok := entry["patterns"].([]any)
	if !ok || len(patterns) != 2 {
		t.Errorf("expected 2 patterns, got %v", entry["patterns"])
	}
	if entry["component"] != testComponent {
		t.Errorf("expected component=pipelock, got %v", entry["component"])
	}
}

func TestLogResponseScan_StripAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogResponseScan(LogContext{url: "https://example.com/page", clientIP: testClientIP, requestID: "req-11"}, "strip", 1, []string{"System Override"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventResponseScan) {
		t.Errorf("expected event=response_scan, got %v", entry["event"])
	}
	if entry["action"] != "strip" {
		t.Errorf("expected action=strip, got %v", entry["action"])
	}
}

func TestLogResponseScan_BundleRulesIncluded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	bundleRules := []BundleRuleHit{
		{RuleID: "owasp-injection-001", Bundle: "owasp-top10", BundleVersion: "1.2.0"},
		{RuleID: "custom-xss-002", Bundle: "owasp-top10", BundleVersion: "1.2.0"},
	}
	logger.LogResponseScan(LogContext{url: "https://example.com/page", clientIP: testClientIP, requestID: "req-12"}, testActionWarn, 2,
		[]string{"owasp-injection-001", "custom-xss-002"}, bundleRules)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	rawRules, ok := entry["bundle_rules"].([]any)
	if !ok {
		t.Fatalf("expected bundle_rules array, got %T (%v)", entry["bundle_rules"], entry["bundle_rules"])
	}
	if len(rawRules) != 2 {
		t.Fatalf("expected 2 bundle rules, got %d", len(rawRules))
	}
	first, ok := rawRules[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map for bundle rule, got %T", rawRules[0])
	}
	if first["rule_id"] != "owasp-injection-001" {
		t.Errorf("rule_id = %v, want owasp-injection-001", first["rule_id"])
	}
	if first["bundle"] != "owasp-top10" {
		t.Errorf("bundle = %v, want owasp-top10", first["bundle"])
	}
	if first["bundle_version"] != "1.2.0" {
		t.Errorf("bundle_version = %v, want 1.2.0", first["bundle_version"])
	}
}

func TestLogResponseScan_NilBundleRulesOmitsField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogResponseScan(LogContext{url: "https://example.com/page", clientIP: testClientIP, requestID: "req-13"}, testActionWarn, 1, []string{"injection"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if _, exists := entry["bundle_rules"]; exists {
		t.Error("bundle_rules field should be omitted when nil")
	}
}

func TestEmit_LogResponseScan_BundleRules(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	bundleRules := []BundleRuleHit{
		{RuleID: "rule-1", Bundle: "test-bundle", BundleVersion: "0.1.0"},
	}
	logger.LogResponseScan(LogContext{url: "https://example.com", clientIP: testClientIP, requestID: "req-14"}, testActionWarn, 1, []string{"rule-1"}, bundleRules)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	emittedRules, ok := ev.Fields["bundle_rules"].([]BundleRuleHit)
	if !ok {
		t.Fatalf("bundle_rules field type = %T, want []BundleRuleHit", ev.Fields["bundle_rules"])
	}
	if len(emittedRules) != 1 {
		t.Fatalf("expected 1 bundle rule, got %d", len(emittedRules))
	}
	if emittedRules[0].RuleID != "rule-1" {
		t.Errorf("rule_id = %q, want rule-1", emittedRules[0].RuleID)
	}
	if emittedRules[0].Bundle != "test-bundle" {
		t.Errorf("bundle = %q, want test-bundle", emittedRules[0].Bundle)
	}
}

func TestEmit_LogResponseScan_NilBundleRulesOmitsField(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogResponseScan(LogContext{url: "https://example.com", clientIP: testClientIP, requestID: "req-15"}, testActionWarn, 1, []string{"injection"}, nil)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if _, exists := ev.Fields["bundle_rules"]; exists {
		t.Error("bundle_rules should not be in emitted fields when nil")
	}
}

func TestLogWSScan_BundleRulesIncluded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	bundleRules := []BundleRuleHit{
		{RuleID: "ws-rule-1", Bundle: "ws-bundle", BundleVersion: "2.0.0"},
	}
	logger.LogWSScan("ws://example.com/chat", DirectionServerToClient, testClientIP, "req-402", testActionWarn, 1, []string{"ws-rule-1"}, bundleRules)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	rawRules, ok := entry["bundle_rules"].([]any)
	if !ok {
		t.Fatalf("expected bundle_rules array, got %T", entry["bundle_rules"])
	}
	if len(rawRules) != 1 {
		t.Fatalf("expected 1 bundle rule, got %d", len(rawRules))
	}
	first := rawRules[0].(map[string]any)
	if first["rule_id"] != "ws-rule-1" {
		t.Errorf("rule_id = %v, want ws-rule-1", first["rule_id"])
	}
}

func TestLogBodyDLP_BundleRulesIncluded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	bundleRules := []BundleRuleHit{
		{RuleID: "dlp-rule-1", Bundle: "dlp-bundle", BundleVersion: "3.0.0"},
	}
	logger.LogBodyDLP(LogContext{method: "POST", url: "https://api.example.com", clientIP: testClientIP, requestID: "req-54"}, testActionWarn, 1, []string{"dlp-rule-1"}, bundleRules)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	rawRules, ok := entry["bundle_rules"].([]any)
	if !ok {
		t.Fatalf("expected bundle_rules array, got %T", entry["bundle_rules"])
	}
	if len(rawRules) != 1 {
		t.Fatalf("expected 1 bundle rule, got %d", len(rawRules))
	}
	first := rawRules[0].(map[string]any)
	if first["bundle"] != "dlp-bundle" {
		t.Errorf("bundle = %v, want dlp-bundle", first["bundle"])
	}
}

func TestLogHeaderDLP_BundleRulesIncluded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	bundleRules := []BundleRuleHit{
		{RuleID: "hdr-rule-1", Bundle: "hdr-bundle", BundleVersion: "1.0.0"},
	}
	logger.LogHeaderDLP(LogContext{method: testMethodGet, url: "https://api.example.com", clientIP: testClientIP, requestID: "req-55"}, "Authorization", testActionWarn, []string{"hdr-rule-1"}, bundleRules)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	rawRules, ok := entry["bundle_rules"].([]any)
	if !ok {
		t.Fatalf("expected bundle_rules array, got %T", entry["bundle_rules"])
	}
	if len(rawRules) != 1 {
		t.Fatalf("expected 1 bundle rule, got %d", len(rawRules))
	}
	first := rawRules[0].(map[string]any)
	if first["bundle"] != "hdr-bundle" {
		t.Errorf("bundle = %v, want hdr-bundle", first["bundle"])
	}
}

func TestLogger_With(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	sub := logger.With("agent", "test-bot")
	sub.LogAllowed(LogContext{method: testMethodGet, url: "https://example.com", clientIP: testClientIP, requestID: "req-1"}, 200, 100, time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["agent"] != "test-bot" {
		t.Errorf("expected agent=test-bot, got %v", entry["agent"])
	}
	if entry["event"] != "allowed" {
		t.Errorf("expected event=allowed, got %v", entry["event"])
	}
	if entry["component"] != testComponent {
		t.Errorf("expected component=pipelock inherited, got %v", entry["component"])
	}
}

func TestLogger_With_DoesNotAffectParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	_ = logger.With("agent", "child-bot")
	logger.LogAllowed(LogContext{method: testMethodGet, url: "https://example.com", clientIP: testClientIP, requestID: "req-1"}, 200, 100, time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if _, ok := entry["agent"]; ok {
		t.Error("expected parent logger not to have agent field")
	}
}

func TestLogger_With_InheritsConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// includeAllowed=false — sub-logger should inherit this
	logger, err := New("json", "file", path, false, true)
	if err != nil {
		t.Fatal(err)
	}

	sub := logger.With("agent", "test-bot")
	sub.LogAllowed(LogContext{method: testMethodGet, url: "https://example.com", clientIP: testClientIP, requestID: "req-1"}, 200, 100, time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected sub-logger to inherit includeAllowed=false and suppress allowed events")
	}
}

func TestLogRedirect_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogRedirect("https://example.com", "https://www.example.com", testClientIP, testReqID, "", 1)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "redirect" {
		t.Errorf("expected event=redirect, got %v", entry["event"])
	}
	if entry["original_url"] != "https://example.com" {
		t.Errorf("expected original_url, got %v", entry["original_url"])
	}
	if entry["redirect_url"] != "https://www.example.com" {
		t.Errorf("expected redirect_url, got %v", entry["redirect_url"])
	}
	hop, ok := entry["hop"].(float64)
	if !ok || hop != 1 {
		t.Errorf("expected hop=1, got %v", entry["hop"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != testReqID {
		t.Errorf("expected request_id=req-7, got %v", entry["request_id"])
	}
}

func TestLogTunnelOpen_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelOpen(LogContext{target: "example.com:443", clientIP: "10.0.0.5", requestID: "req-100"})
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "tunnel_open" {
		t.Errorf("expected event=tunnel_open, got %v", entry["event"])
	}
	if entry["target"] != "example.com:443" {
		t.Errorf("expected target=example.com:443, got %v", entry["target"])
	}
	if entry["client_ip"] != "10.0.0.5" {
		t.Errorf("expected client_ip=10.0.0.5, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-100" {
		t.Errorf("expected request_id=req-100, got %v", entry["request_id"])
	}
}

func TestLogTunnelOpen_Filtered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, false, true) // includeAllowed=false
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelOpen(LogContext{target: "example.com:443", clientIP: "10.0.0.5", requestID: "req-100"})
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected tunnel_open to be filtered when includeAllowed=false")
	}
}

func TestLogTunnelClose_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelClose(LogContext{target: "example.com:443", clientIP: "10.0.0.5", requestID: "req-100"}, 4096, 5*time.Second)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "tunnel_close" {
		t.Errorf("expected event=tunnel_close, got %v", entry["event"])
	}
	if entry["target"] != "example.com:443" {
		t.Errorf("expected target=example.com:443, got %v", entry["target"])
	}
	totalBytes, ok := entry["total_bytes"].(float64)
	if !ok || totalBytes != 4096 {
		t.Errorf("expected total_bytes=4096, got %v", entry["total_bytes"])
	}
	if _, ok := entry["duration_ms"]; !ok {
		t.Error("expected duration_ms field in tunnel_close event")
	}
}

func TestLogTunnelClose_Filtered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, false, true) // includeAllowed=false
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelClose(LogContext{target: "example.com:443", clientIP: "10.0.0.5", requestID: "req-100"}, 4096, 5*time.Second)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected tunnel_close to be filtered when includeAllowed=false")
	}
}

func TestLogForwardHTTP_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogForwardHTTP(LogContext{method: testMethodGet, url: "http://example.com/path", clientIP: "10.0.0.5", requestID: "req-200"}, 200, 2048, 100*time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "forward_http" {
		t.Errorf("expected event=forward_http, got %v", entry["event"])
	}
	if entry["method"] != testMethodGet {
		t.Errorf("expected method=GET, got %v", entry["method"])
	}
	if entry["url"] != "http://example.com/path" {
		t.Errorf("expected url=http://example.com/path, got %v", entry["url"])
	}
	statusCode, ok := entry["status_code"].(float64)
	if !ok || statusCode != 200 {
		t.Errorf("expected status_code=200, got %v", entry["status_code"])
	}
	sizeBytes, ok := entry["size_bytes"].(float64)
	if !ok || sizeBytes != 2048 {
		t.Errorf("expected size_bytes=2048, got %v", entry["size_bytes"])
	}
	if _, ok := entry["duration_ms"]; !ok {
		t.Error("expected duration_ms field in forward_http event")
	}
}

func TestLogForwardHTTP_Filtered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, false, true) // includeAllowed=false
	if err != nil {
		t.Fatal(err)
	}
	logger.LogForwardHTTP(LogContext{method: testMethodGet, url: "http://example.com/path", clientIP: "10.0.0.5", requestID: "req-200"}, 200, 2048, 100*time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected forward_http to be filtered when includeAllowed=false")
	}
}

func TestLogSessionAnomaly_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogSessionAnomaly(testClientIP, "domain_burst", "6 new domains in 5m window", testClientIP, "req-20", 2.0)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "session_anomaly" {
		t.Errorf("expected event=session_anomaly, got %v", entry["event"])
	}
	if entry["session"] != testClientIP {
		t.Errorf("expected session=10.0.0.1, got %v", entry["session"])
	}
	if entry["anomaly_type"] != "domain_burst" {
		t.Errorf("expected anomaly_type=domain_burst, got %v", entry["anomaly_type"])
	}
	if entry["detail"] != "6 new domains in 5m window" {
		t.Errorf("expected detail, got %v", entry["detail"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-20" {
		t.Errorf("expected request_id=req-20, got %v", entry["request_id"])
	}
	score, ok := entry["score"].(float64)
	if !ok || score != 2.0 {
		t.Errorf("expected score=2.0, got %v", entry["score"])
	}
}

func TestLogAdaptiveEscalation_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAdaptiveEscalation(testClientIP, testActionWarn, actionBlock, testClientIP, "req-30", 5.5)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "adaptive_escalation" {
		t.Errorf("expected event=adaptive_escalation, got %v", entry["event"])
	}
	if entry["session"] != testClientIP {
		t.Errorf("expected session=10.0.0.1, got %v", entry["session"])
	}
	if entry["from"] != testActionWarn {
		t.Errorf("expected from=warn, got %v", entry["from"])
	}
	if entry["to"] != actionBlock {
		t.Errorf("expected to=block, got %v", entry["to"])
	}
	score, ok := entry["score"].(float64)
	if !ok || score != 5.5 {
		t.Errorf("expected score=5.5, got %v", entry["score"])
	}
}

func TestLogMCPUnknownTool_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogMCPUnknownTool("execute_code", testActionWarn)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "mcp_unknown_tool" {
		t.Errorf("expected event=mcp_unknown_tool, got %v", entry["event"])
	}
	if entry["tool"] != "execute_code" {
		t.Errorf("expected tool=execute_code, got %v", entry["tool"])
	}
	if entry["action"] != testActionWarn {
		t.Errorf("expected action=warn, got %v", entry["action"])
	}
}

func TestNewNop_SessionEvents(_ *testing.T) {
	logger := NewNop()
	// Should not panic
	logger.LogSessionAnomaly(testClientIP, "domain_burst", "test", testClientIP, "req-1", 1.0)
	logger.LogAdaptiveEscalation(testClientIP, testActionWarn, actionBlock, testClientIP, "req-2", 5.0)
	logger.LogMCPUnknownTool("bad_tool", testActionWarn)
	logger.Close()
}

func TestLogConfigReload_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogConfigReload("success", "hot-reload via SIGHUP", testConfigHash)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "config_reload" {
		t.Errorf("expected event=config_reload, got %v", entry["event"])
	}
	if entry["status"] != "success" {
		t.Errorf("expected status=success, got %v", entry["status"])
	}
	if entry["detail"] != "hot-reload via SIGHUP" {
		t.Errorf("expected detail, got %v", entry["detail"])
	}
	if entry["config_hash"] != testConfigHash {
		t.Errorf("expected config_hash=%s, got %v", testConfigHash, entry["config_hash"])
	}
}

func TestLogWSOpen_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSOpen("ws://example.com/stream", "10.0.0.5", "req-200", "test-agent")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "ws_open" {
		t.Errorf("expected event=ws_open, got %v", entry["event"])
	}
	if entry["target"] != "ws://example.com/stream" {
		t.Errorf("expected target, got %v", entry["target"])
	}
	if entry["agent"] != "test-agent" {
		t.Errorf("expected agent=test-agent, got %v", entry["agent"])
	}
}

func TestLogWSOpen_Filtered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, false, true) // includeAllowed=false
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSOpen("ws://example.com/stream", "10.0.0.5", "req-200", "test-agent")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected ws_open to be filtered when includeAllowed=false")
	}
}

func TestLogWSClose_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSClose("ws://example.com/stream", "10.0.0.5", "req-200", "test-agent",
		4096, 8192, 10, 2, 5*time.Second)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "ws_close" {
		t.Errorf("expected event=ws_close, got %v", entry["event"])
	}
	if entry["target"] != "ws://example.com/stream" {
		t.Errorf("expected target, got %v", entry["target"])
	}
	c2s, ok := entry["client_to_server_bytes"].(float64)
	if !ok || c2s != 4096 {
		t.Errorf("expected client_to_server_bytes=4096, got %v", entry["client_to_server_bytes"])
	}
	s2c, ok := entry["server_to_client_bytes"].(float64)
	if !ok || s2c != 8192 {
		t.Errorf("expected server_to_client_bytes=8192, got %v", entry["server_to_client_bytes"])
	}
	tf, ok := entry["text_frames"].(float64)
	if !ok || tf != 10 {
		t.Errorf("expected text_frames=10, got %v", entry["text_frames"])
	}
}

func TestLogWSClose_Filtered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, false, true) // includeAllowed=false
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSClose("ws://example.com/stream", "10.0.0.5", "req-200", "test-agent",
		4096, 8192, 10, 2, 5*time.Second)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected ws_close to be filtered when includeAllowed=false")
	}
}

func TestLogWSBlocked_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSBlocked("ws://evil.com/exfil", DirectionClientToServer, ScannerDLP, "secret detected", testClientIP, "req-300")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "ws_blocked" {
		t.Errorf("expected event=ws_blocked, got %v", entry["event"])
	}
	if entry["direction"] != DirectionClientToServer {
		t.Errorf("expected direction=client_to_server, got %v", entry["direction"])
	}
	if entry["scanner"] != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %v", entry["scanner"])
	}
	if entry["reason"] != "secret detected" {
		t.Errorf("expected reason='secret detected', got %v", entry["reason"])
	}
}

func TestLogWSBlocked_Filtered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, false) // includeBlocked=false
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSBlocked("ws://evil.com/exfil", DirectionClientToServer, ScannerDLP, "secret detected", testClientIP, "req-300")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected ws_blocked to be filtered when includeBlocked=false")
	}
}

func TestLogWSScan_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSScan("ws://example.com/chat", DirectionServerToClient, testClientIP, "req-400", testActionWarn, 2, []string{"Prompt Injection", "Jailbreak"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "ws_scan" {
		t.Errorf("expected event=ws_scan, got %v", entry["event"])
	}
	if entry["direction"] != DirectionServerToClient {
		t.Errorf("expected direction=server_to_client, got %v", entry["direction"])
	}
	if entry["action"] != testActionWarn {
		t.Errorf("expected action=warn, got %v", entry["action"])
	}
	matchCount, ok := entry["match_count"].(float64)
	if !ok || matchCount != 2 {
		t.Errorf("expected match_count=2, got %v", entry["match_count"])
	}
	patterns, ok := entry["patterns"].([]any)
	if !ok || len(patterns) != 2 {
		t.Errorf("expected 2 patterns, got %v", entry["patterns"])
	}
	// server_to_client = response injection = T1059.
	if entry["mitre_technique"] != mitreT1059 {
		t.Errorf("expected mitre_technique=T1059 for server_to_client, got %v", entry["mitre_technique"])
	}
}

func TestLogWSScan_ClientToServer_DLPTechnique(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogWSScan("ws://example.com/chat", DirectionClientToServer, testClientIP, "req-401", "audit", 1, []string{"AWS Key"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	// client_to_server = DLP/exfil = T1048.
	if entry["mitre_technique"] != mitreT1048 {
		t.Errorf("expected mitre_technique=T1048 for client_to_server, got %v", entry["mitre_technique"])
	}
	if entry["direction"] != DirectionClientToServer {
		t.Errorf("expected direction=client_to_server, got %v", entry["direction"])
	}
}

func TestLogKillSwitchDeny_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogKillSwitchDeny("http", "https://api.example.com/v1/chat", "global", "all traffic halted", "10.0.0.5")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	checks := map[string]any{
		"event":        "kill_switch_deny",
		"transport":    "http",
		"endpoint":     "https://api.example.com/v1/chat",
		"source":       "global",
		"deny_message": "all traffic halted",
		"client_ip":    "10.0.0.5",
		"component":    "pipelock",
		"message":      "kill switch denied request",
	}
	for key, want := range checks {
		if entry[key] != want {
			t.Errorf("expected %s=%v, got %v", key, want, entry[key])
		}
	}

	if entry["time"] == nil {
		t.Error("expected time field")
	}
}

func TestLogKillSwitchDeny_SanitizesFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogKillSwitchDeny(
		"http",
		"https://evil\x1b[2J.com/path",
		"global",
		"bad\x1b[0mmessage",
		"10.0.0\x1b[2J.1",
	)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	for _, field := range []string{"transport", "endpoint", "source", "deny_message", "client_ip"} {
		val, _ := entry[field].(string)
		if strings.Contains(val, "\x1b") {
			t.Errorf("expected ANSI escape to be stripped from %s, got %q", field, val)
		}
	}
}

func TestLogTunnelOpen_SanitizesTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelOpen(LogContext{target: "evil\x1b[2J.com:443", clientIP: "10.0.0.5", requestID: "req-101"})
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	target, _ := entry["target"].(string)
	if strings.Contains(target, "\x1b") {
		t.Error("expected ANSI escape to be stripped from target")
	}
}

// --- Emitter path tests ---
// These verify that audit log methods actually emit events through the emitter.

func newLoggerWithEmitter(t *testing.T) (*Logger, *collectingSink) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	sink := &collectingSink{}
	emitter := emit.NewEmitter("test-instance", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })
	return logger, sink
}

func mustHTTPLogContext(t *testing.T, method, targetURL, requestID string) LogContext {
	t.Helper()
	ctx, err := NewHTTPLogContext(method, targetURL, testClientIP, requestID, testAgentName)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func mustConnectLogContext(t *testing.T, target, clientIP, requestID, agent string) LogContext {
	t.Helper()
	ctx, err := NewConnectLogContext(target, clientIP, requestID, agent)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func mustMCPLogContext(t *testing.T, method, resource, agent string) LogContext {
	t.Helper()
	ctx, err := NewMCPLogContext(method, resource, agent)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func assertEmitterContextFields(t *testing.T, ev emit.Event, wantKey string, wantValue any, absent ...string) {
	t.Helper()
	if got := ev.Fields[wantKey]; got != wantValue {
		t.Fatalf("fields[%s] = %v, want %v", wantKey, got, wantValue)
	}
	for _, key := range absent {
		if _, exists := ev.Fields[key]; exists {
			t.Fatalf("expected %q to be absent, got %v", key, ev.Fields[key])
		}
	}
}

func TestNewHTTPLogContext_RequiresCorrelationFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		url       string
		clientIP  string
		requestID string
		wantErr   error
	}{
		{name: "missing_url", url: "", clientIP: testClientIP, requestID: testReqID, wantErr: errLogContextMissingURL},
		{name: "missing_client_ip", url: "https://example.com", clientIP: "", requestID: testReqID, wantErr: errLogContextMissingClientIP},
		{name: "missing_request_id", url: "https://example.com", clientIP: testClientIP, requestID: "", wantErr: errLogContextMissingRequestID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewHTTPLogContext(testMethodGet, tt.url, tt.clientIP, tt.requestID, "")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewConnectLogContext_RequiresCorrelationFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		target    string
		clientIP  string
		requestID string
		wantErr   error
	}{
		{name: "missing_target", target: "", clientIP: testClientIP, requestID: testReqID, wantErr: errLogContextMissingTarget},
		{name: "missing_client_ip", target: "evil.com:443", clientIP: "", requestID: testReqID, wantErr: errLogContextMissingClientIP},
		{name: "missing_request_id", target: "evil.com:443", clientIP: testClientIP, requestID: "", wantErr: errLogContextMissingRequestID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewConnectLogContext(tt.target, tt.clientIP, tt.requestID, "")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewMCPLogContext_RequiresResource(t *testing.T) {
	t.Parallel()

	_, err := NewMCPLogContext("MCP", "", "")
	if !errors.Is(err, errLogContextMissingResource) {
		t.Fatalf("err = %v, want %v", err, errLogContextMissingResource)
	}
}

func TestNewLogContext_RejectsInvalidIdentifierCombinations(t *testing.T) {
	t.Parallel()

	_, err := newLogContext(testMethodGet, "https://example.com", "example.com:443", "", testClientIP, testReqID, "")
	if !errors.Is(err, errLogContextIdentifierClash) {
		t.Fatalf("err = %v, want %v", err, errLogContextIdentifierClash)
	}

	_, err = newLogContext(testMethodGet, "", "example.com:443", "", testClientIP, testReqID, "")
	if err == nil || !strings.Contains(err.Error(), "target contexts require") {
		t.Fatalf("err = %v, want target method validation error", err)
	}
}

func TestEmit_LogContextFieldRouting(t *testing.T) {
	tests := []struct {
		name      string
		emitFn    func(*testing.T, *Logger)
		wantType  string
		wantKey   string
		wantValue string
		absent    []string
	}{
		{
			name: "fetch_allowed_uses_url_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogAllowed(mustHTTPLogContext(t, testMethodGet, "https://fetch.example/path", "req-fetch"), 200, 64, time.Millisecond)
			},
			wantType:  string(EventAllowed),
			wantKey:   "url",
			wantValue: "https://fetch.example/path",
			absent:    []string{"target", "resource"},
		},
		{
			name: "forward_blocked_uses_url_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogBlocked(mustHTTPLogContext(t, "POST", "http://forward.example/path", "req-forward"), "blocklist", "blocked")
			},
			wantType:  string(EventBlocked),
			wantKey:   "url",
			wantValue: "http://forward.example/path",
			absent:    []string{"target", "resource"},
		},
		{
			name: "websocket_response_scan_uses_url_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogResponseScan(mustHTTPLogContext(t, "WS", "wss://socket.example/stream", "req-ws-scan"), testActionWarn, 1, []string{"injection"}, nil)
			},
			wantType:  string(EventResponseScan),
			wantKey:   "url",
			wantValue: "wss://socket.example/stream",
			absent:    []string{"target", "resource"},
		},
		{
			name: "websocket_exempt_uses_url_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogResponseScanExempt(mustHTTPLogContext(t, "WS", "ws://socket.example/stream", "req-ws-exempt"), "socket.example")
			},
			wantType:  string(EventResponseScanExempt),
			wantKey:   "url",
			wantValue: "ws://socket.example/stream",
			absent:    []string{"target", "resource"},
		},
		{
			name: "mcp_stdio_blocked_uses_resource_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogBlocked(mustMCPLogContext(t, "MCP", "tools/list", testAgentName), "mcp_tool_scanning", "poisoned description")
			},
			wantType:  string(EventBlocked),
			wantKey:   "resource",
			wantValue: "tools/list",
			absent:    []string{"url", "target"},
		},
		{
			name: "mcp_http_anomaly_uses_resource_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogAnomaly(mustMCPLogContext(t, "MCP", "resources/read", testAgentName), "prompt_injection", "tool output suspicious", 0.5)
			},
			wantType:  string(EventAnomaly),
			wantKey:   "resource",
			wantValue: "resources/read",
			absent:    []string{"url", "target"},
		},
		{
			name: "mcp_sse_exempt_uses_resource_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogResponseScanExempt(mustMCPLogContext(t, "MCP", "prompts/get", testAgentName), "mcp.example")
			},
			wantType:  string(EventResponseScanExempt),
			wantKey:   "resource",
			wantValue: "prompts/get",
			absent:    []string{"url", "target"},
		},
		{
			name: "connect_open_uses_target_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogTunnelOpen(mustConnectLogContext(t, "evil.com:443", testClientIP, "req-connect-open", testAgentName))
			},
			wantType:  string(EventTunnelOpen),
			wantKey:   "target",
			wantValue: "evil.com:443",
			absent:    []string{"url", "resource"},
		},
		{
			name: "connect_close_uses_target_only",
			emitFn: func(t *testing.T, logger *Logger) {
				logger.LogTunnelClose(mustConnectLogContext(t, "evil.com:443", testClientIP, "req-connect-close", testAgentName), 128, time.Second)
			},
			wantType:  string(EventTunnelClose),
			wantKey:   "target",
			wantValue: "evil.com:443",
			absent:    []string{"url", "resource"},
		},
		{
			name: "config_reload_error_uses_resource_only",
			emitFn: func(_ *testing.T, logger *Logger) {
				logger.LogError(NewResourceLogContext("CONFIG_RELOAD", "/etc/pipelock/config.yaml"), fmt.Errorf("validation failed"))
			},
			wantType:  string(EventError),
			wantKey:   "resource",
			wantValue: "/etc/pipelock/config.yaml",
			absent:    []string{"url", "target"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, sink := newLoggerWithEmitter(t)
			defer logger.Close()

			tt.emitFn(t, logger)

			ev, ok := sink.lastEvent()
			if !ok {
				t.Fatal("expected emitted event")
			}
			if ev.Type != tt.wantType {
				t.Fatalf("type = %q, want %q", ev.Type, tt.wantType)
			}
			assertEmitterContextFields(t, ev, tt.wantKey, tt.wantValue, tt.absent...)
		})
	}
}

func TestEmit_LogBlocked(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogBlocked(LogContext{method: testMethodGet, url: "https://evil.com", clientIP: testClientIP, requestID: "req-1"}, ScannerDLP, "secret found")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "blocked" {
		t.Errorf("type = %q, want blocked", ev.Type)
	}
	if ev.Fields["scanner"] != ScannerDLP {
		t.Errorf("fields[scanner] = %v, want dlp", ev.Fields["scanner"])
	}
	if ev.Fields["mitre_technique"] != mitreT1048 {
		t.Errorf("fields[mitre_technique] = %v, want T1048", ev.Fields["mitre_technique"])
	}
	if ev.InstanceID != "test-instance" {
		t.Errorf("instance_id = %q, want test-instance", ev.InstanceID)
	}
}

func TestEmit_LogBlocked_IncludeBlockedFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	logger, err := New("json", "file", path, true, false) // includeBlocked=false
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	sink := &collectingSink{}
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })

	logger.LogBlocked(LogContext{method: testMethodGet, url: "https://evil.com", clientIP: testClientIP, requestID: "req-1"}, ScannerDLP, "secret found")

	// Even with includeBlocked=false, emission should still fire
	if _, ok := sink.lastEvent(); !ok {
		t.Error("expected emitted event even when includeBlocked=false")
	}
}

func TestEmit_LogError(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogError(LogContext{method: testMethodGet, url: "https://example.com", clientIP: testClientIP, requestID: "req-2"}, fmt.Errorf("connection refused"))

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventError) {
		t.Errorf("type = %q, want error", ev.Type)
	}
	if ev.Fields[string(EventError)] != "connection refused" {
		t.Errorf("fields[error] = %v", ev.Fields[string(EventError)])
	}
}

func TestEmit_LogAnomaly(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogAnomaly(LogContext{method: testMethodGet, url: "https://example.com", clientIP: testClientIP, requestID: "req-3"}, "entropy", "high entropy", 3.5)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "anomaly" {
		t.Errorf("type = %q, want anomaly", ev.Type)
	}
	if ev.Fields["score"] != 3.5 {
		t.Errorf("fields[score] = %v, want 3.5", ev.Fields["score"])
	}
	if ev.Fields["scanner"] != "entropy" {
		t.Errorf("fields[scanner] = %v, want entropy", ev.Fields["scanner"])
	}
	if ev.Fields["mitre_technique"] != mitreT1048 {
		t.Errorf("fields[mitre_technique] = %v, want T1048", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogResponseScanExempt(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogResponseScanExempt(LogContext{method: testMethodGet, url: "https://api.openai.com/v1/chat", clientIP: testClientIP, requestID: "req-exempt-1", agent: testAgentName}, "api.openai.com")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventResponseScanExempt) {
		t.Errorf("type = %q, want %s", ev.Type, EventResponseScanExempt)
	}
	if ev.Fields["hostname"] != "api.openai.com" {
		t.Errorf("fields[hostname] = %v, want api.openai.com", ev.Fields["hostname"])
	}
	if ev.Fields["enforcement_type"] != "response_scanning" {
		t.Errorf("fields[enforcement_type] = %v, want response_scanning", ev.Fields["enforcement_type"])
	}
	if ev.Fields["reason"] != "exempt_domains match" {
		t.Errorf("fields[reason] = %v, want exempt_domains match", ev.Fields["reason"])
	}
	if ev.Fields["agent"] != testAgentName {
		t.Errorf("fields[agent] = %v, want %s", ev.Fields["agent"], testAgentName)
	}
}

func TestEmit_LogResponseScanExempt_NoAgent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogResponseScanExempt(LogContext{method: testMethodGet, url: "https://api.openai.com/v1/chat", clientIP: testClientIP, requestID: "req-exempt-2"}, "api.openai.com")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if _, hasAgent := ev.Fields["agent"]; hasAgent {
		t.Error("agent field should be absent when empty")
	}
}

func TestEmit_LogResponseScan(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogResponseScan(LogContext{url: "https://example.com", clientIP: testClientIP, requestID: "req-4"}, actionBlock, 2, []string{"injection", "jailbreak"}, nil)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventResponseScan) {
		t.Errorf("type = %q, want response_scan", ev.Type)
	}
	if ev.Fields["match_count"] != 2 {
		t.Errorf("fields[match_count] = %v, want 2", ev.Fields["match_count"])
	}
	if ev.Fields["mitre_technique"] != mitreT1059 {
		t.Errorf("fields[mitre_technique] = %v, want T1059", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogForwardHTTP(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogForwardHTTP(LogContext{method: testMethodGet, url: "http://example.com/path", clientIP: testClientIP, requestID: "req-forward-http", agent: testAgentName}, 200, 2048, 100*time.Millisecond)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventForwardHTTP) {
		t.Fatalf("type = %q, want %s", ev.Type, EventForwardHTTP)
	}
	if ev.Fields["url"] != "http://example.com/path" {
		t.Errorf("fields[url] = %v, want http://example.com/path", ev.Fields["url"])
	}
	if ev.Fields["status_code"] != 200 {
		t.Errorf("fields[status_code] = %v, want 200", ev.Fields["status_code"])
	}
}

func TestEmit_LogConfigReload(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogConfigReload("success", "SIGHUP", testConfigHash)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "config_reload" {
		t.Errorf("type = %q, want config_reload", ev.Type)
	}
	if ev.Fields["status"] != "success" {
		t.Errorf("fields[status] = %v", ev.Fields["status"])
	}
	if ev.Fields["config_hash"] != testConfigHash {
		t.Errorf("fields[config_hash] = %v, want %s", ev.Fields["config_hash"], testConfigHash)
	}
}

func TestEmit_LogWSBlocked(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogWSBlocked("ws://evil.com", DirectionClientToServer, ScannerDLP, "secret", testClientIP, "req-5")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "ws_blocked" {
		t.Errorf("type = %q, want ws_blocked", ev.Type)
	}
	if ev.Fields["mitre_technique"] != mitreT1048 {
		t.Errorf("fields[mitre_technique] = %v, want T1048", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogWSScan(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogWSScan("ws://example.com", DirectionServerToClient, testClientIP, "req-6", testActionWarn, 1, []string{"injection"}, nil)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "ws_scan" {
		t.Errorf("type = %q, want ws_scan", ev.Type)
	}
	if ev.Fields["mitre_technique"] != mitreT1059 {
		t.Errorf("fields[mitre_technique] = %v, want T1059", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogWSScan_ClientToServer(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogWSScan("ws://example.com", DirectionClientToServer, testClientIP, "req-6b", "audit", 1, []string{"AWS Key"}, nil)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Fields["mitre_technique"] != mitreT1048 {
		t.Errorf("fields[mitre_technique] = %v, want T1048", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogSessionAnomaly(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogSessionAnomaly(testClientIP, "domain_burst", "6 domains in 5m", testClientIP, testReqID, 2.0)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "session_anomaly" {
		t.Errorf("type = %q, want session_anomaly", ev.Type)
	}
	if ev.Fields["client_ip"] != testClientIP {
		t.Errorf("fields[client_ip] = %v, want 10.0.0.1", ev.Fields["client_ip"])
	}
	if ev.Fields["request_id"] != testReqID {
		t.Errorf("fields[request_id] = %v, want req-7", ev.Fields["request_id"])
	}
	if ev.Fields["mitre_technique"] != "T1078" {
		t.Errorf("fields[mitre_technique] = %v, want T1078", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogSessionAnomaly_OmitsEmptyFields(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	// Empty clientIP and requestID should be omitted from emitted event
	logger.LogSessionAnomaly("session-1", "domain_burst", "test", "", "", 1.0)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if _, exists := ev.Fields["client_ip"]; exists {
		t.Error("expected client_ip to be omitted when empty")
	}
	if _, exists := ev.Fields["request_id"]; exists {
		t.Error("expected request_id to be omitted when empty")
	}
}

func TestEmit_LogAdaptiveEscalation(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogAdaptiveEscalation(testClientIP, testActionWarn, actionBlock, testClientIP, "req-8", 5.5)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "adaptive_escalation" {
		t.Errorf("type = %q, want adaptive_escalation", ev.Type)
	}
	// Escalation to "block" should be critical severity
	if ev.Severity != emit.SeverityCritical {
		t.Errorf("severity = %v, want critical", ev.Severity)
	}
}

func TestEmit_LogAdaptiveEscalation_OmitsEmptyFields(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogAdaptiveEscalation("session-1", testActionWarn, actionBlock, "", "", 5.0)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if _, exists := ev.Fields["client_ip"]; exists {
		t.Error("expected client_ip to be omitted when empty")
	}
}

func TestEmit_LogMCPUnknownTool(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogMCPUnknownTool("execute_code", testActionWarn)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "mcp_unknown_tool" {
		t.Errorf("type = %q, want mcp_unknown_tool", ev.Type)
	}
	if ev.Fields["tool"] != "execute_code" {
		t.Errorf("fields[tool] = %v", ev.Fields["tool"])
	}
	if ev.Fields["mitre_technique"] != "T1195.002" {
		t.Errorf("fields[mitre_technique] = %v, want T1195.002", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogKillSwitchDeny(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogKillSwitchDeny("http", "https://example.com", "global", "halted", testClientIP)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "kill_switch_deny" {
		t.Errorf("type = %q, want kill_switch_deny", ev.Type)
	}
	if ev.Severity != emit.SeverityCritical {
		t.Errorf("severity = %v, want critical", ev.Severity)
	}
}

func TestEmit_DefensiveEvents_NoMITRETechnique(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	// Kill switch deny is a defensive action, not an attack detection.
	logger.LogKillSwitchDeny("http", "https://example.com", "api", "testing", testClientIP)
	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event for kill_switch_deny")
	}
	if _, exists := ev.Fields["mitre_technique"]; exists {
		t.Error("kill_switch_deny should not have mitre_technique field")
	}

	// Config reload is normal operation.
	logger.LogConfigReload("success", "SIGHUP", testConfigHash)
	ev, ok = sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event for config_reload")
	}
	if _, exists := ev.Fields["mitre_technique"]; exists {
		t.Error("config_reload should not have mitre_technique field")
	}

	// Adaptive escalation is a defensive response.
	logger.LogAdaptiveEscalation("session-1", testActionWarn, actionBlock, testClientIP, "req-1", 5.0)
	ev, ok = sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event for adaptive_escalation")
	}
	if _, exists := ev.Fields["mitre_technique"]; exists {
		t.Error("adaptive_escalation should not have mitre_technique field")
	}
}

func TestLogBodyDLP_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBodyDLP(LogContext{method: "POST", url: "https://api.example.com/v1/chat", clientIP: testClientIP, requestID: "req-50"}, testActionWarn, 2, []string{"AWS Access Key", "GitHub PAT"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventBodyDLP) {
		t.Errorf("expected event=body_dlp, got %v", entry["event"])
	}
	if entry["method"] != "POST" {
		t.Errorf("expected method=POST, got %v", entry["method"])
	}
	if entry["url"] != "https://api.example.com/v1/chat" {
		t.Errorf("expected url, got %v", entry["url"])
	}
	if entry["action"] != testActionWarn {
		t.Errorf("expected action=warn, got %v", entry["action"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-50" {
		t.Errorf("expected request_id=req-50, got %v", entry["request_id"])
	}
	matchCount, ok := entry["match_count"].(float64)
	if !ok || matchCount != 2 {
		t.Errorf("expected match_count=2, got %v", entry["match_count"])
	}
	patterns, ok := entry["patterns"].([]any)
	if !ok || len(patterns) != 2 {
		t.Errorf("expected 2 patterns, got %v", entry["patterns"])
	}
	if entry["mitre_technique"] != mitreT1048 {
		t.Errorf("expected mitre_technique=T1048, got %v", entry["mitre_technique"])
	}
}

func TestLogHeaderDLP_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogHeaderDLP(LogContext{method: "POST", url: "https://api.example.com/v1/chat", clientIP: testClientIP, requestID: "req-51"}, "Authorization", actionBlock, []string{"AWS Access Key"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventHeaderDLP) {
		t.Errorf("expected event=header_dlp, got %v", entry["event"])
	}
	if entry["method"] != "POST" {
		t.Errorf("expected method=POST, got %v", entry["method"])
	}
	if entry["header"] != "Authorization" {
		t.Errorf("expected header=Authorization, got %v", entry["header"])
	}
	if entry["action"] != actionBlock {
		t.Errorf("expected action=block, got %v", entry["action"])
	}
	if entry["mitre_technique"] != mitreT1048 {
		t.Errorf("expected mitre_technique=T1048, got %v", entry["mitre_technique"])
	}
}

func TestEmit_LogBodyDLP(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogBodyDLP(LogContext{method: "POST", url: "https://api.example.com", clientIP: testClientIP, requestID: "req-52"}, actionBlock, 1, []string{"AWS Key"}, nil)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventBodyDLP) {
		t.Errorf("type = %q, want body_dlp", ev.Type)
	}
	if ev.Fields["mitre_technique"] != mitreT1048 {
		t.Errorf("fields[mitre_technique] = %v, want T1048", ev.Fields["mitre_technique"])
	}
	if ev.Fields["match_count"] != 1 {
		t.Errorf("fields[match_count] = %v, want 1", ev.Fields["match_count"])
	}
}

func TestEmit_LogBodyScanAddressProtection(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogBodyScan(LogContext{method: "POST", url: "https://api.example.com", clientIP: testClientIP, requestID: "req-addr-1", agent: "trader-bot"}, EventAddressProtection, actionBlock, 1, []string{"ETH lookalike detected"})

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "address_protection" {
		t.Errorf("type = %q, want address_protection", ev.Type)
	}
	if ev.Fields["match_count"] != 1 {
		t.Errorf("fields[match_count] = %v, want 1", ev.Fields["match_count"])
	}
	if ev.Fields["agent"] != "trader-bot" {
		t.Errorf("fields[agent] = %v, want trader-bot", ev.Fields["agent"])
	}
}

func TestEmit_LogHeaderDLP(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogHeaderDLP(LogContext{method: testMethodGet, url: "https://api.example.com", clientIP: testClientIP, requestID: "req-53"}, "Authorization", actionBlock, []string{"GitHub PAT"}, nil)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventHeaderDLP) {
		t.Errorf("type = %q, want header_dlp", ev.Type)
	}
	if ev.Fields["header"] != "Authorization" {
		t.Errorf("fields[header] = %v, want Authorization", ev.Fields["header"])
	}
	if ev.Fields["mitre_technique"] != mitreT1048 {
		t.Errorf("fields[mitre_technique] = %v, want T1048", ev.Fields["mitre_technique"])
	}
}

func TestEmit_LogAnomaly_NoScanner_NoTechnique(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	// Operational anomaly with empty scanner should not have mitre_technique.
	logger.LogAnomaly(LogContext{method: "STARTUP", url: "0.0.0.0:8888"}, "", "listen address not loopback", 0.5)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if _, exists := ev.Fields["scanner"]; exists {
		t.Error("expected scanner to be omitted when empty")
	}
	if _, exists := ev.Fields["mitre_technique"]; exists {
		t.Error("expected mitre_technique to be omitted when scanner is empty")
	}
}

func TestLogSNIMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogSNIMismatch("allowed.com", "evil.com", testClientIP, testReqID, "test-agent", "mismatch")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("unmarshal: %v\ndata: %s", err, data)
	}

	if entry["event"] != string(EventSNIMismatch) {
		t.Errorf("event = %v, want %s", entry["event"], EventSNIMismatch)
	}
	if entry["connect_host"] != "allowed.com" {
		t.Errorf("connect_host = %v, want allowed.com", entry["connect_host"])
	}
	if entry["sni_host"] != "evil.com" {
		t.Errorf("sni_host = %v, want evil.com", entry["sni_host"])
	}
	if entry["category"] != "mismatch" {
		t.Errorf("category = %v, want mismatch", entry["category"])
	}
	if entry["mitre_technique"] != "T1090.004" {
		t.Errorf("mitre_technique = %v, want T1090.004", entry["mitre_technique"])
	}
}

func TestLogSNIMismatch_Emitter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{}
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)

	logger.LogSNIMismatch("allowed.com", "evil.com", testClientIP, testReqID, "test-agent", "mismatch")
	logger.Close()
	_ = emitter.Close()

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventSNIMismatch) {
		t.Errorf("emitted type = %q, want %q", ev.Type, EventSNIMismatch)
	}
	if ev.Fields["connect_host"] != "allowed.com" {
		t.Errorf("connect_host = %v, want allowed.com", ev.Fields["connect_host"])
	}
	if ev.Fields["sni_host"] != "evil.com" {
		t.Errorf("sni_host = %v, want evil.com", ev.Fields["sni_host"])
	}
	if ev.Fields["mitre_technique"] != "T1090.004" {
		t.Errorf("mitre_technique = %v, want T1090.004", ev.Fields["mitre_technique"])
	}
}

func TestLogChainDetection_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogChainDetection("exfil_then_delete", severityCritical, actionBlock, "filesystem_delete", "session-abc")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("unmarshal: %v\ndata: %s", err, data)
	}

	if entry["event"] != string(EventChainDetection) {
		t.Errorf("event = %v, want %s", entry["event"], EventChainDetection)
	}
	if entry["pattern"] != "exfil_then_delete" {
		t.Errorf("pattern = %v, want exfil_then_delete", entry["pattern"])
	}
	// pattern_severity is the caller-provided metadata; severity is derived from action.
	if entry["pattern_severity"] != severityCritical {
		t.Errorf("pattern_severity = %v, want %s", entry["pattern_severity"], severityCritical)
	}
	if entry["severity"] != severityCritical {
		t.Errorf("severity = %v, want %s (derived from block action)", entry["severity"], severityCritical)
	}
	if entry["action"] != actionBlock {
		t.Errorf("action = %v, want block", entry["action"])
	}
	if entry["tool"] != "filesystem_delete" {
		t.Errorf("tool = %v, want filesystem_delete", entry["tool"])
	}
	if entry["session"] != "session-abc" {
		t.Errorf("session = %v, want session-abc", entry["session"])
	}
	if entry["mitre_technique"] != mitreT1059 {
		t.Errorf("mitre_technique = %v, want %s", entry["mitre_technique"], mitreT1059)
	}
}

func TestLogChainDetection_Emitter_Block(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogChainDetection("exfil_then_delete", severityCritical, actionBlock, "filesystem_delete", "session-abc")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != string(EventChainDetection) {
		t.Errorf("emitted type = %q, want %q", ev.Type, EventChainDetection)
	}
	if ev.Severity != emit.SeverityCritical {
		t.Errorf("severity = %v, want %v", ev.Severity, emit.SeverityCritical)
	}
	if ev.Fields["pattern"] != "exfil_then_delete" {
		t.Errorf("pattern = %v, want exfil_then_delete", ev.Fields["pattern"])
	}
	if ev.Fields["pattern_severity"] != severityCritical {
		t.Errorf("pattern_severity = %v, want %s", ev.Fields["pattern_severity"], severityCritical)
	}
	if ev.Fields["severity"] != severityCritical {
		t.Errorf("severity = %v, want %s (derived from block action)", ev.Fields["severity"], severityCritical)
	}
	if ev.Fields["tool"] != "filesystem_delete" {
		t.Errorf("tool = %v, want filesystem_delete", ev.Fields["tool"])
	}
	if ev.Fields["session"] != "session-abc" {
		t.Errorf("session = %v, want session-abc", ev.Fields["session"])
	}
	if ev.Fields["mitre_technique"] != mitreT1059 {
		t.Errorf("mitre_technique = %v, want %s", ev.Fields["mitre_technique"], mitreT1059)
	}
}

func TestLogChainDetection_Emitter_Warn(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogChainDetection("read_then_exfil", "warn", "warn", "http_fetch", "session-xyz")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Severity != emit.SeverityWarn {
		t.Errorf("severity = %v, want %v", ev.Severity, emit.SeverityWarn)
	}
	if ev.Fields["action"] != "warn" {
		t.Errorf("action = %v, want warn", ev.Fields["action"])
	}
}

func TestLogBlockedIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(LogContext{method: testMethodGet, url: "http://evil.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "dlp", "secret found")
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogBlockedOmitsEmptyAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(LogContext{method: testMethodGet, url: "http://evil.com", clientIP: testClientIP, requestID: "req-1"}, "dlp", "secret found")
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if _, exists := entry["agent"]; exists {
		t.Errorf("agent key should not be present for empty agent, got %v", entry["agent"])
	}
}

func TestLogAllowedIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAllowed(LogContext{method: testMethodGet, url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, 200, 1024, time.Second)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogErrorIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogError(LogContext{method: testMethodGet, url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, fmt.Errorf("connection refused"))
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogAnomalyIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAnomaly(LogContext{method: testMethodGet, url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "dlp", "suspicious", 0.5)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogTunnelOpenIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelOpen(LogContext{target: "example.com:443", clientIP: testClientIP, requestID: "req-1", agent: testAgentName})
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogBlockedEmitterIncludesAgent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogBlocked(LogContext{method: testMethodGet, url: "http://evil.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "dlp", "secret found")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Fields["agent"] != testAgentName {
		t.Errorf("emitter agent = %v, want %s", ev.Fields["agent"], testAgentName)
	}
}

func TestLogBlockedEmitterOmitsEmptyAgent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogBlocked(LogContext{method: testMethodGet, url: "http://evil.com", clientIP: testClientIP, requestID: "req-1"}, "dlp", "secret found")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if _, exists := ev.Fields["agent"]; exists {
		t.Errorf("emitter agent key should not be present for empty agent, got %v", ev.Fields["agent"])
	}
}

func TestLogResponseScanEmitterIncludesAgent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogResponseScan(LogContext{url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "block", 1, []string{"injection"}, nil)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Fields["agent"] != testAgentName {
		t.Errorf("emitter agent = %v, want %s", ev.Fields["agent"], testAgentName)
	}
}

func TestLogAnomalyEmitterIncludesAgent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogAnomaly(LogContext{method: testMethodGet, url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "dlp", "suspicious", 0.5)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Fields["agent"] != testAgentName {
		t.Errorf("emitter agent = %v, want %s", ev.Fields["agent"], testAgentName)
	}
}

func TestLogErrorEmitterIncludesAgent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogError(LogContext{method: testMethodGet, url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, fmt.Errorf("test"))

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Fields["agent"] != testAgentName {
		t.Errorf("emitter agent = %v, want %s", ev.Fields["agent"], testAgentName)
	}
}

func TestLogChainDetection_PersistPatternEmitsT1053(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogChainDetection("write-persist", severityCritical, actionBlock, "systemctl_enable", "session-1")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("unmarshal: %v\ndata: %s", err, data)
	}

	if entry["mitre_technique"] != mitreT1053 {
		t.Errorf("mitre_technique = %v, want %s for persistence pattern", entry["mitre_technique"], mitreT1053)
	}
}

func TestLogChainDetection_NonPersistPatternEmitsT1059(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogChainDetection("read-then-exec", severityWarn, testActionWarn, "bash_exec", "session-2")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("unmarshal: %v\ndata: %s", err, data)
	}

	if entry["mitre_technique"] != mitreT1059 {
		t.Errorf("mitre_technique = %v, want %s for non-persistence pattern", entry["mitre_technique"], mitreT1059)
	}
}

func TestLogResponseScanIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogResponseScan(LogContext{url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "block", 1, []string{"injection"}, nil)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogTunnelCloseIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelClose(LogContext{target: "example.com:443", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, 1024, time.Second)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogForwardHTTPIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogForwardHTTP(LogContext{method: testMethodGet, url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, 200, 512, time.Second)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogRedirectIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogRedirect("http://a.com", "http://b.com", testClientIP, "req-1", testAgentName, 1)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogBodyDLPIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBodyDLP(LogContext{method: "POST", url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "block", 1, []string{"aws_key"}, nil)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogHeaderDLPIncludesAgent(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "audit.jsonl")
	logger, err := New("json", "file", logFile, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogHeaderDLP(LogContext{method: testMethodGet, url: "http://example.com", clientIP: testClientIP, requestID: "req-1", agent: testAgentName}, "Authorization", "warn", []string{"bearer"}, nil)
	logger.Close()

	data, err := os.ReadFile(filepath.Clean(logFile))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry["agent"] != testAgentName {
		t.Errorf("agent = %v, want %s", entry["agent"], testAgentName)
	}
}

func TestLogAgentListener(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAgentListener("127.0.0.1:9100", "strict-bot")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("unmarshal: %v\ndata: %s", err, data)
	}

	if entry["event"] != string(EventAgentListener) {
		t.Errorf("event = %v, want %s", entry["event"], EventAgentListener)
	}
	if entry["listen"] != "127.0.0.1:9100" {
		t.Errorf("listen = %v, want 127.0.0.1:9100", entry["listen"])
	}
	if entry["agent"] != "strict-bot" {
		t.Errorf("agent = %v, want strict-bot", entry["agent"])
	}
}

func TestLogAdaptiveUpgrade_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAdaptiveUpgrade("agent|10.0.0.1", "elevated", testActionWarn, actionBlock, ScannerDLP, testClientIP, "req-123")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	tests := []struct {
		field string
		want  any
	}{
		{"event", "adaptive_upgrade"},
		{"session", "agent|10.0.0.1"},
		{"escalation_level", "elevated"},
		{"from_action", testActionWarn},
		{"to_action", actionBlock},
		{"scanner", ScannerDLP},
		{"client_ip", testClientIP},
		{"request_id", "req-123"},
	}
	for _, tt := range tests {
		if entry[tt.field] != tt.want {
			t.Errorf("field %q = %v, want %v", tt.field, entry[tt.field], tt.want)
		}
	}
}

func TestLogAdaptiveUpgrade_Nop(_ *testing.T) {
	// Nop logger should not panic.
	logger := NewNop()
	logger.LogAdaptiveUpgrade("agent|10.0.0.1", "elevated", testActionWarn, actionBlock, ScannerDLP, testClientIP, "req-1")
	logger.Close()
}

func TestEmit_LogAdaptiveUpgrade(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogAdaptiveUpgrade("agent|10.0.0.1", "elevated", testActionWarn, actionBlock, ScannerDLP, testClientIP, "req-99")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "adaptive_upgrade" {
		t.Errorf("type = %q, want adaptive_upgrade", ev.Type)
	}
	// Upgrade to "block" must emit at critical severity.
	if ev.Severity != emit.SeverityCritical {
		t.Errorf("severity = %v, want critical", ev.Severity)
	}
	if ev.Fields["escalation_level"] != "elevated" {
		t.Errorf("escalation_level = %v, want elevated", ev.Fields["escalation_level"])
	}
	if ev.Fields["from_action"] != testActionWarn {
		t.Errorf("from_action = %v, want %s", ev.Fields["from_action"], testActionWarn)
	}
	if ev.Fields["to_action"] != actionBlock {
		t.Errorf("to_action = %v, want %s", ev.Fields["to_action"], actionBlock)
	}
}

func TestEmit_LogAdaptiveUpgrade_WarnSeverity(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	// Upgrade to "warn" (not block) must emit at warn severity.
	logger.LogAdaptiveUpgrade("agent|10.0.0.1", "high", "forward", testActionWarn, ScannerDLP, testClientIP, "req-100")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Severity != emit.SeverityWarn {
		t.Errorf("severity = %v, want warn", ev.Severity)
	}
}

func TestEmit_LogAdaptiveUpgrade_OmitsEmptyOptional(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogAdaptiveUpgrade("session-key", "elevated", testActionWarn, actionBlock, ScannerDLP, "", "")

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if _, exists := ev.Fields["client_ip"]; exists {
		t.Error("expected client_ip to be omitted when empty")
	}
	if _, exists := ev.Fields["request_id"]; exists {
		t.Error("expected request_id to be omitted when empty")
	}
}

func TestLogToolRedirect_JSONFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogToolRedirect("sess-1", "bash", "sha256:abc123 len=42", "safe-fetch", "audited handler", "redirect-curl", "redirected", 15)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one log line")
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if entry["event"] != "tool_redirect" {
		t.Errorf("event = %v, want tool_redirect", entry["event"])
	}
	if entry["tool_name"] != "bash" {
		t.Errorf("tool_name = %v, want bash", entry["tool_name"])
	}
	if entry["args_digest"] != "sha256:abc123 len=42" {
		t.Errorf("args_digest = %v, want sha256:abc123 len=42", entry["args_digest"])
	}
	if entry["redirect_profile"] != "safe-fetch" {
		t.Errorf("redirect_profile = %v, want safe-fetch", entry["redirect_profile"])
	}
	if entry["result"] != "redirected" {
		t.Errorf("result = %v, want redirected", entry["result"])
	}
	if entry["session_id"] != "sess-1" {
		t.Errorf("session_id = %v, want sess-1", entry["session_id"])
	}
}

func TestLogToolRedirect_Emitter(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()

	logger.LogToolRedirect("sess-2", "curl-tool", "sha256:def456 len=100", "safe-fetch", "audited", "rule-1", "redirected", 25)

	ev, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if ev.Type != "tool_redirect" {
		t.Errorf("type = %q, want tool_redirect", ev.Type)
	}
	if ev.Fields["tool_name"] != "curl-tool" {
		t.Errorf("tool_name = %v, want curl-tool", ev.Fields["tool_name"])
	}
	if ev.Fields["redirect_profile"] != "safe-fetch" {
		t.Errorf("redirect_profile = %v, want safe-fetch", ev.Fields["redirect_profile"])
	}
	if ev.Fields["result"] != "redirected" {
		t.Errorf("result = %v, want redirected", ev.Fields["result"])
	}
	// session_id must NOT be in emitted fields — it's local-log only.
	if _, exists := ev.Fields["session_id"]; exists {
		t.Error("session_id must not be emitted to external sinks")
	}
}

func TestLogToolRedirect_NoSessionID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogToolRedirect("", "bash", "sha256:abc len=10", "p", "r", "rule", "blocked", 5)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, exists := entry["session_id"]; exists {
		t.Error("expected session_id to be omitted when empty")
	}
}

// TestLogContext_EmptyFieldsOmitted verifies that LogContext methods using optStr
// omit client_ip, request_id, and agent when empty (MCP/CEE paths).
func TestLogContext_EmptyFieldsOmitted(t *testing.T) {
	tests := []struct {
		name   string
		logFn  func(*Logger)
		absent []string
	}{
		{
			name: "LogBlocked_empty_http_fields",
			logFn: func(l *Logger) {
				l.LogBlocked(LogContext{method: "CEE", url: "mcp-input"}, "cross_request_entropy", "budget exceeded")
			},
			absent: []string{"client_ip", "request_id", "agent"},
		},
		{
			name: "LogAnomaly_empty_http_fields",
			logFn: func(l *Logger) {
				l.LogAnomaly(LogContext{method: "CEE", url: "mcp-input"}, "cross_request_entropy", "near miss", 0)
			},
			absent: []string{"client_ip", "request_id", "agent"},
		},
		{
			name: "LogError_empty_http_fields",
			logFn: func(l *Logger) {
				l.LogError(LogContext{method: "RELOAD"}, fmt.Errorf("test error"))
			},
			absent: []string{"client_ip", "request_id", "agent"},
		},
		{
			name: "LogResponseScanExempt_empty_http_fields",
			logFn: func(l *Logger) {
				l.LogResponseScanExempt(LogContext{method: "WS", url: "ws://example.com"}, "example.com")
			},
			absent: []string{"client_ip", "request_id", "agent"},
		},
		{
			name: "LogResponseScan_includes_method",
			logFn: func(l *Logger) {
				l.LogResponseScan(LogContext{method: testMethodGet, url: "https://example.com", clientIP: testClientIP, requestID: "req-1"}, testActionWarn, 1, []string{"injection"}, nil)
			},
			absent: []string{"agent"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "test.log")
			logger, err := New("json", "file", path, true, true)
			if err != nil {
				t.Fatal(err)
			}
			tt.logFn(logger)
			logger.Close()

			data, _ := os.ReadFile(filepath.Clean(path))
			var entry map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			for _, key := range tt.absent {
				if _, exists := entry[key]; exists {
					t.Errorf("expected %q to be omitted when empty, but it was present with value %v", key, entry[key])
				}
			}
		})
	}
}

// TestLogResponseScan_IncludesMethod verifies the method field is present in response_scan events.
func TestLogResponseScan_IncludesMethod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogResponseScan(LogContext{method: testMethodGet, url: "https://example.com", clientIP: testClientIP, requestID: "req-method-1"}, testActionWarn, 1, []string{"Prompt Injection"}, nil)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if entry["method"] != testMethodGet {
		t.Errorf("expected method=GET, got %v", entry["method"])
	}
}

// TestLogContext_ResourceField_MCP verifies that MCP contexts emit "resource"
// instead of "url" in the audit log output.
func TestLogContext_ResourceField_MCP(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "resource-mcp.json")
	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := NewMCPLogContext("MCP", "tools/list", testAgentName)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(ctx, "mcp_tool_scanning", "poisoned description")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if entry["resource"] != "tools/list" {
		t.Errorf("expected resource=tools/list, got %v", entry["resource"])
	}
	if _, hasURL := entry["url"]; hasURL {
		t.Error("url field should be absent for MCP contexts")
	}
	if _, hasTarget := entry["target"]; hasTarget {
		t.Error("target field should be absent for MCP contexts")
	}
}

// TestLogContext_ResourceField_ConfigReload verifies that config reload contexts
// emit "resource" for the config file path.
func TestLogContext_ResourceField_ConfigReload(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "resource-config.json")
	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx := LogContext{method: "CONFIG_RELOAD", resource: "/etc/pipelock/config.yaml"}
	logger.LogError(ctx, fmt.Errorf("validation failed"))
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if entry["resource"] != "/etc/pipelock/config.yaml" {
		t.Errorf("expected resource path, got %v", entry["resource"])
	}
	if _, hasURL := entry["url"]; hasURL {
		t.Error("url field should be absent for config contexts")
	}
}

// TestLogContext_TargetField_Connect verifies that CONNECT contexts emit
// "target" instead of "url".
func TestLogContext_TargetField_Connect(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "target-connect.json")
	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := NewConnectLogContext("evil.com:443", testClientIP, testReqID, testAgentName)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelOpen(ctx)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if entry["target"] != "evil.com:443" {
		t.Errorf("expected target=evil.com:443, got %v", entry["target"])
	}
	if _, hasURL := entry["url"]; hasURL {
		t.Error("url field should be absent for CONNECT contexts")
	}
	if _, hasResource := entry["resource"]; hasResource {
		t.Error("resource field should be absent for CONNECT contexts")
	}
}

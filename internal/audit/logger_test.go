package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	logger.LogAllowed("GET", "https://example.com", "127.0.0.1", "req-1", 200, 1024, time.Second)
	logger.LogBlocked("GET", "https://evil.com", "blocklist", "domain blocked", "127.0.0.1", "req-2")
	logger.LogError("GET", "https://fail.com", "127.0.0.1", "req-3", os.ErrNotExist)
	logger.LogAnomaly("GET", "https://sus.com", "high entropy", "127.0.0.1", "req-4", 0.9)
	logger.LogStartup(":8888", "balanced")
	logger.LogShutdown("test")
	logger.LogRedirect("https://a.com", "https://b.com", "127.0.0.1", "req-6", 1)
	logger.LogResponseScan("https://example.com", "127.0.0.1", "req-8", "warn", 2, []string{"Prompt Injection", "Jailbreak Attempt"})
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
	logger.LogAllowed("GET", "https://example.com", "127.0.0.1", "req-1", 200, 1024, time.Second)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogBlocked("GET", "https://evil.com", "blocklist", "domain blocked", "127.0.0.1", "req-1")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogAllowed("GET", "https://example.com", "10.0.0.5", "req-42", 200, 1024, time.Second)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	if entry["method"] != "GET" {
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
	logger.LogBlocked("GET", "https://evil.com", "blocklist", "domain in blocklist", "192.168.1.1", "req-7")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	if entry["request_id"] != "req-7" {
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
	logger.LogError("GET", "https://fail.com", "10.0.0.1", "req-9", os.ErrNotExist)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "error" {
		t.Errorf("expected event=error, got %v", entry["event"])
	}
	if entry["error"] == nil || entry["error"] == "" {
		t.Error("expected error field to be populated")
	}
	if entry["client_ip"] != "10.0.0.1" { //nolint:goconst // test value
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
	logger.LogStartup(":8888", "balanced")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogAnomaly("GET", "https://sus.com/data", "high entropy segment", "10.0.0.1", "req-5", 0.85)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	if entry["client_ip"] != "10.0.0.1" {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-5" {
		t.Errorf("expected request_id=req-5, got %v", entry["request_id"])
	}
}

func TestNew_BothOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "both", path, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logger.LogStartup(":8888", "balanced")
	logger.Close()

	// Verify file was written
	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogStartup(":8888", "balanced")
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
	logger.LogAllowed("GET", "https://example.com/page", "10.0.0.5", "req-100", 200, 5000, 150*time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	checks := map[string]any{
		"event":      "allowed",
		"method":     "GET",
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
	logger.LogBlocked("GET", "https://evil.com/exfil", "blocklist", "domain in blocklist: evil.com", "192.168.1.1", "req-50")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	checks := map[string]any{
		"event":      "blocked",
		"method":     "GET",
		"url":        "https://evil.com/exfil",
		"scanner":    "blocklist",
		"reason":     "domain in blocklist: evil.com",
		"component":  "pipelock",
		"client_ip":  "192.168.1.1",
		"request_id": "req-50",
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
	logger.LogError("GET", "https://fail.com", "10.0.0.1", "req-77", os.ErrPermission)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "error" {
		t.Errorf("expected event=error, got %v", entry["event"])
	}
	if entry["component"] != "pipelock" { //nolint:goconst // test value
		t.Errorf("expected component=pipelock, got %v", entry["component"])
	}
	if entry["client_ip"] != "10.0.0.1" { //nolint:goconst // test value
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
	logger.LogStartup(":8888", "test")
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

	logger.LogStartup(":8888", "balanced")
	logger.LogAllowed("GET", "https://a.com", "10.0.0.1", "req-1", 200, 100, time.Millisecond)
	logger.LogBlocked("GET", "https://b.com", "dlp", "secret found", "10.0.0.1", "req-2")
	logger.LogError("GET", "https://c.com", "10.0.0.1", "req-3", os.ErrNotExist)
	logger.LogAnomaly("GET", "https://d.com", "weird", "10.0.0.1", "req-4", 0.5)
	logger.LogShutdown("done")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogResponseScan("https://example.com/page", "10.0.0.1", "req-10", "warn", 2, []string{"Prompt Injection", "Jailbreak Attempt"})
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "response_scan" {
		t.Errorf("expected event=response_scan, got %v", entry["event"])
	}
	if entry["url"] != "https://example.com/page" {
		t.Errorf("expected url, got %v", entry["url"])
	}
	if entry["client_ip"] != "10.0.0.1" {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-10" {
		t.Errorf("expected request_id=req-10, got %v", entry["request_id"])
	}
	if entry["action"] != "warn" {
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
	if entry["component"] != "pipelock" {
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
	logger.LogResponseScan("https://example.com/page", "10.0.0.1", "req-11", "strip", 1, []string{"System Override"})
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "response_scan" {
		t.Errorf("expected event=response_scan, got %v", entry["event"])
	}
	if entry["action"] != "strip" {
		t.Errorf("expected action=strip, got %v", entry["action"])
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
	sub.LogAllowed("GET", "https://example.com", "10.0.0.1", "req-1", 200, 100, time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // test reads its own temp file
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
	if entry["component"] != "pipelock" {
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
	logger.LogAllowed("GET", "https://example.com", "10.0.0.1", "req-1", 200, 100, time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // test reads its own temp file
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
	sub.LogAllowed("GET", "https://example.com", "10.0.0.1", "req-1", 200, 100, time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // test reads its own temp file
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
	logger.LogRedirect("https://example.com", "https://www.example.com", "10.0.0.1", "req-7", 1)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	if entry["client_ip"] != "10.0.0.1" {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-7" {
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
	logger.LogTunnelOpen("example.com:443", "10.0.0.5", "req-100")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogTunnelOpen("example.com:443", "10.0.0.5", "req-100")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogTunnelClose("example.com:443", "10.0.0.5", "req-100", 4096, 5*time.Second)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogTunnelClose("example.com:443", "10.0.0.5", "req-100", 4096, 5*time.Second)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
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
	logger.LogForwardHTTP("GET", "http://example.com/path", "10.0.0.5", "req-200", 200, 2048, 100*time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "forward_http" {
		t.Errorf("expected event=forward_http, got %v", entry["event"])
	}
	if entry["method"] != "GET" {
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
	logger.LogForwardHTTP("GET", "http://example.com/path", "10.0.0.5", "req-200", 200, 2048, 100*time.Millisecond)
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	if len(bytes.TrimSpace(data)) > 0 {
		t.Error("expected forward_http to be filtered when includeAllowed=false")
	}
}

func TestLogTunnelOpen_SanitizesTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogTunnelOpen("evil\x1b[2J.com:443", "10.0.0.5", "req-101")
	logger.Close()

	data, _ := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	target, _ := entry["target"].(string)
	if strings.Contains(target, "\x1b") {
		t.Error("expected ANSI escape to be stripped from target")
	}
}

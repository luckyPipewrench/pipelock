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
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %o", perm)
	}
}

func TestNew_FileOutputMissingPath(t *testing.T) {
	_, err := New("json", "file", "/nonexistent/dir/test.log", true, true)
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestNewNop(t *testing.T) {
	logger := NewNop()
	// Should not panic
	logger.LogAllowed("GET", "https://example.com", "127.0.0.1", "req-1", 200, 1024, time.Second)
	logger.LogBlocked("GET", "https://evil.com", "blocklist", "domain blocked", "127.0.0.1", "req-2")
	logger.LogError("GET", "https://fail.com", "127.0.0.1", "req-3", os.ErrNotExist)
	logger.LogAnomaly("GET", "https://sus.com", "high entropy", "127.0.0.1", "req-4", 0.9)
	logger.LogStartup(":8888", "balanced")
	logger.LogShutdown("test")
	logger.LogRedirect("https://a.com", "https://b.com", "127.0.0.1", "req-6", 1)
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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
	if entry["client_ip"] != "10.0.0.1" {
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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
	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
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

	data, _ := os.ReadFile(path)
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != "error" {
		t.Errorf("expected event=error, got %v", entry["event"])
	}
	if entry["component"] != "pipelock" {
		t.Errorf("expected component=pipelock, got %v", entry["component"])
	}
	if entry["client_ip"] != "10.0.0.1" {
		t.Errorf("expected client_ip=10.0.0.1, got %v", entry["client_ip"])
	}
	if entry["request_id"] != "req-77" {
		t.Errorf("expected request_id=req-77, got %v", entry["request_id"])
	}
}

func TestNewNop_CloseIsSafe(t *testing.T) {
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
	if perm != 0600 {
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

	data, _ := os.ReadFile(path)
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

func TestLogRedirect_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogRedirect("https://example.com", "https://www.example.com", "10.0.0.1", "req-7", 1)
	logger.Close()

	data, _ := os.ReadFile(path)
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

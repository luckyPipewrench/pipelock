// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

const (
	testAirlockSession = "agent-a|10.0.0.1"
	testAirlockTier    = "soft"
	testAirlockTrigger = "adaptive"
	testTransport      = "fetch"
	testExampleURL     = "https://example.com"
)

func TestLogAirlockEnter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock_enter.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAirlockEnter(testAirlockSession, testAirlockTier, testAirlockTrigger, testClientIP, testReqID)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v\nraw: %s", err, data)
	}

	if entry["event"] != string(EventAirlockEnter) {
		t.Errorf("expected event=%s, got %v", EventAirlockEnter, entry["event"])
	}
	if entry["session"] != testAirlockSession {
		t.Errorf("expected session=%s, got %v", testAirlockSession, entry["session"])
	}
	if entry["tier"] != testAirlockTier {
		t.Errorf("expected tier=%s, got %v", testAirlockTier, entry["tier"])
	}
	if entry["trigger"] != testAirlockTrigger {
		t.Errorf("expected trigger=%s, got %v", testAirlockTrigger, entry["trigger"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=%s, got %v", testClientIP, entry["client_ip"])
	}
	if entry["request_id"] != testReqID {
		t.Errorf("expected request_id=%s, got %v", testReqID, entry["request_id"])
	}
}

func TestLogAirlockEnter_OptionalFieldsOmitted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock_enter_minimal.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAirlockEnter(testAirlockSession, testAirlockTier, testAirlockTrigger, "", "")
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	// optStr fields should be absent when empty.
	if _, ok := entry["client_ip"]; ok {
		t.Error("expected client_ip to be omitted when empty")
	}
	if _, ok := entry["request_id"]; ok {
		t.Error("expected request_id to be omitted when empty")
	}
}

func TestLogAirlockDeny(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock_deny.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAirlockDeny(testAirlockSession, "hard", testTransport, testMethodGet, testClientIP, testReqID)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventAirlockDeny) {
		t.Errorf("expected event=%s, got %v", EventAirlockDeny, entry["event"])
	}
	if entry["session"] != testAirlockSession {
		t.Errorf("expected session=%s, got %v", testAirlockSession, entry["session"])
	}
	if entry["tier"] != "hard" {
		t.Errorf("expected tier=hard, got %v", entry["tier"])
	}
	if entry["transport"] != testTransport {
		t.Errorf("expected transport=%s, got %v", testTransport, entry["transport"])
	}
	if entry["method"] != testMethodGet {
		t.Errorf("expected method=%s, got %v", testMethodGet, entry["method"])
	}
}

func TestLogAirlockDeescalate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock_deesc.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAirlockDeescalate(testAirlockSession, "hard", testAirlockTier, testClientIP, testReqID)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventAirlockDeescalate) {
		t.Errorf("expected event=%s, got %v", EventAirlockDeescalate, entry["event"])
	}
	if entry["session"] != testAirlockSession {
		t.Errorf("expected session=%s, got %v", testAirlockSession, entry["session"])
	}
	if entry["from"] != "hard" {
		t.Errorf("expected from=hard, got %v", entry["from"])
	}
	if entry["to"] != testAirlockTier {
		t.Errorf("expected to=%s, got %v", testAirlockTier, entry["to"])
	}
}

func TestLogShieldRewrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "shield_rewrite.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogShieldRewrite("extension_probing", 3, testTransport, testExampleURL, testClientIP, testReqID)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventShieldRewrite) {
		t.Errorf("expected event=%s, got %v", EventShieldRewrite, entry["event"])
	}
	if entry["category"] != "extension_probing" {
		t.Errorf("expected category=extension_probing, got %v", entry["category"])
	}
	// JSON numbers decode as float64.
	if hits, ok := entry["hits"].(float64); !ok || int(hits) != 3 {
		t.Errorf("expected hits=3, got %v", entry["hits"])
	}
	if entry["transport"] != testTransport {
		t.Errorf("expected transport=%s, got %v", testTransport, entry["transport"])
	}
	if entry["url"] != testExampleURL {
		t.Errorf("expected url=https://example.com, got %v", entry["url"])
	}
}

func TestLogSessionAdmin(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "session_admin.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogSessionAdmin("reset_ok", testClientIP, testAirlockSession, "success", http.StatusOK)
	logger.Close()

	data, _ := os.ReadFile(filepath.Clean(path))
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if entry["event"] != string(EventSessionAdmin) {
		t.Errorf("expected event=%s, got %v", EventSessionAdmin, entry["event"])
	}
	if entry["action"] != "reset_ok" {
		t.Errorf("expected action=reset_ok, got %v", entry["action"])
	}
	if entry["client_ip"] != testClientIP {
		t.Errorf("expected client_ip=%s, got %v", testClientIP, entry["client_ip"])
	}
	if entry["session_key"] != testAirlockSession {
		t.Errorf("expected session_key=%s, got %v", testAirlockSession, entry["session_key"])
	}
	if sc, ok := entry["status_code"].(float64); !ok || int(sc) != http.StatusOK {
		t.Errorf("expected status_code=200, got %v", entry["status_code"])
	}
}

func TestLogSessionAdmin_EmittedToSink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "session_admin_emit.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{}
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })

	logger.LogSessionAdmin("list", testClientIP, "", "ok", http.StatusOK)
	logger.Close()

	evt, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if evt.Type != string(EventSessionAdmin) {
		t.Errorf("expected emitted type=%s, got %s", EventSessionAdmin, evt.Type)
	}
}

func TestLogAirlockEnter_EmittedToSink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock_enter_emit.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{}
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })

	logger.LogAirlockEnter(testAirlockSession, testAirlockTier, testAirlockTrigger, testClientIP, testReqID)
	logger.Close()

	evt, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if evt.Type != string(EventAirlockEnter) {
		t.Errorf("expected emitted type=%s, got %s", EventAirlockEnter, evt.Type)
	}
}

func TestLogAirlockDeny_EmittedToSink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock_deny_emit.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{}
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })

	logger.LogAirlockDeny(testAirlockSession, "hard", testTransport, testMethodGet, testClientIP, testReqID)
	logger.Close()

	evt, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if evt.Type != string(EventAirlockDeny) {
		t.Errorf("expected emitted type=%s, got %s", EventAirlockDeny, evt.Type)
	}
}

func TestLogAirlockDeescalate_EmittedToSink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock_deesc_emit.log")

	logger, err := New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{}
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })

	logger.LogAirlockDeescalate(testAirlockSession, "hard", testAirlockTier, testClientIP, testReqID)
	logger.Close()

	evt, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected emitted event")
	}
	if evt.Type != string(EventAirlockDeescalate) {
		t.Errorf("expected emitted type=%s, got %s", EventAirlockDeescalate, evt.Type)
	}
}

func TestLogNop_AirlockMethods(t *testing.T) {
	t.Parallel()
	logger := NewNop()
	// All airlock log methods should not panic on nop logger.
	logger.LogAirlockEnter("sess", "soft", "adaptive", "10.0.0.1", "req-1")
	logger.LogAirlockDeny("sess", "hard", "fetch", "GET", "10.0.0.1", "req-2")
	logger.LogAirlockDeescalate("sess", "hard", "soft", "10.0.0.1", "req-3")
	logger.LogShieldRewrite("extension_probing", 2, "fetch", testExampleURL, "10.0.0.1", "req-4")
	logger.LogSessionAdmin("test", "10.0.0.1", "sess", "ok", http.StatusOK)
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode"
)

const sha256HexLength = 64

func TestSanitizeLogValueStripsLogControls(t *testing.T) {
	got := sanitizeLogValue("agent\r\n\t\x1b[31m\x7f\u0085\u2028\u2029Injected: forged log line")
	if containsUnsafeLogRune(got) {
		t.Fatalf("sanitizeLogValue left a log-control rune: %q", got)
	}
	if strings.Contains(got, "\x1b") || !strings.Contains(got, "[31m") {
		t.Fatalf("sanitizeLogValue = %q, want ANSI introducer neutralized and printable bytes preserved", got)
	}
}

func TestSanitizeLogValueStripsAllUnicodeControls(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.IsControl(r) && r != '\u2028' && r != '\u2029' {
			continue
		}
		got := sanitizeLogValue("safe" + string(r) + "tail")
		if got != "safe tail" {
			t.Fatalf("sanitizeLogValue(%U) = %q, want %q", r, got, "safe tail")
		}
	}
}

// sanitizeLogAttrs is the class-fix: every agent-influenced identifier logged
// through integrityLogAttrs (agent_key, declared_agent_key, profile names) must
// have log-control runes neutralized so it cannot forge or split a log line,
// while non-string values pass through unchanged, slog.Attr values are handled,
// literal keys are preserved, and the caller's slice is not mutated.
func TestSanitizeLogAttrsNeutralizesStringValues(t *testing.T) {
	in := []any{
		"agent_key\n", "evil\n\x1b[31mforged_admin=true",
		"generation", 7,
		slog.String("declared_agent_key", "a\rb\u2028"),
		slog.Any("error", errors.New("disk\nforged=true")),
		"dangling_key\n",
	}
	out := sanitizeLogAttrs(in)

	if out[0] != "agent_key\n" {
		t.Fatalf("attr key was mutated: got %q", out[0])
	}
	if got, ok := out[1].(string); !ok || containsUnsafeLogRune(got) {
		t.Fatalf("string attr value retained a log-control rune: %#v", out[1])
	}
	if out[3] != 7 {
		t.Fatalf("non-string attr value was mutated: got %v, want 7", out[3])
	}
	attr, ok := out[4].(slog.Attr)
	if !ok {
		t.Fatalf("slog.Attr value changed type: %T", out[4])
	}
	if attr.Key != "declared_agent_key" {
		t.Fatalf("slog.Attr key was mutated: %q", attr.Key)
	}
	if containsUnsafeLogRune(attr.Value.String()) {
		t.Fatalf("slog.Attr string value retained a log-control rune: %q", attr.Value.String())
	}
	errAttr, ok := out[5].(slog.Attr)
	if !ok {
		t.Fatalf("slog.Any error attr changed type: %T", out[5])
	}
	if got, ok := errAttr.Value.Any().(string); !ok || containsUnsafeLogRune(got) {
		t.Fatalf("slog.Any error attr retained a log-control rune: %#v", errAttr.Value.Any())
	}
	if out[6] != "dangling_key\n" {
		t.Fatalf("dangling key was mutated: got %q", out[6])
	}
	// The caller's original slice must be untouched (sanitizeLogAttrs copies).
	if in[1] != "evil\n\x1b[31mforged_admin=true" {
		t.Fatalf("sanitizeLogAttrs mutated the caller's input: %q", in[1])
	}
}

func TestIntegrityLogAttrsFingerprintsUserInfluencedDiagnostics(t *testing.T) {
	mgr := &Manager{cfg: Config{ProfileDir: "profiles\n", DeviationAction: deviationActionBlock}}
	err := fmt.Errorf("wrapping raw failure: %w", errors.New("disk\nforged=true\x1b[31m"))
	attrs := mgr.integrityLogAttrs("failure\nclass", err,
		"agent_key", "evil\ragent",
		"generation", uint64(7),
		slog.String("declared_agent_key", "declared\nagent"),
	)

	attrValues := map[string]any{}
	for i := 0; i < len(attrs)-1; i += 2 {
		key, ok := attrs[i].(string)
		if !ok {
			continue
		}
		attrValues[key] = attrs[i+1]
	}
	for _, key := range []string{"failure_class", "profile_dir"} {
		got, ok := attrValues[key].(string)
		if !ok {
			t.Fatalf("attr %q = %#v, want sanitized string", key, attrValues[key])
		}
		if containsUnsafeLogRune(got) {
			t.Fatalf("attr %q retained a log-control rune: %q", key, got)
		}
	}
	for _, key := range []string{"error", "agent_key", "declared_agent_key"} {
		if _, ok := attrValues[key]; ok {
			t.Fatalf("attr %q must not expose raw user-influenced text: %#v", key, attrValues[key])
		}
	}
	for _, key := range []string{"error_sha256", "agent_key_sha256", "declared_agent_key_sha256"} {
		got, ok := attrValues[key].(string)
		if !ok {
			t.Fatalf("attr %q = %#v, want string fingerprint", key, attrValues[key])
		}
		if len(got) != sha256HexLength || containsUnsafeLogRune(got) {
			t.Fatalf("attr %q is not a safe fingerprint: %q", key, got)
		}
	}
	if attrValues["generation"] != uint64(7) {
		t.Fatalf("generation attr = %#v, want 7", attrValues["generation"])
	}
}

func TestPendingProfileIntegrityNonEnforcingWarningUsesFingerprint(t *testing.T) {
	dir := t.TempDir()
	rawAgentKey := "evil\n\x1b[31mforged=true"
	mgr := &Manager{cfg: Config{
		ProfileDir:       dir,
		IntegrityKeyPath: filepath.Join(dir, "integrity.key"),
		DeviationAction:  deviationActionWarn,
	}}

	var handler captureLogHandler
	previous := slog.Default()
	slog.SetDefault(slog.New(&handler))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})

	if err := mgr.verifyPendingProfileIntegrityForRatify(rawAgentKey); err != nil {
		t.Fatalf("verifyPendingProfileIntegrityForRatify should continue under warn: %v", err)
	}

	for _, record := range handler.recordsSnapshot() {
		if record.message != "baseline pending profile integrity verification failed; continuing under non-enforcing deviation_action" {
			continue
		}
		if _, ok := record.attrs["agent_key"]; ok {
			t.Fatalf("warning logged raw agent_key attr: %#v", record.attrs["agent_key"])
		}
		if _, ok := record.attrs["error"]; ok {
			t.Fatalf("warning logged raw error attr: %#v", record.attrs["error"])
		}
		fingerprint, ok := record.attrs["agent_key_sha256"].(string)
		if !ok {
			t.Fatalf("agent_key_sha256 attr = %#v, want string", record.attrs["agent_key_sha256"])
		}
		if len(fingerprint) != sha256HexLength || strings.Contains(fingerprint, rawAgentKey) || containsUnsafeLogRune(fingerprint) {
			t.Fatalf("agent_key_sha256 is not a safe fingerprint: %q", fingerprint)
		}
		return
	}
	t.Fatal("did not capture non-enforcing pending-profile warning")
}

func TestBaselineWarningsSanitizeProfileNames(t *testing.T) {
	dir := t.TempDir()
	profileName := "evil\n\x1b[31m\u2028.json"
	if err := os.WriteFile(filepath.Join(dir, profileName), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt profile: %v", err)
	}

	var handler captureLogHandler
	previous := slog.Default()
	slog.SetDefault(slog.New(&handler))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})

	_, err := NewManager(Config{Enabled: true, ProfileDir: dir, DeviationAction: deviationActionWarn})
	if err != nil {
		t.Fatalf("NewManager should skip corrupt profile under warn: %v", err)
	}

	for _, record := range handler.recordsSnapshot() {
		if record.message != "skipping corrupt persisted baseline profile" {
			continue
		}
		profile, ok := record.attrs["profile"].(string)
		if !ok {
			t.Fatalf("profile attr = %#v, want string", record.attrs["profile"])
		}
		if containsUnsafeLogRune(profile) {
			t.Fatalf("profile attr retained a log-control rune: %q", profile)
		}
		return
	}
	t.Fatal("did not capture corrupt-profile warning")
}

type capturedLogRecord struct {
	message string
	attrs   map[string]any
}

type captureLogHandler struct {
	mu      sync.Mutex
	records []capturedLogRecord
}

func (h *captureLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *captureLogHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := map[string]any{}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, capturedLogRecord{message: record.Message, attrs: attrs})
	return nil
}

func (h *captureLogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *captureLogHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *captureLogHandler) recordsSnapshot() []capturedLogRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]capturedLogRecord, len(h.records))
	copy(out, h.records)
	return out
}

func containsUnsafeLogRune(s string) bool {
	if strings.ContainsAny(s, "\u2028\u2029") {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

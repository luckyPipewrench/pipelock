package chains

import (
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func intPtr(v int) *int { return &v }

func TestSubsequenceMatch(t *testing.T) {
	// Basic subsequence: [read, exec] should match in [read, exec]
	history := []toolCallRecord{
		{category: "read", name: "read_file"},    //nolint:goconst // test value
		{category: "exec", name: "bash_command"}, //nolint:goconst // test value
	}
	pat := pattern{
		name:     "read-then-exec", //nolint:goconst // test value
		sequence: []string{"read", "exec"},
		severity: "high", //nolint:goconst // test value
		action:   "warn", //nolint:goconst // test value
	}
	if !subsequenceMatch(history, pat.sequence, 3) {
		t.Error("expected subsequence match for [read, exec] in [read, exec]")
	}

	// With intervening calls: [read, list, exec] should match [read, exec] with max_gap=3
	history2 := []toolCallRecord{
		{category: "read", name: "read_file"},  //nolint:goconst // test value
		{category: "list", name: "list_files"}, //nolint:goconst // test value
		{category: "exec", name: "bash_exec"},  //nolint:goconst // test value
	}
	if !subsequenceMatch(history2, pat.sequence, 3) {
		t.Error("expected subsequence match for [read, exec] in [read, list, exec] with gap=3")
	}

	// Three-step pattern
	pat3 := pattern{
		name:     "read-write-send", //nolint:goconst // test value
		sequence: []string{"read", "write", "network"},
		severity: "critical", //nolint:goconst // test value
		action:   "warn",     //nolint:goconst // test value
	}
	history3 := []toolCallRecord{
		{category: "read", name: "read_file"},       //nolint:goconst // test value
		{category: "write", name: "write_file"},     //nolint:goconst // test value
		{category: "network", name: "send_request"}, //nolint:goconst // test value
	}
	if !subsequenceMatch(history3, pat3.sequence, 3) {
		t.Error("expected subsequence match for [read, write, network]")
	}
}

func TestSubsequenceMatch_MaxGap(t *testing.T) {
	// Gap of 1: [read, list, exec] should match [read, exec] with max_gap=1
	history := []toolCallRecord{
		{category: "read", name: "read_file"},
		{category: "list", name: "list_files"},
		{category: "exec", name: "bash_command"},
	}
	seq := []string{"read", "exec"}
	if !subsequenceMatch(history, seq, 1) {
		t.Error("expected match with gap=1")
	}

	// Gap of 2 (exceeds max_gap=1): should NOT match
	history2 := []toolCallRecord{
		{category: "read", name: "read_file"},
		{category: "list", name: "list_files"},
		{category: "list", name: "list_dirs"},
		{category: "exec", name: "bash_command"},
	}
	if subsequenceMatch(history2, seq, 1) {
		t.Error("should NOT match with gap=2 when max_gap=1")
	}

	// Gap of 0 (strict adjacency): only matches if consecutive
	if !subsequenceMatch([]toolCallRecord{
		{category: "read", name: "r"},
		{category: "exec", name: "e"},
	}, seq, 0) {
		t.Error("expected match with gap=0 for adjacent entries")
	}

	if subsequenceMatch([]toolCallRecord{
		{category: "read", name: "r"},
		{category: "list", name: "l"},
		{category: "exec", name: "e"},
	}, seq, 0) {
		t.Error("should NOT match with gap=1 when max_gap=0")
	}
}

func TestSubsequenceMatch_NoMatch(t *testing.T) {
	// Missing step
	history := []toolCallRecord{
		{category: "read", name: "read_file"},
		{category: "list", name: "list_files"},
	}
	seq := []string{"read", "exec"}
	if subsequenceMatch(history, seq, 10) {
		t.Error("should not match when step is missing")
	}

	// Wrong order
	history2 := []toolCallRecord{
		{category: "exec", name: "bash_exec"},
		{category: "read", name: "read_file"},
	}
	if subsequenceMatch(history2, seq, 10) {
		t.Error("should not match when steps are in wrong order")
	}

	// Empty history
	if subsequenceMatch(nil, seq, 10) {
		t.Error("should not match on empty history")
	}

	// Empty pattern
	if subsequenceMatch(history, nil, 10) {
		t.Error("should not match on empty pattern")
	}
}

func TestBuiltInPatterns(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn", //nolint:goconst // test value
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
	}

	m := NewMatcher(cfg)

	// Verify all 8 built-in patterns exist.
	expectedPatterns := map[string]struct{}{
		"read-then-exec":       {},
		"read-write-send":      {},
		"env-then-network":     {},
		"directory-scan":       {},
		"write-execute":        {},
		"write-chmod-execute":  {},
		"read-sensitive-write": {},
		"shell-burst":          {},
	}

	if len(m.patterns) < len(expectedPatterns) {
		t.Errorf("expected at least %d built-in patterns, got %d", len(expectedPatterns), len(m.patterns))
	}

	found := make(map[string]bool)
	for _, p := range m.patterns {
		found[p.name] = true
	}
	for name := range expectedPatterns {
		if !found[name] {
			t.Errorf("missing built-in pattern %q", name)
		}
	}
}

func TestMatcher_Record(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
	}
	m := NewMatcher(cfg)

	// Record a read followed by exec — should match "read-then-exec"
	v1 := m.Record("session1", "read_file") //nolint:goconst // test value
	if v1.Matched {
		t.Error("single read should not match any pattern")
	}

	v2 := m.Record("session1", "bash_command") //nolint:goconst // test value
	if !v2.Matched {
		t.Error("read + exec should match read-then-exec pattern")
	}
	if v2.PatternName != "read-then-exec" {
		t.Errorf("expected pattern read-then-exec, got %q", v2.PatternName)
	}
	if v2.Severity != "high" {
		t.Errorf("expected severity high, got %q", v2.Severity)
	}
	if v2.Action != "warn" {
		t.Errorf("expected action warn, got %q", v2.Action)
	}
}

func TestMatcher_WindowEviction(t *testing.T) {
	// Test count-based eviction
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    3, // Very small window
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
	}
	m := NewMatcher(cfg)

	// Fill window with reads, then overflow
	m.Record("s1", "read_file")
	m.Record("s1", "list_files")
	m.Record("s1", "list_dirs")
	// Window is now full (3 entries). Next entry should evict oldest.
	m.Record("s1", "run_command") //nolint:goconst // test value

	// The read_file should have been evicted. So read-then-exec should NOT match
	// because the read is gone.
	_ = m.Record("s1", "bash_exec")
	// However, run_command (exec) and bash_exec (exec) are both exec.
	// Check that the original read is gone by checking history size.
	sh, ok := m.sessions.Load("s1")
	if !ok {
		t.Fatal("session not found")
	}
	sess := sh.(*sessionHistory)
	sess.mu.Lock()
	count := len(sess.records)
	sess.mu.Unlock()
	if count > 3 {
		t.Errorf("expected at most %d records, got %d", 3, count)
	}

	// Test time-based eviction
	cfg2 := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    100,
		WindowSeconds: 1, // 1 second window
		MaxGap:        intPtr(3),
	}
	m2 := NewMatcher(cfg2)

	m2.Record("s2", "read_file")
	time.Sleep(1100 * time.Millisecond) // Wait for window to expire

	// The read should be evicted. New exec should not match read-then-exec.
	v := m2.Record("s2", "bash_command")
	if v.Matched && v.PatternName == "read-then-exec" {
		t.Error("stale read should have been evicted by time window")
	}
	_ = v
}

func TestMatcher_CustomPatterns(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(5),
		CustomPatterns: []config.ChainPattern{
			{
				Name:     "custom-read-list-write",
				Sequence: []string{"read", "list", "write"},
				Severity: "critical", // critical so it beats built-in "read-sensitive-write" (medium)
			},
		},
	}
	m := NewMatcher(cfg)

	m.Record("s1", "read_file")
	m.Record("s1", "list_files")
	v := m.Record("s1", "write_file")

	if !v.Matched {
		t.Error("expected custom pattern to match")
	}
	// The built-in "read-sensitive-write" (medium) also matches, but custom
	// pattern has critical severity, so it wins.
	if v.PatternName != "custom-read-list-write" {
		t.Errorf("expected custom-read-list-write, got %q", v.PatternName)
	}
	if v.Severity != "critical" {
		t.Errorf("expected severity critical, got %q", v.Severity)
	}
}

func TestMatcher_PatternOverrides(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
		PatternOverrides: map[string]string{
			"read-then-exec": "block", //nolint:goconst // test value
		},
	}
	m := NewMatcher(cfg)

	m.Record("s1", "read_file")
	v := m.Record("s1", "bash_command")

	if !v.Matched {
		t.Error("expected match")
	}
	if v.Action != "block" { //nolint:goconst // test value
		t.Errorf("expected action block from pattern override, got %q", v.Action)
	}
}

func TestMatcher_HighestSeverity(t *testing.T) {
	// Create a scenario where multiple patterns match simultaneously.
	// read-write-send (critical) and read-sensitive-write (medium)
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(5),
	}
	m := NewMatcher(cfg)

	m.Record("s1", "read_file")
	m.Record("s1", "write_file")
	v := m.Record("s1", "send_request")

	if !v.Matched {
		t.Error("expected match")
	}
	// read-write-send is critical, read-sensitive-write is medium.
	// Should return the highest severity.
	if v.Severity != "critical" {
		t.Errorf("expected critical severity (highest), got %q", v.Severity)
	}
}

func TestMatcher_UnknownCategory(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
	}
	m := NewMatcher(cfg)

	// Unknown tools should not be recorded
	v := m.Record("s1", "foobar_baz")
	if v.Matched {
		t.Error("unknown tool should not match")
	}

	// Verify it wasn't recorded in the session
	sh, ok := m.sessions.Load("s1")
	if ok {
		sess := sh.(*sessionHistory)
		sess.mu.Lock()
		count := len(sess.records)
		sess.mu.Unlock()
		if count != 0 {
			t.Errorf("unknown tool should not be recorded, got %d records", count)
		}
	}
	// ok=false is also acceptable (no session created yet)
}

func TestMatcher_Concurrent(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    100,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
	}
	m := NewMatcher(cfg)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			session := "session-concurrent" //nolint:goconst // test value
			m.Record(session, "read_file")
			m.Record(session, "bash_command")
			m.Record(session, "list_files")
			m.Record(session, "write_file")
			m.Record(session, "send_request")
		}(i)
	}
	wg.Wait()

	// Just verify no panics/races occurred. The -race flag will catch data races.
}

func TestMatcher_SessionIsolation(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
	}
	m := NewMatcher(cfg)

	// Session A: record read
	m.Record("sessionA", "read_file")

	// Session B: record exec — should NOT match read-then-exec because
	// the read was in a different session.
	v := m.Record("sessionB", "bash_command")
	if v.Matched {
		t.Error("sessions should be isolated: exec in sessionB should not see read from sessionA")
	}

	// Session A: record exec — SHOULD match because both are in sessionA
	v2 := m.Record("sessionA", "bash_command")
	if !v2.Matched {
		t.Error("read + exec in same session should match")
	}
}

func TestMatcher_NilSafe(t *testing.T) {
	// Disabled config should create a no-op matcher
	cfg := &config.ToolChainDetection{
		Enabled: false,
	}
	m := NewMatcher(cfg)

	v := m.Record("s1", "read_file")
	if v.Matched {
		t.Error("disabled matcher should never match")
	}
}

func TestMatcher_CustomPatternAction(t *testing.T) {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
		CustomPatterns: []config.ChainPattern{
			{
				Name:     "custom-block-pattern",
				Sequence: []string{"env", "network"},
				Severity: "critical",
				Action:   "block",
			},
		},
	}
	m := NewMatcher(cfg)

	m.Record("s1", "env_get")
	v := m.Record("s1", "fetch_url")

	if !v.Matched {
		t.Error("expected match")
	}
	// Both custom and built-in "env-then-network" match. The custom has
	// action=block, the built-in has action=warn. Block should win.
	if v.Action != "block" {
		t.Errorf("expected block (strictest action), got %q", v.Action)
	}
}

func TestMatcher_MaxGapRetry(t *testing.T) {
	// Test that when the first occurrence of step[0] fails due to gap,
	// the matcher tries the next occurrence of step[0].
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(1),
	}
	m := NewMatcher(cfg)

	// First read, then too many gaps before exec
	m.Record("s1", "read_file")    // read at pos 0
	m.Record("s1", "list_files")   // gap 1
	m.Record("s1", "list_files")   // gap 2 — too many
	m.Record("s1", "read_file")    // read at pos 3 — retry start
	m.Record("s1", "bash_command") // exec at pos 4 — gap 0 from pos 3

	// Should match starting from the second read
	sh, _ := m.sessions.Load("s1")
	sess := sh.(*sessionHistory)
	sess.mu.Lock()
	matched := subsequenceMatch(sess.records, []string{"read", "exec"}, 1)
	sess.mu.Unlock()
	if !matched {
		t.Error("should match using second occurrence of step[0]")
	}
}

func TestMatcher_NilConfig(t *testing.T) {
	// nil config should produce a no-op matcher (not panic).
	m := NewMatcher(nil)
	v := m.Record("s1", "read_file")
	if v.Matched {
		t.Error("nil config matcher should never match")
	}
}

func TestMatcher_WithMetrics(t *testing.T) {
	var recorded []string
	recorder := &stubMetrics{recordFn: func(p, s, a string) {
		recorded = append(recorded, p+":"+s+":"+a)
	}}

	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
	}
	m := NewMatcher(cfg).WithMetrics(recorder)

	m.Record("s1", "read_file")
	m.Record("s1", "bash_command")

	if len(recorded) == 0 {
		t.Fatal("expected metrics recording on chain match")
	}
	if recorded[0] != "read-then-exec:high:warn" {
		t.Errorf("unexpected metric: %s", recorded[0])
	}
}

type stubMetrics struct {
	recordFn func(pattern, severity, action string)
}

func (s *stubMetrics) RecordChainDetection(pattern, severity, action string) {
	s.recordFn(pattern, severity, action)
}

func TestMatcher_CustomPatternOverride(t *testing.T) {
	// Custom pattern with PatternOverrides should use the override action.
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		Action:        "warn",
		WindowSize:    20,
		WindowSeconds: 60,
		MaxGap:        intPtr(3),
		CustomPatterns: []config.ChainPattern{
			{
				Name:     "my-custom",
				Sequence: []string{"read", "write"},
				Severity: "medium",
				Action:   "warn",
			},
		},
		PatternOverrides: map[string]string{
			"my-custom": "block",
		},
	}
	m := NewMatcher(cfg)

	m.Record("s1", "read_file")
	v := m.Record("s1", "write_file")

	if !v.Matched {
		t.Fatal("expected match")
	}
	if v.Action != "block" {
		t.Errorf("expected override action %q, got %q", "block", v.Action)
	}
}

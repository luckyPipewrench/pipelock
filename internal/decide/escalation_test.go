// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// ptrStr returns a pointer to s. Used to build EscalationActions in tests.
func ptrStr(s string) *string { return &s }

// ptrBool returns a pointer to b. Used to build EscalationActions in tests.
func ptrBool(b bool) *bool { return &b }

// defaultAdaptiveConfig returns an AdaptiveEnforcement with defaults applied:
//   - Elevated: upgrade_warn=block
//   - High:     upgrade_warn=block, upgrade_ask=block
//   - Critical: upgrade_warn=block, upgrade_ask=block, block_all=true
func defaultAdaptiveConfig() *config.AdaptiveEnforcement {
	return &config.AdaptiveEnforcement{
		Enabled:              true,
		EscalationThreshold:  5.0,
		DecayPerCleanRequest: 0.5,
		Levels: config.EscalationLevels{
			Elevated: config.EscalationActions{
				UpgradeWarn: ptrStr(config.ActionBlock),
				UpgradeAsk:  nil, // no upgrade at elevated
				BlockAll:    nil, // no block_all at elevated
			},
			High: config.EscalationActions{
				UpgradeWarn: ptrStr(config.ActionBlock),
				UpgradeAsk:  ptrStr(config.ActionBlock),
				BlockAll:    nil, // no block_all at high
			},
			Critical: config.EscalationActions{
				UpgradeWarn: ptrStr(config.ActionBlock),
				UpgradeAsk:  ptrStr(config.ActionBlock),
				BlockAll:    ptrBool(true),
			},
		},
	}
}

// TestUpgradeAction_FullTable covers all 20 cells in the action×level matrix
// using the default post-ApplyDefaults config.
func TestUpgradeAction_FullTable(t *testing.T) {
	cfg := defaultAdaptiveConfig()

	const (
		actionClean = ""
		levelNormal = 0
		levelElev   = 1
		levelHigh   = 2
		levelCrit   = 3
	)

	tests := []struct {
		name       string
		baseAction string
		level      int
		want       string
	}{
		// Level 0 — never changed
		{"clean/level0", actionClean, levelNormal, actionClean},
		{"strip/level0", config.ActionStrip, levelNormal, config.ActionStrip},
		{"warn/level0", config.ActionWarn, levelNormal, config.ActionWarn},
		{"ask/level0", config.ActionAsk, levelNormal, config.ActionAsk},
		{"block/level0", config.ActionBlock, levelNormal, config.ActionBlock},

		// Level 1 (elevated): upgrade_warn=block, upgrade_ask=nil (no upgrade), no block_all
		{"clean/level1", actionClean, levelElev, actionClean},
		{"strip/level1", config.ActionStrip, levelElev, config.ActionStrip},
		{"warn/level1", config.ActionWarn, levelElev, config.ActionBlock},
		{"ask/level1", config.ActionAsk, levelElev, config.ActionAsk},
		{"block/level1", config.ActionBlock, levelElev, config.ActionBlock},

		// Level 2 (high): upgrade_warn=block, upgrade_ask=block, no block_all
		{"clean/level2", actionClean, levelHigh, actionClean},
		{"strip/level2", config.ActionStrip, levelHigh, config.ActionStrip},
		{"warn/level2", config.ActionWarn, levelHigh, config.ActionBlock},
		{"ask/level2", config.ActionAsk, levelHigh, config.ActionBlock},
		{"block/level2", config.ActionBlock, levelHigh, config.ActionBlock},

		// Level 3+ (critical): block_all=true → everything becomes block
		{"clean/level3", actionClean, levelCrit, config.ActionBlock},
		{"strip/level3", config.ActionStrip, levelCrit, config.ActionBlock},
		{"warn/level3", config.ActionWarn, levelCrit, config.ActionBlock},
		{"ask/level3", config.ActionAsk, levelCrit, config.ActionBlock},
		{"block/level3", config.ActionBlock, levelCrit, config.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UpgradeAction(tt.baseAction, tt.level, cfg)
			if got != tt.want {
				t.Errorf("UpgradeAction(%q, %d) = %q, want %q", tt.baseAction, tt.level, got, tt.want)
			}
		})
	}
}

// TestUpgradeAction_Level0NeverChanges verifies the level-0 identity property
// with a broader set of inputs including unknown actions.
func TestUpgradeAction_Level0NeverChanges(t *testing.T) {
	cfg := defaultAdaptiveConfig()
	actions := []string{"", config.ActionStrip, config.ActionWarn, config.ActionAsk, config.ActionBlock, "forward", "allow", "unknown"}

	for _, action := range actions {
		t.Run("action="+action, func(t *testing.T) {
			got := UpgradeAction(action, 0, cfg)
			if got != action {
				t.Errorf("UpgradeAction(%q, 0) = %q, want unchanged %q", action, got, action)
			}
		})
	}
}

// TestUpgradeAction_NilConfig verifies that a nil cfg returns baseAction unchanged.
func TestUpgradeAction_NilConfig(t *testing.T) {
	actions := []string{"", config.ActionStrip, config.ActionWarn, config.ActionAsk, config.ActionBlock}
	for _, action := range actions {
		t.Run("action="+action, func(t *testing.T) {
			got := UpgradeAction(action, 3, nil)
			if got != action {
				t.Errorf("UpgradeAction(%q, 3, nil) = %q, want %q", action, got, action)
			}
		})
	}
}

// TestUpgradeAction_DisabledConfig verifies that enabled=false returns baseAction unchanged.
func TestUpgradeAction_DisabledConfig(t *testing.T) {
	cfg := defaultAdaptiveConfig()
	cfg.Enabled = false
	actions := []string{"", config.ActionStrip, config.ActionWarn, config.ActionAsk, config.ActionBlock}
	for _, action := range actions {
		t.Run("action="+action, func(t *testing.T) {
			got := UpgradeAction(action, 3, cfg)
			if got != action {
				t.Errorf("UpgradeAction(%q, 3, disabled) = %q, want %q", action, got, action)
			}
		})
	}
}

// TestUpgradeAction_Monotonic proves the monotonic guarantee:
// UpgradeAction(action, N+1, cfg) is always >= UpgradeAction(action, N, cfg)
// where block > ask > warn > strip > "" in enforcement strength.
func TestUpgradeAction_Monotonic(t *testing.T) {
	cfg := defaultAdaptiveConfig()

	// actionRank maps actions to enforcement strength (higher = stricter).
	actionRank := map[string]int{
		"":                 0,
		config.ActionStrip: 1,
		config.ActionWarn:  2,
		config.ActionAsk:   3,
		config.ActionBlock: 4,
	}

	actions := []string{"", config.ActionStrip, config.ActionWarn, config.ActionAsk, config.ActionBlock}
	levels := []int{0, 1, 2, 3, 4} // level 4 should behave same as 3 (3+ = critical)

	for _, action := range actions {
		for i := 0; i < len(levels)-1; i++ {
			levelN := levels[i]
			levelN1 := levels[i+1]
			t.Run("action="+action+"/levels="+itoa(levelN)+"-"+itoa(levelN1), func(t *testing.T) {
				resultN := UpgradeAction(action, levelN, cfg)
				resultN1 := UpgradeAction(action, levelN1, cfg)

				rankN := actionRank[resultN]
				rankN1 := actionRank[resultN1]

				if rankN1 < rankN {
					t.Errorf("monotonic violation: UpgradeAction(%q, %d) = %q (rank %d) > UpgradeAction(%q, %d) = %q (rank %d)",
						action, levelN, resultN, rankN,
						action, levelN1, resultN1, rankN1)
				}
			})
		}
	}
}

// itoa converts an int to string for use in subtest names without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

// TestUpgradeAction_CustomConfig_ElevatedAskUpgrade tests an unusual but legal
// config where elevated has upgrade_ask=block (stricter than the default).
func TestUpgradeAction_CustomConfig_ElevatedAskUpgrade(t *testing.T) {
	cfg := defaultAdaptiveConfig()
	cfg.Levels.Elevated.UpgradeAsk = ptrStr(config.ActionBlock) // non-default: upgrade ask at elevated

	got := UpgradeAction(config.ActionAsk, 1, cfg)
	if got != config.ActionBlock {
		t.Errorf("UpgradeAction(ask, 1, elevated.upgrade_ask=block) = %q, want %q", got, config.ActionBlock)
	}

	// warn still upgrades at elevated
	got = UpgradeAction(config.ActionWarn, 1, cfg)
	if got != config.ActionBlock {
		t.Errorf("UpgradeAction(warn, 1, elevated.upgrade_warn=block) = %q, want %q", got, config.ActionBlock)
	}
}

// TestUpgradeAction_SoftenedConfig_ElevatedNoWarnUpgrade tests that an operator
// who explicitly sets upgrade_warn="" at elevated (no upgrade) is respected.
func TestUpgradeAction_SoftenedConfig_ElevatedNoWarnUpgrade(t *testing.T) {
	cfg := defaultAdaptiveConfig()
	noUpgrade := ""
	cfg.Levels.Elevated.UpgradeWarn = &noUpgrade // explicit empty = no upgrade

	got := UpgradeAction(config.ActionWarn, 1, cfg)
	if got != config.ActionWarn {
		t.Errorf("UpgradeAction(warn, 1, elevated.upgrade_warn=\"\") = %q, want warn (no upgrade)", got)
	}
}

// TestUpgradeAction_BlockAllAtCritical verifies that block_all=true at critical
// overrides even clean and strip base actions.
func TestUpgradeAction_BlockAllAtCritical(t *testing.T) {
	cfg := defaultAdaptiveConfig()
	// Critical.BlockAll is already true in default; make it explicit in this test.
	cfg.Levels.Critical.BlockAll = ptrBool(true)

	tests := []struct {
		baseAction string
	}{
		{""},
		{config.ActionStrip},
		{config.ActionWarn},
		{config.ActionAsk},
		{config.ActionBlock},
	}

	for _, tt := range tests {
		t.Run("base="+tt.baseAction, func(t *testing.T) {
			got := UpgradeAction(tt.baseAction, 3, cfg)
			if got != config.ActionBlock {
				t.Errorf("UpgradeAction(%q, 3, block_all=true) = %q, want block", tt.baseAction, got)
			}
		})
	}
}

// TestUpgradeAction_Level3Plus verifies that levels >= 3 all map to critical behavior.
func TestUpgradeAction_Level3Plus(t *testing.T) {
	cfg := defaultAdaptiveConfig()

	for _, level := range []int{3, 4, 5, 100} {
		t.Run("level="+itoa(level), func(t *testing.T) {
			got := UpgradeAction(config.ActionWarn, level, cfg)
			if got != config.ActionBlock {
				t.Errorf("UpgradeAction(warn, %d) = %q, want block (all >= 3 map to critical)", level, got)
			}
		})
	}
}

// TestUpgradeAction_NilPointerFields verifies defensive nil handling:
// nil UpgradeWarn/UpgradeAsk/BlockAll fields are treated as "no upgrade".
func TestUpgradeAction_NilPointerFields(t *testing.T) {
	cfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Elevated: config.EscalationActions{
				UpgradeWarn: nil, // nil = no upgrade (defensive)
				UpgradeAsk:  nil,
				BlockAll:    nil,
			},
			High: config.EscalationActions{
				UpgradeWarn: nil,
				UpgradeAsk:  nil,
				BlockAll:    nil,
			},
			Critical: config.EscalationActions{
				UpgradeWarn: nil,
				UpgradeAsk:  nil,
				BlockAll:    nil, // nil block_all = no session deny
			},
		},
	}

	tests := []struct {
		baseAction string
		level      int
	}{
		{config.ActionWarn, 1},
		{config.ActionWarn, 2},
		{config.ActionWarn, 3},
		{config.ActionAsk, 1},
		{config.ActionAsk, 2},
		{config.ActionAsk, 3},
		{"", 3},
		{config.ActionStrip, 3},
	}

	for _, tt := range tests {
		t.Run("action="+tt.baseAction+"/level="+itoa(tt.level), func(t *testing.T) {
			got := UpgradeAction(tt.baseAction, tt.level, cfg)
			if got != tt.baseAction {
				t.Errorf("UpgradeAction(%q, %d, all-nil) = %q, want unchanged %q",
					tt.baseAction, tt.level, got, tt.baseAction)
			}
		})
	}
}

// TestUpgradeAction_NegativeLevel verifies that a negative level is treated as
// normal (no upgrade) and must never fall through to the critical default case.
// A negative level is invalid state; treat it as level 0 (no escalation).
func TestUpgradeAction_NegativeLevel(t *testing.T) {
	cfg := defaultAdaptiveConfig()
	// Level -1 must return baseAction unchanged, not critical block_all.
	if got := UpgradeAction(config.ActionWarn, -1, cfg); got != config.ActionWarn {
		t.Errorf("UpgradeAction(warn, -1) = %q, want warn (negative level treated as normal)", got)
	}
	// Verify that level 0 is also unchanged (regression guard).
	if got := UpgradeAction(config.ActionWarn, 0, cfg); got != config.ActionWarn {
		t.Errorf("UpgradeAction(warn, 0) = %q, want warn", got)
	}
}

// ---------------------------------------------------------------------------
// RecordEscalation tests
// ---------------------------------------------------------------------------

// escalationRecorder is a mock session.Recorder for testing RecordEscalation.
// It lets tests control whether RecordSignal returns an escalation transition.
type escalationRecorder struct {
	signals   []session.SignalType
	score     float64
	escalate  bool   // when true, RecordSignal returns an escalation
	fromLabel string // "from" label returned on escalation
	toLabel   string // "to" label returned on escalation
}

func (r *escalationRecorder) RecordSignal(sig session.SignalType, _ float64) (bool, string, string) {
	r.signals = append(r.signals, sig)
	if r.escalate {
		return true, r.fromLabel, r.toLabel
	}
	return false, "", ""
}

func (r *escalationRecorder) RecordClean(_ float64) {}
func (r *escalationRecorder) EscalationLevel() int  { return 0 }
func (r *escalationRecorder) ThreatScore() float64  { return r.score }

// testLogger creates an audit logger writing to a temp file. Returns the
// logger and the log file path for post-test verification.
func testLogger(t *testing.T) (*audit.Logger, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.New("json", "file", logPath, true, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	return logger, logPath
}

func TestRecordEscalation_NoEscalation(t *testing.T) {
	rec := &escalationRecorder{escalate: false}
	logger, logPath := testLogger(t)
	m := metrics.New()
	params := EscalationParams{
		Threshold: 5.0,
		Logger:    logger,
		Metrics:   m,
		Session:   "agent|127.0.0.1",
		ClientIP:  "127.0.0.1",
		RequestID: "req-1",
	}

	got := RecordEscalation(rec, session.SignalBlock, params)
	if got {
		t.Error("RecordEscalation returned true, want false (no escalation)")
	}
	if len(rec.signals) != 1 || rec.signals[0] != session.SignalBlock {
		t.Errorf("signal not recorded: got %v", rec.signals)
	}
	// Logger should not have been called — log file should be empty.
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	if len(data) > 0 {
		t.Errorf("expected empty log file, got %d bytes", len(data))
	}
}

func TestRecordEscalation_Escalation(t *testing.T) {
	rec := &escalationRecorder{
		escalate:  true,
		fromLabel: session.EscalationLabel(0),
		toLabel:   session.EscalationLabel(1),
		score:     6.0,
	}
	logger, logPath := testLogger(t)
	m := metrics.New()
	params := EscalationParams{
		Threshold: 5.0,
		Logger:    logger,
		Metrics:   m,
		Session:   "agent|10.0.0.1",
		ClientIP:  "10.0.0.1",
		RequestID: "req-2",
	}

	got := RecordEscalation(rec, session.SignalBlock, params)
	if !got {
		t.Error("RecordEscalation returned false, want true (escalation occurred)")
	}
	// Audit log should have an entry.
	logger.Close()
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected audit log entry for escalation, got empty file")
	}
}

func TestRecordEscalation_NilLogger(t *testing.T) {
	rec := &escalationRecorder{
		escalate:  true,
		fromLabel: session.EscalationLabel(0),
		toLabel:   session.EscalationLabel(1),
		score:     6.0,
	}
	m := metrics.New()
	params := EscalationParams{
		Threshold: 5.0,
		Logger:    nil,
		Metrics:   m,
		Session:   "key",
		ClientIP:  "127.0.0.1",
		RequestID: "req-3",
	}

	// Must not panic.
	got := RecordEscalation(rec, session.SignalNearMiss, params)
	if !got {
		t.Error("RecordEscalation returned false, want true")
	}
}

func TestRecordEscalation_NilMetrics(t *testing.T) {
	rec := &escalationRecorder{
		escalate:  true,
		fromLabel: session.EscalationLabel(0),
		toLabel:   session.EscalationLabel(1),
		score:     6.0,
	}
	params := EscalationParams{
		Threshold: 5.0,
		Logger:    nil,
		Metrics:   nil,
		Session:   "key",
		ClientIP:  "127.0.0.1",
		RequestID: "req-4",
	}

	// Must not panic with both logger and metrics nil.
	got := RecordEscalation(rec, session.SignalStrip, params)
	if !got {
		t.Error("RecordEscalation returned false, want true")
	}
}

func TestRecordEscalation_FromLevel0_NoGaugeDecrement(t *testing.T) {
	// When escalating FROM level 0 ("normal"), the old level gauge should
	// NOT be decremented — there's nothing to decrement.
	rec := &escalationRecorder{
		escalate:  true,
		fromLabel: session.EscalationLabel(0), // "normal"
		toLabel:   session.EscalationLabel(1), // "elevated"
		score:     6.0,
	}
	m := metrics.New()
	params := EscalationParams{
		Threshold: 5.0,
		Logger:    nil,
		Metrics:   m,
		Session:   "key",
		ClientIP:  "127.0.0.1",
		RequestID: "req-5",
	}

	// Exercises the from != EscalationLabel(0) branch — should skip decrement.
	// No panic and correct return is sufficient (gauge internals verified by
	// metrics package tests).
	got := RecordEscalation(rec, session.SignalBlock, params)
	if !got {
		t.Error("RecordEscalation returned false, want true")
	}
}

func TestRecordEscalation_FromNonZero_GaugeDecrement(t *testing.T) {
	// When escalating FROM a non-zero level (e.g. elevated → high), the old
	// level gauge IS decremented.
	rec := &escalationRecorder{
		escalate:  true,
		fromLabel: session.EscalationLabel(1), // "elevated"
		toLabel:   session.EscalationLabel(2), // "high"
		score:     12.0,
	}
	m := metrics.New()
	params := EscalationParams{
		Threshold: 5.0,
		Logger:    nil,
		Metrics:   m,
		Session:   "key",
		ClientIP:  "127.0.0.1",
		RequestID: "req-6",
	}

	got := RecordEscalation(rec, session.SignalBlock, params)
	if !got {
		t.Error("RecordEscalation returned false, want true")
	}
}

func TestRecordEscalation_ConsoleWriter(t *testing.T) {
	rec := &escalationRecorder{
		escalate:  true,
		fromLabel: session.EscalationLabel(0),
		toLabel:   session.EscalationLabel(1),
		score:     7.5,
	}
	var buf bytes.Buffer
	params := EscalationParams{
		Threshold:     5.0,
		ConsoleWriter: &buf,
		Session:       "key",
		ClientIP:      "127.0.0.1",
		RequestID:     "req-7",
	}

	got := RecordEscalation(rec, session.SignalBlock, params)
	if !got {
		t.Error("RecordEscalation returned false, want true")
	}
	output := buf.String()
	if !strings.Contains(output, "session escalated") {
		t.Errorf("console output missing escalation message, got %q", output)
	}
	if !strings.Contains(output, "7.5") {
		t.Errorf("console output missing score, got %q", output)
	}
}

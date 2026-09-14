// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestSessionManagerWarnsForUnproduciblePersistedBaselineProfiles(t *testing.T) {
	profileDir := t.TempDir()
	baselineCfg := &config.BehavioralBaseline{
		Enabled:          true,
		LearningWindow:   1,
		DeviationAction:  config.ActionBlock,
		ProfileDir:       profileDir,
		AutoRatify:       true,
		SensitivitySigma: 2,
		SeasonalityMode:  config.SeasonalityModeNone,
	}

	seed := NewSessionManager(testSessionConfig(), nil, nil)
	if err := seed.EnableBaseline(baselineCfg); err != nil {
		t.Fatalf("seed EnableBaseline: %v", err)
	}
	seedSession := seed.GetOrCreate("legacy-agent|192.0.2.1")
	seedSession.RecordRequest("steady.example", testSessionConfig())
	seed.RecordBaselineForAgent("legacy-agent", seedSession)
	seed.Close()

	var output bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", false, true, &output)
	if err != nil {
		t.Fatalf("NewWithStream: %v", err)
	}
	t.Cleanup(logger.Close)
	current := NewSessionManager(testSessionConfig(), nil, nil, SessionManagerOptions{Logger: logger})
	t.Cleanup(current.Close)
	if err := current.EnableBaseline(baselineCfg); err != nil {
		t.Fatalf("startup EnableBaseline: %v", err)
	}
	current.WarnUnproducibleBaselineProfiles(nil)
	if got := strings.Count(output.String(), "legacy-agent"); got != 1 {
		t.Fatalf("startup warning count = %d, want 1; logs=%s", got, output.String())
	}

	if err := current.ReconfigureBaseline(baselineCfg); err != nil {
		t.Fatalf("reload ReconfigureBaseline: %v", err)
	}
	current.WarnUnproducibleBaselineProfiles(nil)
	if got := strings.Count(output.String(), "legacy-agent"); got != 2 {
		t.Fatalf("reload warning count = %d, want 2; logs=%s", got, output.String())
	}

	if err := current.ReconfigureBaseline(baselineCfg); err != nil {
		t.Fatalf("clean reload ReconfigureBaseline: %v", err)
	}
	current.WarnUnproducibleBaselineProfiles(map[string]struct{}{"legacy-agent": {}})
	if got := strings.Count(output.String(), "legacy-agent"); got != 2 {
		t.Fatalf("reload without unreachable profile emitted warning; count=%d logs=%s", got, output.String())
	}
}

func TestIPv6FoldedBaselineCheckDoesNotFailClosedOnKeyValidation(t *testing.T) {
	sm := NewSessionManager(testSessionConfig(), nil, nil)
	t.Cleanup(sm.Close)
	if err := sm.EnableBaseline(testBaselineBlockConfig(t)); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}
	key := baselineAgentKeyForSessionKey("2001:db8::1")
	sess := sm.GetOrCreate("2001:db8::1")
	sess.RecordRequest("steady.example", testSessionConfig())
	if result := sm.CheckBaselineFailClosed(key, sess); result != nil {
		t.Fatalf("IPv6 folded baseline key failed closed: %+v", result)
	}
}

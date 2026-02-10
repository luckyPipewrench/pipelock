package projectscan

import "testing"

func TestComputeScore_Nil(t *testing.T) {
	if got := computeScore(nil); got != 0 {
		t.Errorf("computeScore(nil) = %d, want 0", got)
	}
}

func TestComputeScore_GenericNoGit(t *testing.T) {
	cfg := &SuggestCfg{
		Preset:     AgentGeneric,
		GitEnabled: false,
	}
	score := computeScore(cfg)
	// Should get everything except git (5) and MCP (10)
	// 20+15+15+10+10+10+5 = 85
	if score != 85 {
		t.Errorf("computeScore(generic, no git) = %d, want 85", score)
	}
}

func TestComputeScore_GenericWithGit(t *testing.T) {
	cfg := &SuggestCfg{
		Preset:     AgentGeneric,
		GitEnabled: true,
	}
	score := computeScore(cfg)
	// 85 + 5 (git) = 90
	if score != 90 {
		t.Errorf("computeScore(generic, git) = %d, want 90", score)
	}
}

func TestComputeScore_ClaudeCode(t *testing.T) {
	cfg := &SuggestCfg{
		Preset:     AgentClaudeCode,
		GitEnabled: true,
	}
	score := computeScore(cfg)
	// 90 + 10 (MCP) = 100
	if score != 100 {
		t.Errorf("computeScore(claude-code, git) = %d, want 100", score)
	}
}

func TestComputeScore_CursorWithGit(t *testing.T) {
	cfg := &SuggestCfg{
		Preset:     AgentCursor,
		GitEnabled: true,
	}
	score := computeScore(cfg)
	// 90 + 10 (MCP for cursor) = 100
	if score != 100 {
		t.Errorf("computeScore(cursor, git) = %d, want 100", score)
	}
}

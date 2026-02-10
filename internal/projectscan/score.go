package projectscan

// computeScore calculates a security score from 0-100.
// nil config means "unprotected" (no pipelock at all).
func computeScore(cfg *SuggestCfg) int {
	if cfg == nil {
		return 0
	}

	score := 0

	// DLP patterns cover found secrets (+20)
	score += 20

	// Env leak scanning enabled (+15)
	score += 15

	// Response scanning enabled (+15)
	score += 15

	// Domain blocklist active (+10)
	score += 10

	// SSRF protection active (+10)
	score += 10

	// Entropy analysis active (+10)
	score += 10

	// Rate limiting active (+5)
	score += 5

	// Git protection (+5)
	if cfg.GitEnabled {
		score += 5
	}

	// MCP servers wrapped (+10)
	// Only full credit if suggestion includes MCP guidance
	if cfg.Preset == AgentClaudeCode || cfg.Preset == AgentCursor {
		score += 10
	}

	return score
}

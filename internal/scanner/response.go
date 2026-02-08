package scanner

import "fmt"

// ResponseScanResult describes the outcome of scanning response content.
type ResponseScanResult struct {
	Clean              bool
	Matches            []ResponseMatch
	TransformedContent string // only set for strip action
}

// ResponseMatch describes a single pattern match in response content.
type ResponseMatch struct {
	PatternName string
	MatchText   string // truncated to 100 chars
	Position    int
}

// ScanResponse checks fetched content for prompt injection patterns.
// If scanning is disabled, returns Clean=true immediately.
// For "strip" action, replaces matches with [REDACTED: PatternName].
func (s *Scanner) ScanResponse(content string) ResponseScanResult {
	if !s.responseEnabled {
		return ResponseScanResult{Clean: true}
	}

	var matches []ResponseMatch
	for _, p := range s.responsePatterns {
		locs := p.re.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matchText := content[loc[0]:loc[1]]
			if len(matchText) > 100 {
				matchText = matchText[:100]
			}
			matches = append(matches, ResponseMatch{
				PatternName: p.name,
				MatchText:   matchText,
				Position:    loc[0],
			})
		}
	}

	if len(matches) == 0 {
		return ResponseScanResult{Clean: true}
	}

	result := ResponseScanResult{
		Clean:   false,
		Matches: matches,
	}

	if s.responseAction == "strip" { //nolint:goconst // action string used as-is from config
		transformed := content
		for _, p := range s.responsePatterns {
			replacement := fmt.Sprintf("[REDACTED: %s]", p.name)
			transformed = p.re.ReplaceAllString(transformed, replacement)
		}
		result.TransformedContent = transformed
	}

	return result
}

// ResponseScanningEnabled returns whether response scanning is active.
func (s *Scanner) ResponseScanningEnabled() bool {
	return s.responseEnabled
}

// ResponseAction returns the configured response scanning action (strip, warn, block).
func (s *Scanner) ResponseAction() string {
	return s.responseAction
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func recordBodyRedactionMetrics(m *metrics.Metrics, transport, agent string, report *redact.Report) {
	if m == nil || report == nil || !report.Applied || report.TotalRedactions <= 0 {
		return
	}
	provider := report.Provider
	if provider == "" {
		provider = redact.ProviderGenericJSON
	}
	parser := report.Parser
	if parser == "" {
		parser = redact.ParserJSON
	}
	for class, count := range report.ByClass {
		m.RecordBodyRedactions(transport, agent, provider, parser, string(class), count)
	}
}

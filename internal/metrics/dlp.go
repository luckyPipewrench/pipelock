// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// registerDLPMetrics builds and registers the DLP, address protection, and
// file sentry counter set, attaching the handles to m.
func (m *Metrics) registerDLPMetrics(reg *prometheus.Registry) {
	m.bodyDLPHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "body_dlp_hits_total",
		Help:      "Total request body DLP scan detections by action.",
	}, []string{"action", "agent"})

	m.headerDLPHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "header_dlp_hits_total",
		Help:      "Total request header DLP scan detections by action.",
	}, []string{"action", "agent"})

	m.dlpWarnMatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "dlp_warn_matches_total",
		Help:      "Total warn-mode DLP matches by pattern and transport.",
	}, []string{"pattern", "transport"})

	m.AddressFindings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "address_findings_total",
		Help:      "Address protection findings by chain and verdict.",
	}, []string{"chain", "verdict"})

	m.FileSentryFindings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "file_sentry_findings_total",
		Help:      "Secrets detected in agent-written files by pattern and severity.",
	}, []string{"pattern", "severity", "agent"})

	reg.MustRegister(
		m.bodyDLPHits, m.headerDLPHits, m.dlpWarnMatches,
		m.AddressFindings, m.FileSentryFindings,
	)
}

// RecordBodyDLP increments the request body DLP scan counter by action.
func (m *Metrics) RecordBodyDLP(action, agent string) {
	m.bodyDLPHits.WithLabelValues(action, agent).Inc()
}

// RecordHeaderDLP increments the request header DLP scan counter by action.
func (m *Metrics) RecordHeaderDLP(action, agent string) {
	m.headerDLPHits.WithLabelValues(action, agent).Inc()
}

// RecordDLPWarnMatch increments the warn-mode DLP counter.
func (m *Metrics) RecordDLPWarnMatch(pattern, transport string) {
	if m == nil {
		return
	}
	m.dlpWarnMatches.WithLabelValues(pattern, transport).Inc()
}

// RecordAddressFinding increments the address findings counter.
func (m *Metrics) RecordAddressFinding(chain, verdict string) {
	m.AddressFindings.WithLabelValues(chain, verdict).Inc()
}

// RecordFileSentryFinding increments the file sentry findings counter.
// The agent label is "true" if the write was attributed to the agent process tree.
func (m *Metrics) RecordFileSentryFinding(pattern, severity string, isAgent bool) {
	if m == nil {
		return
	}
	agent := "false"
	if isAgent {
		agent = "true"
	}
	m.FileSentryFindings.WithLabelValues(pattern, severity, agent).Inc()
}

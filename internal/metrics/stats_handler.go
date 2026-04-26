// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxTopEntries = 100

// PrometheusHandler returns an HTTP handler that serves /metrics in Prometheus text format.
func (m *Metrics) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// StatsHandler returns an HTTP handler that serves a JSON stats summary.
func (m *Metrics) StatsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		total := m.allowedCount + m.blockedCount
		stats := statsResponse{
			UptimeSeconds: time.Since(m.startTime).Seconds(),
			Requests: requestStats{
				Total:   total,
				Allowed: m.allowedCount,
				Blocked: m.blockedCount,
			},
			Tunnels:           m.tunnelCount,
			WebSockets:        m.wsConnectionCount,
			TopBlockedDomains: topN(m.topBlockedDomains),
			TopScanners:       topN(m.topScannerHits),
			Sessions: sessionStats{
				Active:       m.sessionActiveCount,
				Anomalies:    m.sessionAnomalyCount,
				Escalations:  m.sessionEscalationCount,
				TopAnomalies: topN(m.topAnomalyTypes),
			},
		}
		ceeFunc := m.CEEStatsFunc
		if total > 0 {
			stats.Requests.BlockRate = float64(m.blockedCount) / float64(total)
		}
		if len(m.agentStats) > 0 {
			stats.Agents = make(map[string]agentStatsOut, len(m.agentStats))
			for name, ac := range m.agentStats {
				stats.Agents[name] = agentStatsOut{
					Allowed: ac.Allowed,
					Blocked: ac.Blocked,
					Tunnels: ac.Tunnels,
				}
			}
		}
		m.mu.Unlock()

		// Call CEE stats func outside the lock (it accesses proxy atomic pointers).
		if ceeFunc != nil {
			stats.CEE = ceeFunc()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	}
}

type statsResponse struct {
	UptimeSeconds     float64                  `json:"uptime_seconds"`
	Requests          requestStats             `json:"requests"`
	Tunnels           int64                    `json:"tunnels"`
	WebSockets        int64                    `json:"websockets"`
	TopBlockedDomains []rankedEntry            `json:"top_blocked_domains"`
	TopScanners       []rankedEntry            `json:"top_scanners"`
	Sessions          sessionStats             `json:"sessions"`
	CEE               CEEStats                 `json:"cross_request_detection"`
	Agents            map[string]agentStatsOut `json:"agents,omitempty"`
}

type agentStatsOut struct {
	Allowed int64 `json:"allowed"`
	Blocked int64 `json:"blocked"`
	Tunnels int64 `json:"tunnels"`
}

type sessionStats struct {
	Active       int64         `json:"active"`
	Anomalies    int64         `json:"anomalies"`
	Escalations  int64         `json:"escalations"`
	TopAnomalies []rankedEntry `json:"top_anomalies"`
}

type requestStats struct {
	Total     int64   `json:"total"`
	Allowed   int64   `json:"allowed"`
	Blocked   int64   `json:"blocked"`
	BlockRate float64 `json:"block_rate"`
}

type rankedEntry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func topN(m map[string]int64) []rankedEntry {
	entries := make([]rankedEntry, 0, len(m))
	for name, count := range m {
		entries = append(entries, rankedEntry{Name: name, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	return entries
}
